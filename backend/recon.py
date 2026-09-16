"""Security reconnaissance: sensitive paths, security headers, TLS certificates.

All checks are passive/baseline information gathering — no exploitation.
"""

import asyncio
import re
import ssl
import datetime

import httpx

from . import config

CONCURRENCY = 100
PROBE_TIMEOUT = 8.0

# Common sensitive/exposed paths — existence check only (status code), no content dumping
SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.bak",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/admin/",
    "/administrator/",
    "/server-status",
    "/actuator",              # Spring Boot
    "/actuator/env",          # Spring Boot env exposure
    "/swagger.json",
    "/api-docs",
    "/graphql",
    "/debug/vars",            # Go pprof/expvar
    "/.aws/credentials",
    "/web.config",
    "/crossdomain.xml",
]

# Security response headers worth having (baseline)
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


async def check_sensitive_paths(sem, client, base_url):
    """Return list of {path, status} for paths that responded (not 404/timeout)."""
    found = []
    for path in SENSITIVE_PATHS:
        async with sem:
            try:
                resp = await client.get(base_url + path, follow_redirects=False)
                # 404/405 = not exposed; anything else is worth flagging
                if resp.status_code not in (404, 405, 410):
                    found.append({"path": path, "status": resp.status_code})
            except Exception:
                pass
    return found


def check_headers(resp: httpx.Response) -> dict:
    """Return {missing: [...], present: {...}} for security headers."""
    lower = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in SECURITY_HEADERS if h not in lower]
    present = {h: lower[h] for h in SECURITY_HEADERS if h in lower}
    return {"missing": missing, "present": present}


async def check_tls(host: str) -> dict | None:
    """Fetch certificate info: issuer, expiry, SANs, days remaining."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want the cert regardless of validity
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx), timeout=PROBE_TIMEOUT
        )
        der = writer.get_extra_info("ssl_object").getpeercert(True)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        import subprocess, json, os, tempfile
        # Use Python's ssl to parse via _ssl-level DER -> use openssl if available;
        # fallback: minimal parse of notAfter via ssl module is not available for DER,
        # so convert with ssl.DER_cert_to_PEM_cert and parse with a lightweight regex.
        pem = ssl.DER_cert_to_PEM_cert(der)
        # Parse SANs and validity from PEM via openssl CLI if present; else regex fallback
        san, issuer, not_after = [], "", None
        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "x509", "-noout", "-issuer", "-dates", "-ext", "subjectAltName",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate(pem.encode(), timeout=10)
            text = out.decode(errors="replace")
            m = re.search(r"issuer=?(.+)", text)
            if m: issuer = m.group(1).strip()
            m = re.search(r"notAfter=(.+)", text)
            if m:
                not_after_str = m.group(1).strip()
                for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                    try:
                        not_after = datetime.datetime.strptime(not_after_str, fmt)
                        break
                    except ValueError:
                        continue
            sans = re.findall(r"DNS:([^,\s]+)", text)
            san = sans
        except (FileNotFoundError, asyncio.TimeoutError):
            pass
        days_left = (not_after - datetime.datetime.utcnow()).days if not_after else None
        return {
            "issuer": issuer,
            "not_after": not_after.isoformat() if not_after else None,
            "days_left": days_left,
            "expiring_soon": days_left is not None and days_left < 30,
            "sans": san,
        }
    except Exception:
        return None


async def recon(http_results: dict[str, dict]) -> dict:
    """Run all baseline checks against hosts that answered HTTP.

    http_results: {sub: {url, status, title}} from http_probe.
    """
    sem = asyncio.Semaphore(CONCURRENCY)
    headers = {"User-Agent": config.USER_AGENT}

    async with httpx.AsyncClient(
        headers=headers, timeout=PROBE_TIMEOUT, verify=False, follow_redirects=True
    ) as client:
        async def full_check(sub, info):
            base = info["url"].rstrip("/")
            paths_task = check_sensitive_paths(sem, client, base)
            try:
                resp = await client.get(base)
                headers_info = check_headers(resp)
            except Exception:
                headers_info = None
            tls_task = check_tls(sub)
            paths, tls = await asyncio.gather(paths_task, tls_task)
            return sub, {"paths": paths, "headers": headers_info, "tls": tls}

        pairs = await asyncio.gather(
            *(full_check(sub, info) for sub, info in http_results.items() if info)
        )

    results = dict(pairs)
    flagged = {
        s: r for s, r in results.items()
        if r["paths"] or (r["tls"] and r["tls"]["expiring_soon"])
    }
    return {
        "results": results,
        "flagged_count": len(flagged),
        "checked": len(results),
    }
