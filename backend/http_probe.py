"""HTTP probing: fetch status code and <title> for live subdomains."""

import asyncio
import re

import httpx

from . import config

CONCURRENCY = 100
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def _probe_one(sem: asyncio.Semaphore, client: httpx.AsyncClient, subdomain: str):
    """Return (subdomain, {status, title, url} | None)."""
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                resp = await client.get(url, follow_redirects=True)
                m = TITLE_RE.search(resp.text)
                title = m.group(1).strip()[:120] if m else ""
                return subdomain, {
                    "url": str(resp.url),
                    "status": resp.status_code,
                    "title": title,
                }
            except Exception:
                continue
    return subdomain, None


async def probe(
    subdomains: list[str],
    timeout: float = config.HTTP_PROBE_TIMEOUT,
    verify: bool | None = None,
) -> dict[str, dict]:
    """Probe alive subdomains concurrently. Result: {sub: info or None}.

    TLS verification defaults to config.HTTP_VERIFY_TLS: discovered hosts
    frequently serve mismatched or self-signed certs, and we only want the
    status line and title.
    """
    sem = asyncio.Semaphore(CONCURRENCY)
    headers = {"User-Agent": config.USER_AGENT}
    if verify is None:
        verify = config.HTTP_VERIFY_TLS
    async with httpx.AsyncClient(
        headers=headers, timeout=timeout, verify=verify,
        follow_redirects=True,
    ) as client:
        pairs = await asyncio.gather(*(_probe_one(sem, client, s) for s in subdomains))
    return dict(pairs)
