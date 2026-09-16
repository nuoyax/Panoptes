"""DNS liveness verification for discovered subdomains."""

import asyncio
from collections import defaultdict

import dns.asyncresolver

CONCURRENCY = 200  # parallel DNS lookups


async def _resolve_one(sem: asyncio.Semaphore, subdomain: str) -> tuple[str, list[str] | None]:
    """Return (subdomain, ips) — ips is None when resolution failed."""
    async with sem:
        try:
            answers = await dns.asyncresolver.resolve(subdomain, "A")
            return subdomain, sorted(r.address for r in answers)
        except Exception:
            return subdomain, None


async def verify(subdomains: list[str]) -> dict[str, list[str] | None]:
    """Resolve A records concurrently. Result: {sub: ips or None}."""
    sem = asyncio.Semaphore(CONCURRENCY)
    pairs = await asyncio.gather(*(_resolve_one(sem, s) for s in subdomains))
    return dict(pairs)


def summarize(results: dict[str, list[str] | None]) -> dict:
    alive = {s: ips for s, ips in results.items() if ips}
    ip_groups: dict[str, list[str]] = defaultdict(list)
    for sub, ips in alive.items():
        for ip in ips:
            ip_groups[ip].append(sub)
    return {
        "alive": alive,
        "alive_count": len(alive),
        "shared_ips": {ip: subs for ip, subs in sorted(ip_groups.items(), key=lambda kv: -len(kv[1])) if len(subs) > 1},
    }
