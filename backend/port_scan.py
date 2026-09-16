"""TCP port scanning for live subdomains (common ports, high concurrency)."""

import asyncio

# Common web/service ports probed by default
DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 3000, 22, 21, 3306, 6379, 5432, 27017, 9200, 3389]

CONCURRENCY = 500   # parallel connection attempts
TIMEOUT = 1.5       # seconds per connect


async def _check_port(ip: str, port: int, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None


async def _scan_host(sem: asyncio.Semaphore, ports: list[int], host: str, ips: list[str]):
    """Scan a host on all its resolved IPs; return (host, open_ports)."""
    tasks = [_check_port(ip, p, sem) for ip in ips for p in ports]
    results = await asyncio.gather(*tasks)
    # Map port -> which IP answered
    open_ports: dict[int, str] = {}
    idx = 0
    for ip in ips:
        for p in ports:
            if results[idx] is not None and p not in open_ports:
                open_ports[p] = ip
            idx += 1
    return host, dict(sorted(open_ports.items()))


async def scan(alive: dict[str, list[str]], ports: list[int] | None = None) -> dict:
    """Scan TCP ports of alive hosts.

    alive: {subdomain: [ips]} from dns_verify.
    Returns {summary, results: {sub: {port: ip}}}.
    """
    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(CONCURRENCY)
    pairs = await asyncio.gather(
        *(_scan_host(sem, ports, host, ips) for host, ips in alive.items())
    )
    results = {h: p for h, p in pairs if p}
    return {
        "ports": ports,
        "results": results,
        "hosts_with_open": len(results),
        "total_open": sum(len(p) for p in results.values()),
    }
