"""TCP port scanning for live subdomains (common ports, high concurrency).

Port list is grouped by service; several entries map to well-known
CVE-associated services useful for attack-surface awareness.
"""

import asyncio

# Grouped common ports; entries: (port, service label)
# * = services with a history of notable CVEs / frequent exposure findings
DEFAULT_PORTS: list[tuple[int, str]] = [
    # --- Web & proxies ---
    (80, "HTTP"),
    (443, "HTTPS"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (8000, "HTTP-Dev"),        # Django/uvicorn/http.server
    (3000, "Node/Dev"),        # Express/React dev
    (5000, "Flask"),
    (7001, "WebLogic"),        # * CVE-2017-10271, LogShell-adjacent deserial
    (8009, "AJP"),             # * CVE-2020-1938 Ghostcat (Tomcat)
    (9090, "Admin-UI"),
    # --- Remote access ---
    (22, "SSH"),
    (3389, "RDP"),             # * BlueKeep CVE-2019-0708
    (5900, "VNC"),             # * unauth access, CVE-2006-2369 era issues
    (23, "Telnet"),            # * plaintext, legacy
    # --- Databases & caches ---
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (6379, "Redis"),           # * unauth RCE (CVE-2022-0543 Lua sandbox escape)
    (27017, "MongoDB"),        # * classic no-auth exposure (CVE-2018-1000006)
    (9200, "Elasticsearch"),   # * CVE-2014-3120 / CVE-2015-1427 scripting RCE
    (11211, "Memcached"),      # * UDP amplification DDoS, unauth
    # --- File & message ---
    (21, "FTP"),               # * plaintext, anonymous logins
    (445, "SMB"),              # * EternalBlue CVE-2017-0144
    (139, "NetBIOS"),
    (2049, "NFS"),
    (873, "rsync"),
    (161, "SNMP"),             # * default community strings
    (5672, "AMQP/RabbitMQ"),
    (2181, "ZooKeeper"),       # * unauth 4-letter-word abuse
    # --- Other exposed services ---
    (2375, "Docker API"),      # * unauth Docker daemon = root RCE
    (2377, "Docker Swarm"),
    (10250, "kubelet"),        # * unauth kubelet API (CVE-2018-1002105)
    (6443, "K8s API"),
    (8500, "Consul"),          # * CVE-2019-14809 related exposures
    (9200 + 1, "Elastic-Transport"),
    (1900, "SSDP/UPnP"),
    (11214, "Memcached-Inc"),
]

CONCURRENCY = 500   # parallel connection attempts
TIMEOUT = 1.5       # seconds per connect


async def _check_port(
    ip: str, port: int, sem: asyncio.Semaphore, timeout: float
) -> int | None:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None


async def _scan_host(
    sem: asyncio.Semaphore,
    ports: list[tuple[int, str]],
    host: str,
    ips: list[str],
    timeout: float,
):
    """Scan a host on all its resolved IPs; return (host, {port: {ip, service}})."""
    port_nums = [p for p, _ in ports]
    service_of = dict(ports)
    tasks = [_check_port(ip, p, sem, timeout) for ip in ips for p in port_nums]
    results = await asyncio.gather(*tasks)
    open_ports: dict[int, dict] = {}
    idx = 0
    for ip in ips:
        for p in port_nums:
            if results[idx] is not None and p not in open_ports:
                open_ports[p] = {"ip": ip, "service": service_of.get(p, "")}
            idx += 1
    return host, dict(sorted(open_ports.items()))


async def scan(
    alive: dict[str, list[str]],
    ports=None,
    concurrency: int = CONCURRENCY,
    timeout: float = TIMEOUT,
) -> dict:
    """Scan TCP ports of alive hosts.

    alive: {subdomain: [ips]} from dns_verify.
    Returns {ports, results: {sub: {port: {ip, service}}}, ...}.
    """
    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(concurrency)
    pairs = await asyncio.gather(
        *(_scan_host(sem, ports, host, ips, timeout) for host, ips in alive.items())
    )
    results = {h: p for h, p in pairs if p}
    return {
        "ports": [p for p, _ in ports],
        "results": results,
        "hosts_with_open": len(results),
        "total_open": sum(len(p) for p in results.values()),
    }
