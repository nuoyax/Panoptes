"""Wayback Machine CDX index — free, no API key required.

GET https://web.archive.org/cdx/search/cdx?url=*.<apex>&fl=original&output=text
Returns one crawled URL per line. Historial URLs surface subdomains that have
since gone offline, which pure CT-log sources miss.

This is the slowest upstream of the set (30-60s for a large apex), which is
tolerable now that scans run as background jobs.
"""

from urllib.parse import urlsplit

from .. import config
from .base import CTSource


class WaybackSource(CTSource):
    name = "wayback"
    URL = "https://web.archive.org/cdx/search/cdx"

    async def query(self, client, apex: str) -> list[str]:
        params = {
            "url": f"*.{apex}",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": str(config.MAX_RESULTS),
        }
        resp = await client.get(self.URL, params=params, timeout=config.WAYBACK_TIMEOUT)
        resp.raise_for_status()
        if len(resp.content) > config.SOURCE_HTTP_MAX_BYTES:
            raise RuntimeError("response body too large")
        names: list[str] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Lines are URLs (no scheme in some CDX modes) — keep only the hostname
            target = line if "//" in line else "//" + line
            host = urlsplit(target).hostname
            if host:
                names.append(host.lower())
        return names
