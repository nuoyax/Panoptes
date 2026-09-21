"""HackerTarget host search — free, no API key required.

GET https://api.hackertarget.com/hostsearch/?q=<apex>
Returns CSV lines of "hostname,ip".

Quirk: when the free daily quota is exhausted the API answers HTTP 200 with a
plain-text sentence ("API count exceeded...") instead of an error status, so the
body must be inspected or the source silently contributes zero records.
"""

from .. import config
from .base import CTSource

ERROR_PREFIXES = ("error", "api count exceeded", "quota", "no records found")


class HackerTargetSource(CTSource):
    name = "hackertarget"
    URL = "https://api.hackertarget.com/hostsearch/"

    async def query(self, client, apex: str) -> list[str]:
        resp = await client.get(self.URL, params={"q": apex})
        resp.raise_for_status()
        if len(resp.content) > config.SOURCE_HTTP_MAX_BYTES:
            raise RuntimeError("response body too large")
        text = resp.text
        lowered = text.lstrip().lower()
        if lowered.startswith(ERROR_PREFIXES):
            raise RuntimeError(text.strip().splitlines()[0][:200])
        names: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            host = line.split(",", 1)[0].strip().lower().lstrip("*.")
            if host:
                names.append(host)
        return names
