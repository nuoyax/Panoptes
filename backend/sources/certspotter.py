"""Cert Spotter v1 API (free, no key required for small queries).

https://www.certspotter.com/api/v0/certs?domain=<apex>
Returns certificate objects; we collect DNS names from each.
"""

import json

from .base import CTSource


class CertSpotterSource(CTSource):
    name = "certspotter"

    async def query(self, client, apex: str) -> list[str]:
        url = f"https://www.certspotter.com/api/v0/certs"
        params = {"domain": apex, "include_subdomains": "true", "expand": "dns_names"}
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        data = json.loads(resp.text)
        if not isinstance(data, list):
            return []
        names: list[str] = []
        for cert in data:
            for n in cert.get("dns_names") or []:
                names.append(n.lstrip("*.").lower())
        return names
