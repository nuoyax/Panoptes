"""AlienVault OTX passive DNS — public, no key required.

https://otx.alienvault.com/api/v1/indicators/domain/<apex>/passive_dns
"""

import json

from .base import CTSource


class OtxSource(CTSource):
    name = "otx"

    async def query(self, client, apex: str) -> list[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns"
        resp = await client.get(url)
        resp.raise_for_status()
        data = json.loads(resp.text)
        records = (data.get("passive_dns") or [])
        return [
            (r.get("hostname") or "").strip().lower()
            for r in records
            if r.get("hostname")
        ]
