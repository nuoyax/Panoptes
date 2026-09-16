"""crt.sh JSON interface — https://crt.sh/?q=%25.<apex>&output=json"""

import json

from .. import config
from .base import CTSource


class CrtShSource(CTSource):
    name = "crt.sh"

    async def query(self, client, apex: str) -> list[str]:
        url = "https://crt.sh/"
        params = {"q": f"%.{apex}", "output": "json"}
        if config.CRTSH_EXCLUDE_EXPIRED:
            params["exclude"] = "expired"
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        data = json.loads(resp.text)
        names: list[str] = []
        for row in data:
            for field in ("name_value", "common_name"):
                raw = row.get(field) or ""
                names.extend(n.strip().lstrip("*.").lower() for n in raw.split("\n") if n.strip())
        return names
