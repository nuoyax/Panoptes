"""Cert Spotter — Certificate Transparency log search, free tier without a token.

GET https://api.certspotter.com/v1/issuances?domain=<apex>&include_subdomains=true&expand=dns_names
Returns a JSON array of issuance objects; `dns_names` holds the SANs.

The older /api/v0/certs endpoint has been retired (HTTP 410) — use v1.
The unauthenticated free tier has a low rate limit and answers 429 when spent.
"""

from .base import CTSource


class CertSpotterSource(CTSource):
    name = "certspotter"
    URL = "https://api.certspotter.com/v1/issuances"

    async def query(self, client, apex: str) -> list[str]:
        params = [
            ("domain", apex),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
            ("match_wildcards", "true"),
        ]
        resp = await client.get(self.URL, params=params)
        if resp.status_code == 429:
            raise RuntimeError(
                "rate limited (free tier is low; results will be partial)"
            )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            return []
        names: list[str] = []
        for cert in data:
            for raw in cert.get("dns_names") or []:
                name = raw.strip().lower().lstrip("*.")
                if name:
                    names.append(name)
        return names
