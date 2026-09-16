"""Concurrent multi-source aggregation with dedup and apex filtering."""

import asyncio
import re

import httpx

from . import config
from .sources.base import CTSource
from .sources.certspotter import CertSpotterSource
from .sources.crtsh import CrtShSource

SOURCES: list[CTSource] = [CrtShSource(), CertSpotterSource()]

_NAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


async def _fetch_one(source: CTSource, client: httpx.AsyncClient, apex: str):
    try:
        return source.name, await source.query(client, apex), None
    except Exception as exc:  # single source failure must not break the rest
        return source.name, [], f"{type(exc).__name__}: {exc}"


def _normalize(raw_names: list[str], apex: str) -> set[str]:
    """Lowercase, strip wildcard prefix, keep only entries under apex."""
    suffix = "." + apex
    out: set[str] = set()
    for name in raw_names:
        name = name.strip().lower().lstrip("*.").rstrip(".")
        if not name or not name.endswith(suffix) or name == apex:
            continue
        if not _NAME_RE.match(name):
            continue
        out.add(name)
    return out


async def aggregate(apex: str) -> tuple[list[str], dict]:
    """Query all sources concurrently; return (sorted subdomains, meta)."""
    headers = {"User-Agent": config.USER_AGENT}
    async with httpx.AsyncClient(
        headers=headers, timeout=config.UPSTREAM_TIMEOUT, follow_redirects=True
    ) as client:
        results = await asyncio.gather(
            *(_fetch_one(s, client, apex) for s in SOURCES)
        )

    merged: set[str] = set()
    errors: dict[str, str] = {}
    counts: dict[str, int] = {}
    for name, names, err in results:
        counts[name] = len(names)
        if err:
            errors[name] = err
        merged |= _normalize(names, apex)

    subdomains = sorted(merged)[: config.MAX_RESULTS]
    meta = {
        "sources": counts,
        "errors": errors,
    }
    return subdomains, meta
