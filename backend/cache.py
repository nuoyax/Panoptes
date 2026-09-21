"""SQLite cache for aggregated subdomain results."""

import json
import time

import aiosqlite

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    apex       TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);
"""


class Cache:
    def __init__(self, db_path=config.DB_PATH):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(_SCHEMA)
            await db.commit()

    async def get(self, apex: str) -> tuple[list[str], float, dict] | None:
        """Return (subdomains, fetched_at, meta) if a fresh entry exists.

        Legacy rows written before meta was stored hold a bare list of names;
        they are read back with empty meta rather than discarded.
        """
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT data, fetched_at FROM cache WHERE apex = ?", (apex,)
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        data, fetched_at = json.loads(row[0]), row[1]
        if time.time() - fetched_at > config.CACHE_TTL_SECONDS:
            return None
        if isinstance(data, dict):
            return data.get("subdomains") or [], data.get("meta") or {}, fetched_at
        return data, {}, fetched_at

    async def put(self, apex: str, subdomains: list[str], meta: dict | None = None):
        """Store the subdomain list together with its aggregation meta."""
        payload = json.dumps({"subdomains": subdomains, "meta": meta or {}})
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO cache (apex, data, fetched_at) VALUES (?, ?, ?)",
                (apex, payload, int(time.time())),
            )
            await db.commit()
