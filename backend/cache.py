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

    async def get(self, apex: str) -> tuple[list[str], float] | None:
        """Return (subdomains, fetched_at) if a fresh entry exists."""
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
        return data, fetched_at

    async def put(self, apex: str, subdomains: list[str]):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO cache (apex, data, fetched_at) VALUES (?, ?, ?)",
                (apex, json.dumps(subdomains), int(time.time())),
            )
            await db.commit()
