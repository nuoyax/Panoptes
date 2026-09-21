"""Persistent storage for the subdomain inventory, enrichment and scan jobs.

One aiosqlite connection shared by every coroutine, guarded by a lock:
SQLite's busy_timeout only reconciles *different* connections, so two coroutines
interleaving execute/commit on the same one can split a transaction boundary.

Table families are deliberately separate from the `cache` table owned by
backend/cache.py (same database file, different concern): `cache` holds the 24h
subdomain list, `store` holds per-stage enrichment and job records.

Enrichment is keyed by (apex, name, stage). A scan that only asked for DNS
writes only `stage='dns'` rows, so a later scan that adds security writes only
the missing stage and leaves the DNS rows untouched — no read-modify-write
merge and no race between concurrent scans of the same apex.

Staleness is per-row `checked_at` compared against a per-stage TTL at read
time, so retuning a TTL needs no migration.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

import aiosqlite

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS subdomain (
    apex       TEXT NOT NULL,
    name       TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (apex, name)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS enrichment (
    apex       TEXT NOT NULL,
    name       TEXT NOT NULL,
    stage      TEXT NOT NULL,
    status     TEXT NOT NULL,
    data       TEXT,
    checked_at INTEGER NOT NULL,
    elapsed_ms INTEGER,
    PRIMARY KEY (apex, name, stage)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_enrichment_apex_stage ON enrichment(apex, stage);

CREATE TABLE IF NOT EXISTS job (
    id          TEXT PRIMARY KEY,
    apex        TEXT NOT NULL,
    stages      TEXT NOT NULL,
    state       TEXT NOT NULL,
    progress    TEXT NOT NULL,
    error       TEXT,
    result      TEXT,
    created_at  INTEGER NOT NULL,
    finished_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_job_apex ON job(apex);
CREATE INDEX IF NOT EXISTS idx_job_created ON job(created_at);
"""

TERMINAL_STATES = ("done", "error", "cancelled", "timeout")
_CHUNK = 500  # names per SELECT ... IN (...)


# --------------------------------------------------------------------------- #
# stage <-> stored-row conversion
# --------------------------------------------------------------------------- #
def status_of(stage: str, value: dict | None) -> str:
    """Short machine-readable status for one stored row."""
    if value is None:
        return {  # a negative result is still a cached answer
            "dns": "dead",
            "http": "none",
            "ports": "none",
            "security": "none",
        }.get(stage, "none")
    if stage == "dns":
        return "alive" if value.get("ips") else "dead"
    if stage == "http":
        return "ok"
    if stage == "ports":
        return "open"
    return "flagged"


def flatten(stage: str, payload: dict[str, Any]) -> dict[str, dict | None]:
    """Convert a stage's raw result into {name: data | None} rows.

    `dns` takes the {host: [ips] | None} map from dns_verify.verify — polarity is
    preserved so a host that does not resolve is stored as a cached negative
    instead of being re-resolved on every scan.
    """
    if stage == "dns":
        return {name: ({"ips": ips} if ips else None) for name, ips in payload.items()}
    return dict(payload or {})


def unflatten(stage: str, rows: dict[str, dict | None]) -> dict[str, Any]:
    """Convert stored rows back into a stage's raw result shape."""
    if stage == "dns":
        return {name: ((value or {}).get("ips") or None) for name, value in rows.items()}
    if stage != "ports":
        return dict(rows)
    # A port payload is keyed by port number inside each host entry; JSON
    # stringifies those keys, so they are cast back to int for in-process parity
    # with a live scan (the wire format stringifies them again either way).
    out: dict[str, dict | None] = {}
    for name, ports in rows.items():
        if ports is None:
            out[name] = None
            continue
        restored: dict[int | str, dict | None] = {}
        for port, value in ports.items():
            try:
                restored[int(port)] = value
            except (TypeError, ValueError):
                restored[port] = value
        out[name] = restored
    return out


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, db_path: Path | str = config.DB_PATH):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def init(self):
        async with self._lock:
            if self._db is not None:
                return
            db = await aiosqlite.connect(self.db_path)
            try:
                await db.execute("PRAGMA journal_mode=WAL")
                await db.execute("PRAGMA busy_timeout=5000")
                await db.executescript(_SCHEMA)
                await db.commit()
            except Exception:
                await db.close()
                raise
            self._db = db

    async def close(self):
        async with self._lock:
            if self._db is None:
                return
            db, self._db = self._db, None
        await db.close()

    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Store.init() has not been awaited")
        return self._db

    # --- subdomain inventory -------------------------------------------------
    async def get_subdomains(
        self, apex: str, ttl: int = config.TTL_SUBDOMAIN
    ) -> list[str] | None:
        """Return the known names for `apex` if the inventory is still fresh."""
        cutoff = int(time.time()) - ttl
        async with self._lock:
            async with self._conn().execute(
                "SELECT MAX(last_seen) FROM subdomain WHERE apex = ?", (apex,)
            ) as cur:
                row = await cur.fetchone()
            if not row or row[0] is None or row[0] < cutoff:
                return None
            async with self._conn().execute(
                "SELECT name FROM subdomain WHERE apex = ? ORDER BY name", (apex,)
            ) as cur:
                rows = await cur.fetchall()
        return [r[0] for r in rows]

    async def replace_subdomains(self, apex: str, names: Iterable[str]):
        """UPSERT names, preserving first_seen for names already known."""
        now = int(time.time())
        rows = [(apex, name, now, now) for name in names]
        if not rows:
            return
        async with self._lock:
            await self._conn().executemany(
                "INSERT INTO subdomain (apex, name, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(apex, name) DO UPDATE SET last_seen = excluded.last_seen",
                rows,
            )
            await self._conn().commit()

    # --- enrichment ----------------------------------------------------------
    async def get_stage(
        self,
        apex: str,
        stage: str,
        names: Sequence[str] | None = None,
        ttl: int | None = None,
    ) -> dict[str, dict | None]:
        """Return fresh stored rows for a stage, chunked to respect SQLite limits.

        Neither a name nor a payload is included unless the row is newer than
        `ttl`, so callers derive "still needs probing" as names minus keys.
        """
        cutoff = int(time.time()) - (ttl if ttl is not None else 0)
        out: dict[str, dict | None] = {}
        async with self._lock:
            if names is None:
                async with self._conn().execute(
                    "SELECT name, data FROM enrichment "
                    "WHERE apex = ? AND stage = ? AND checked_at >= ?",
                    (apex, stage, cutoff),
                ) as cur:
                    for name, data in await cur.fetchall():
                        out[name] = json.loads(data) if data else None
                return out
            for chunk in _chunks(list(names), _CHUNK):
                placeholders = ",".join("?" * len(chunk))
                async with self._conn().execute(
                    "SELECT name, data FROM enrichment "
                    f"WHERE apex = ? AND stage = ? AND checked_at >= ? "
                    f"AND name IN ({placeholders})",
                    (apex, stage, cutoff, *chunk),
                ) as cur:
                    for name, data in await cur.fetchall():
                        out[name] = json.loads(data) if data else None
        return out

    async def put_stage(
        self,
        apex: str,
        stage: str,
        items: dict[str, dict | None],
        elapsed_ms: int | None = None,
    ):
        """UPSERT a whole stage's results in one transaction."""
        if not items:
            return
        now = int(time.time())
        rows = [
            (
                apex,
                name,
                stage,
                status_of(stage, value),
                json.dumps(value) if value is not None else None,
                now,
                elapsed_ms,
            )
            for name, value in items.items()
        ]
        async with self._lock:
            await self._conn().executemany(
                "INSERT INTO enrichment "
                "(apex, name, stage, status, data, checked_at, elapsed_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(apex, name, stage) DO UPDATE SET "
                "status = excluded.status, data = excluded.data, "
                "checked_at = excluded.checked_at, elapsed_ms = excluded.elapsed_ms",
                rows,
            )
            await self._conn().commit()

    # --- jobs ---------------------------------------------------------------
    async def job_insert(
        self, job_id: str, apex: str, stages: list[str], progress: dict, now: int
    ):
        async with self._lock:
            await self._conn().execute(
                "INSERT OR REPLACE INTO job "
                "(id, apex, stages, state, progress, error, result, created_at, finished_at) "
                "VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, NULL)",
                (job_id, apex, json.dumps(stages), "queued", json.dumps(progress), now),
            )
            await self._conn().commit()

    async def job_update(
        self,
        job_id: str,
        state: str,
        progress: dict,
        result: dict | None,
        error: str | None,
        finished_at: int | None = None,
    ):
        async with self._lock:
            await self._conn().execute(
                "UPDATE job SET state = ?, progress = ?, result = ?, error = ?, "
                "finished_at = COALESCE(?, finished_at) WHERE id = ?",
                (
                    state,
                    json.dumps(progress),
                    json.dumps(result) if result is not None else None,
                    error,
                    finished_at,
                    job_id,
                ),
            )
            await self._conn().commit()

    async def job_get(self, job_id: str) -> dict | None:
        async with self._lock:
            async with self._conn().execute(
                "SELECT id, apex, stages, state, progress, error, result, "
                "created_at, finished_at FROM job WHERE id = ?",
                (job_id,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        return _job_row(row)

    async def job_list(self, apex: str | None = None, limit: int = 20) -> list[dict]:
        cols = (
            "id, apex, stages, state, progress, error, result, created_at, finished_at"
        )
        async with self._lock:
            if apex:
                sql = f"SELECT {cols} FROM job WHERE apex = ? ORDER BY created_at DESC LIMIT ?"
                params: tuple = (apex, limit)
            else:
                sql = f"SELECT {cols} FROM job ORDER BY created_at DESC LIMIT ?"
                params = (limit,)
            async with self._conn().execute(sql, params) as cur:
                rows = await cur.fetchall()
        out = []
        for row in rows:
            job = _job_row(row)
            out.append(
                {
                    "job_id": job["id"],
                    "apex": job["apex"],
                    "stages": job["stages"],
                    "state": job["state"],
                    "created_at": job["created_at"],
                    "finished_at": job["finished_at"],
                    "error": job["error"],
                }
            )
        return out

    async def job_mark_orphans(self) -> int:
        """Fail jobs left non-terminal by a previous process.

        Running jobs are not resumed: the subdomain cache and every enrichment
        row survive, so re-running the scan only pays for the missing stages.
        """
        placeholders = ",".join("?" * len(TERMINAL_STATES))
        async with self._lock:
            cur = await self._conn().execute(
                f"UPDATE job SET state = 'error', error = ?, finished_at = ? "
                f"WHERE state NOT IN ({placeholders})",
                ("server restarted", int(time.time()), *TERMINAL_STATES),
            )
            await self._conn().commit()
            return cur.rowcount or 0

    async def job_delete(self, job_id: str) -> bool:
        async with self._lock:
            cur = await self._conn().execute("DELETE FROM job WHERE id = ?", (job_id,))
            await self._conn().commit()
            return (cur.rowcount or 0) > 0

    # --- maintenance --------------------------------------------------------
    async def prune(
        self,
        job_ttl: int = config.JOB_TTL_SECONDS,
        enrichment_days: int = config.ENRICHMENT_RETENTION_DAYS,
    ) -> int:
        """Drop finished jobs past their TTL and long-dead enrichment rows."""
        now = int(time.time())
        placeholders = ",".join("?" * len(TERMINAL_STATES))
        removed = 0
        async with self._lock:
            cur = await self._conn().execute(
                f"DELETE FROM job WHERE state IN ({placeholders}) AND created_at < ?",
                (*TERMINAL_STATES, now - job_ttl),
            )
            removed += cur.rowcount or 0
            cur = await self._conn().execute(
                "DELETE FROM enrichment WHERE checked_at < ?",
                (now - enrichment_days * 86400,),
            )
            removed += cur.rowcount or 0
            await self._conn().commit()
        return removed


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _job_row(row) -> dict:
    """Column order is fixed in every SELECT: see job_get/job_list."""
    (jid, apex, stages, state, progress, error, result, created_at, finished_at) = row
    return {
        "id": jid,
        "apex": apex,
        "stages": json.loads(stages),
        "state": state,
        "progress": json.loads(progress),
        "error": error,
        "result": json.loads(result) if result else None,
        "created_at": created_at,
        "finished_at": finished_at,
    }
