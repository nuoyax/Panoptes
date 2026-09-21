"""Background scan jobs: stage orchestration, progress, cancellation, reaping.

A scan is a long tail of wall-clock work (DNS for thousands of names, then
HTTP, ports and security checks), so it runs as a detached task that the client
polls instead of a request-scoped coroutine. The registry is authoritative in
memory while the process lives and SQLite is the durability layer: POST/scan
returns as soon as the job row exists, and a restart can still serve the final
payload of a job that finished before it.

Stages resume from persisted enrichment unless `force` is set, so a repeat scan
of the same apex reports `skipped`/`from_cache` and costs nothing.
"""

import asyncio
import contextlib
import time
import uuid
from dataclasses import dataclass, field

from . import config, aggregator, dns_verify, http_probe, port_scan, recon
from .store import Store, flatten, status_of, unflatten

STAGES = ("dns", "http", "ports", "security")

# Immutable stage order plus what each stage needs from the previous one. A
# requested stage pulls in its dependencies, which is a behaviour fix: asking
# for sec_check without http_check used to silently return null.
STAGE_DEPS: dict[str, tuple[str, ...]] = {
    "dns": (),
    "http": ("dns",),
    "ports": ("dns",),
    "security": ("http",),
}
PENDING = "pending"
RUNNING = "running"
DONE = "done"
SKIPPED = "skipped"
ERROR = "error"
CANCELLED = "cancelled"
TIMEOUT = "timeout"
TERMINAL_JOB_STATES = (DONE, ERROR, CANCELLED, TIMEOUT)

# Legacy checkbox names accepted by the API
STAGE_ALIASES = {
    "dns": "dns",
    "dns_check": "dns",
    "http": "http",
    "http_check": "http",
    "port": "ports",
    "ports": "ports",
    "port_check": "ports",
    "sec": "security",
    "security": "security",
    "sec_check": "security",
}


class StageNotRequested(ValueError):
    """Raised when an unknown stage name reaches the pipeline."""


def expand_stages(requested) -> list[str]:
    """Resolve aliases, pull in dependencies transitively, return canonical order.

    The closure must be transitive, not one level: `security` needs `http`, and
    `http` in turn needs `dns`, so asking for security alone has to schedule all
    three or the http stage finds nothing to inspect.
    """
    wanted: set[str] = set()
    pending: list[str] = []
    for raw in requested:
        stage = STAGE_ALIASES.get(str(raw).strip().lower())
        if stage is None:
            raise StageNotRequested(raw)
        pending.append(stage)
    while pending:
        stage = pending.pop()
        if stage in wanted:
            continue
        wanted.add(stage)
        pending.extend(STAGE_DEPS[stage])
    return [s for s in STAGES if s in wanted]


def auto_stages(requested) -> list[str]:
    """Dependencies that were added on the caller's behalf."""
    explicit = {STAGE_ALIASES.get(str(r).strip().lower()) for r in requested}
    return [s for s in expand_stages(requested) if s not in explicit]


def _select_hosts(hosts: list[str], limit: int) -> tuple[list[str], int]:
    """Cap a host list, returning (kept, dropped)."""
    if limit and len(hosts) > limit:
        return hosts[:limit], len(hosts) - limit
    return hosts, 0


def _needs_probing(cached: dict, targets: list[str]) -> bool:
    """True when any target lacks a stored row (a stored negative still counts)."""
    return len(targets) - sum(1 for t in targets if t in cached) > 0


@dataclass
class StageProgress:
    state: str = PENDING
    checked: int = 0
    total: int = 0
    elapsed_ms: int | None = None
    summary: dict | None = None
    error: str | None = None
    from_cache: bool = False
    reason: str | None = None

    def as_dict(self) -> dict:
        out = {
            "state": self.state,
            "checked": self.checked,
            "total": self.total,
            "elapsed_ms": self.elapsed_ms,
            "from_cache": self.from_cache,
            "summary": self.summary,
        }
        if self.error:
            out["error"] = self.error
        if self.reason:
            out["reason"] = self.reason
        return out


@dataclass
class Job:
    id: str
    apex: str
    stages: list[str]
    auto: list[str]
    force: bool
    state: str = "queued"
    created_at: int = 0
    started_at: int | None = None
    finished_at: int | None = None
    error: str | None = None
    progress: dict[str, StageProgress] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    aggregate_meta: dict = field(default_factory=dict)
    cached: bool = False
    fetched_at: int | None = None
    truncated: dict[str, int] = field(default_factory=dict)
    results: dict[str, dict] = field(default_factory=dict)
    cancelled: bool = False
    task: asyncio.Task | None = None


class JobRegistry:
    def __init__(
        self,
        store: Store,
        cache,
        max_concurrent: int = config.JOB_MAX_CONCURRENT,
        job_ttl: int = config.JOB_TTL_SECONDS,
    ):
        self._store = store
        self._cache = cache
        self._sem = asyncio.Semaphore(max_concurrent)
        self._jobs: dict[str, Job] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._job_ttl = job_ttl

    # --- public API ---------------------------------------------------------
    async def create(self, apex: str, stages, force: bool = False) -> Job:
        """Register a job and start it. Returns an existing live job if it covers this one.

        The job row is written before the task is spawned, so a GET right after
        POST /scan can never 404 — hence this method is async even though
        starting a task is not.
        """
        resolved = expand_stages(stages)
        existing = self.find_active(apex, resolved)
        if existing is not None:
            return existing
        self._reap()
        job = Job(
            id=uuid.uuid4().hex,
            apex=apex,
            stages=resolved,
            auto=auto_stages(stages),
            force=force,
            created_at=int(time.time()),
            progress={s: StageProgress() for s in resolved},
        )
        self._jobs[job.id] = job
        await self._store.job_insert(
            job.id, apex, resolved, self._progress_dict(job), job.created_at
        )
        task = asyncio.create_task(self._run(job))
        job.task = task
        self._tasks[job.id] = task
        task.add_done_callback(lambda _t, jid=job.id: self._tasks.pop(jid, None))
        return job

    def find_active(self, apex: str, stages) -> Job | None:
        """A live job whose requested stages cover `stages` for the same apex."""
        needed = set(stages)
        for job in self._jobs.values():
            if job.apex != apex or job.state in TERMINAL_JOB_STATES:
                continue
            if needed <= set(job.stages):
                return job
        return None

    def get(self, job_id: str) -> Job | None:
        self._reap()
        return self._jobs.get(job_id)

    def active_count(self) -> int:
        return sum(
            1 for j in self._jobs.values() if j.state not in TERMINAL_JOB_STATES
        )

    async def wait(self, job: Job, timeout: float | None = None) -> Job:
        """Wait for a job to reach a terminal state (or `timeout` seconds).

        The job task is shielded: a timeout means "stop waiting for the
        response", never "cancel the background work". A job whose task has
        already finished (or was never spawned — replayed from the DB) is
        settled directly from its own state.
        """
        task = job.task
        if task is not None and not task.done():
            try:
                if timeout is None:
                    await asyncio.shield(task)
                else:
                    await asyncio.wait_for(asyncio.shield(task), timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
            return job
        deadline = None if timeout is None else time.monotonic() + timeout
        while job.state not in TERMINAL_JOB_STATES:
            if deadline is not None and time.monotonic() >= deadline:
                break
            await asyncio.sleep(0.2)
        return job

    async def cancel(self, job_id: str) -> bool:
        """Soft-cancel: whatever stages already finished stay persisted.

        Returns False when the job is unknown or already terminal (including
        one known only from its persisted row).
        """
        job = self._jobs.get(job_id)
        if job is None:
            return False
        if job.state in TERMINAL_JOB_STATES:
            return False
        job.cancelled = True
        task = job.task
        if task is not None and not task.done():
            task.cancel()
        return True

    async def shutdown(self):
        """Cancel live jobs and let each one persist its own state."""
        tasks = [t for t in self._tasks.values() if not t.done()]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    # --- serialisation ------------------------------------------------------
    def public(self, job: Job) -> dict:
        return self._payload(job)

    @staticmethod
    def from_record(record: dict) -> dict:
        """Rebuild the public payload from a persisted job row.

        `progress` is stored verbatim, so the same progress block a live job
        served is replayed here; stage summaries come back out of it and the
        subdomain list out of the stored result.
        """
        progress = record.get("progress") or {}
        stored = record.get("result") or {}
        results = {}
        for stage in STAGES:
            entry = progress.get(stage) or {}
            if entry.get("state") in (DONE, SKIPPED):
                results[stage] = entry.get("summary")
            else:
                results[stage] = None
        return {
            "job_id": record["id"],
            "apex": record["apex"],
            "state": record["state"],
            "stages": record["stages"],
            "auto_stages": [],
            "created_at": record["created_at"],
            "finished_at": record["finished_at"],
            "elapsed_seconds": _elapsed(record["created_at"], record["finished_at"]),
            "error": record["error"],
            "force": False,
            "truncated": stored.get("truncated") or {},
            "cached": bool(stored.get("cached")),
            "fetched_at": None,
            "count": stored.get("count") or len(stored.get("subdomains") or []),
            "sources": stored.get("sources") or {},
            "source_errors": stored.get("source_errors") or {},
            "subdomains": stored.get("subdomains") or [],
            "progress": progress,
            "results": results,
            "replayed": True,
        }

    # --- internals ----------------------------------------------------------
    def _reap(self):
        cutoff = int(time.time()) - self._job_ttl
        stale = [
            jid
            for jid, job in self._jobs.items()
            if job.state in TERMINAL_JOB_STATES
            and (job.finished_at or job.created_at) < cutoff
            and jid not in self._tasks
        ]
        for jid in stale:
            self._jobs.pop(jid, None)
            # The persisted row has its own TTL: deleting it here would drop
            # history for a job the operator may still want to inspect.

    def _payload(self, job: Job) -> dict:
        """The exact JSON served by GET /jobs/{id} for a live in-memory job."""
        results = {}
        for stage in job.stages:
            prog = job.progress.get(stage)
            if prog and prog.state in (DONE, SKIPPED):
                results[stage] = prog.summary
        for stage in STAGES:
            results.setdefault(stage, None)
        return {
            "job_id": job.id,
            "apex": job.apex,
            "state": job.state,
            "stages": job.stages,
            "auto_stages": job.auto,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
            "elapsed_seconds": _elapsed(
                job.started_at or job.created_at, job.finished_at
            ),
            "error": job.error,
            "force": job.force,
            "truncated": job.truncated,
            "cached": job.cached,
            "fetched_at": job.fetched_at,
            "count": len(job.subdomains),
            "sources": job.aggregate_meta.get("sources") or {},
            "source_errors": job.aggregate_meta.get("errors") or {},
            "subdomains": job.subdomains,
            "progress": {s: job.progress[s].as_dict() for s in job.stages},
            "results": results,
        }

    def _progress_dict(self, job: Job) -> dict:
        return {s: job.progress[s].as_dict() for s in job.stages}

    async def _persist(self, job: Job):
        await self._store.job_update(
            job.id,
            job.state,
            self._progress_dict(job),
            {
                "count": len(job.subdomains),
                "subdomains": job.subdomains,
                "truncated": job.truncated,
                "sources": job.aggregate_meta.get("sources") or {},
                "source_errors": job.aggregate_meta.get("errors") or {},
                "cached": job.cached,
            },
            job.error,
            job.finished_at,
        )

    # --- job body -----------------------------------------------------------
    async def _run(self, job: Job):
        try:
            async with self._sem:
                job.state = RUNNING
                job.started_at = int(time.time())
                try:
                    await asyncio.wait_for(
                        self._run_inner(job), timeout=config.JOB_MAX_SECONDS
                    )
                except asyncio.TimeoutError:
                    job.state = TIMEOUT
                    job.error = f"exceeded the {config.JOB_MAX_SECONDS}s job budget"
        except asyncio.CancelledError:
            # A cancel (or a timeout from the budget above) must leave the job
            # terminal before the exception escapes, or the state falls through
            # to the "ended without a terminal state" net in finally.
            if job.state not in TERMINAL_JOB_STATES:
                job.state = CANCELLED
                job.error = "cancelled by request"
            self._mark_pending_cancelled(job)
            job.finished_at = int(time.time())
            with contextlib.suppress(Exception):
                await self._persist(job)
            raise
        except Exception as exc:
            job.state = ERROR
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            if job.state not in TERMINAL_JOB_STATES:
                job.state = ERROR
                job.error = job.error or "job ended without a terminal state"
            job.finished_at = job.finished_at or int(time.time())
            self._mark_pending_cancelled(job)
            with contextlib.suppress(Exception):
                await self._persist(job)

    def _mark_pending_cancelled(self, job: Job):
        for stage in job.stages:
            prog = job.progress[stage]
            if prog.state in (PENDING, RUNNING):
                prog.state = CANCELLED

    async def _run_inner(self, job: Job):
        await self._load_aggregate(job)
        handlers = {
            "dns": self._stage_dns,
            "http": self._stage_http,
            "ports": self._stage_ports,
            "security": self._stage_security,
        }
        # STAGE_DEPS are a prefix of STAGES, so a single ordered pass is enough.
        for stage in job.stages:
            prog = job.progress[stage]
            if prog.state in (CANCELLED, SKIPPED):
                continue
            try:
                await handlers[stage](job)
            except asyncio.CancelledError:
                prog.state = CANCELLED
                raise
            except Exception as exc:
                prog.state = ERROR
                prog.error = f"{type(exc).__name__}: {exc}"
            if job.cancelled:
                prog.state = CANCELLED
                break
        if not job.cancelled:
            job.state = DONE

    # --- stages -------------------------------------------------------------
    async def _load_aggregate(self, job: Job):
        """Resolve the subdomain list from cache, inventory or upstream sources."""
        if not job.force:
            hit = await self._cache.get(job.apex)
            if hit:
                names, meta, fetched_at = hit
                job.subdomains = names
                job.aggregate_meta = meta
                job.cached = True
                job.fetched_at = int(fetched_at)
                return
            stored = await self._store.get_subdomains(job.apex)
            if stored:
                job.subdomains = stored
                job.cached = True
                job.fetched_at = None
                return

        t0 = time.perf_counter()
        names, meta = await aggregator.aggregate(job.apex)
        meta = dict(meta)
        meta["elapsed_seconds"] = round(time.perf_counter() - t0, 2)
        meta["count"] = len(names)
        job.subdomains = names
        job.aggregate_meta = meta
        job.fetched_at = int(time.time())
        await self._cache.put(job.apex, names, meta)
        await self._store.replace_subdomains(job.apex, names)

    async def _stage_dns(self, job: Job):
        prog = job.progress["dns"]
        targets, dropped = _select_hosts(job.subdomains, config.MAX_DNS_HOSTS)
        if dropped:
            job.truncated["dns"] = dropped
        prog.total = len(targets)
        if not targets:
            prog.state = SKIPPED
            prog.reason = "no subdomains to resolve"
            prog.summary = _empty_dns_summary()
            return

        cached: dict[str, dict | None] = {}
        if not job.force:
            cached = await self._store.get_stage(
                job.apex, "dns", targets, config.TTL_DNS
            )
        if cached and not _needs_probing(cached, targets):
            prog.state = SKIPPED
            prog.from_cache = True
            prog.checked = prog.total
            prog.summary = _dns_summary(unflatten("dns", cached), 0.0)
            return

        t0 = time.perf_counter()
        fresh = await dns_verify.verify(targets)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        merged = _merge_cached(cached, flatten("dns", fresh))
        await self._store.put_stage(job.apex, "dns", merged, elapsed_ms)
        await self._store.replace_subdomains(job.apex, job.subdomains)
        prog.state = DONE
        prog.checked = prog.total
        prog.elapsed_ms = elapsed_ms
        prog.summary = _dns_summary(unflatten("dns", merged), elapsed_ms / 1000)

    async def _stage_http(self, job: Job):
        prog = job.progress["http"]
        alive = _alive_map(job)
        if not alive:
            prog.state = SKIPPED
            prog.reason = "no dns results to probe"
            prog.summary = _http_summary({}, 0.0)
            return
        targets, dropped = _select_hosts(sorted(alive), config.MAX_HTTP_HOSTS)
        if dropped:
            job.truncated["http"] = dropped
        prog.total = len(targets)

        cached: dict[str, dict | None] = {}
        if not job.force:
            cached = await self._store.get_stage(
                job.apex, "http", targets, config.TTL_HTTP
            )
        if cached and not _needs_probing(cached, targets):
            prog.state = SKIPPED
            prog.from_cache = True
            prog.checked = prog.total
            prog.summary = _http_summary(unflatten("http", cached), 0.0)
            return

        t0 = time.perf_counter()
        fresh = await http_probe.probe(targets)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        merged = _merge_cached(cached, flatten("http", fresh))
        await self._store.put_stage(job.apex, "http", merged, elapsed_ms)
        prog.state = DONE
        prog.checked = prog.total
        prog.elapsed_ms = elapsed_ms
        prog.summary = _http_summary(unflatten("http", merged), elapsed_ms / 1000)

    async def _stage_ports(self, job: Job):
        prog = job.progress["ports"]
        alive = _alive_map(job)
        if not alive:
            prog.state = SKIPPED
            prog.reason = "no dns results to scan"
            prog.summary = _empty_ports_summary()
            return
        targets, dropped = _select_hosts(sorted(alive), config.MAX_SCAN_HOSTS)
        if dropped:
            job.truncated["ports"] = dropped
        prog.total = len(targets)

        cached = {}
        if not job.force:
            cached = await self._store.get_stage(
                job.apex, "ports", targets, config.TTL_PORTS
            )
        if cached and not _needs_probing(cached, targets):
            prog.state = SKIPPED
            prog.from_cache = True
            prog.checked = prog.total
            prog.summary = _ports_summary(unflatten("ports", cached), 0.0)
            return

        t0 = time.perf_counter()
        fresh = await port_scan.scan({h: alive[h] for h in targets})
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        merged = _merge_cached(cached, flatten("ports", fresh.get("results") or {}))
        await self._store.put_stage(job.apex, "ports", merged, elapsed_ms)
        summary = {
            "ports": fresh.get("ports") or [p for p, _ in port_scan.DEFAULT_PORTS],
            "results": unflatten("ports", merged),
            "hosts_with_open": sum(1 for v in merged.values() if v),
            "total_open": sum(len(v) for v in merged.values() if v),
        }
        prog.state = DONE
        prog.checked = prog.total
        prog.elapsed_ms = elapsed_ms
        prog.summary = _ports_summary(summary, elapsed_ms / 1000)

    async def _stage_security(self, job: Job):
        prog = job.progress["security"]
        http_results = {
            name: info
            for name, info in (job.progress["http"].summary or {}).get("results", {}).items()
            if info
        }
        if not http_results:
            prog.state = SKIPPED
            prog.reason = "no http results to inspect"
            prog.summary = {"results": {}, "flagged_count": 0, "checked": 0}
            return
        targets, dropped = _select_hosts(sorted(http_results), config.MAX_SCAN_HOSTS)
        if dropped:
            job.truncated["security"] = dropped
        prog.total = len(targets)

        cached = {}
        if not job.force:
            cached = await self._store.get_stage(
                job.apex, "security", targets, config.TTL_SECURITY
            )
        if cached and not _needs_probing(cached, targets):
            prog.state = SKIPPED
            prog.from_cache = True
            prog.checked = prog.total
            prog.summary = _sec_summary(unflatten("security", cached), 0.0)
            return

        t0 = time.perf_counter()
        fresh = await recon.recon({h: http_results[h] for h in targets})
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        merged = _merge_cached(
            cached, flatten("security", fresh.get("results") or {})
        )
        await self._store.put_stage(job.apex, "security", merged, elapsed_ms)
        summary = unflatten("security", merged)
        prog.state = DONE
        prog.checked = prog.total
        prog.elapsed_ms = elapsed_ms
        prog.summary = _sec_summary(summary, elapsed_ms / 1000)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _elapsed(start: int | None, end: int | None) -> float | None:
    if not start:
        return None
    return round((end or time.time()) - start, 2)


def _merge_cached(cached: dict, fresh: dict) -> dict:
    """Everything probed this run plus the still-fresh rows we reused.

    Rewriting the reused rows refreshes their checked_at, so a partially
    refreshed stage does not immediately look half-stale.
    """
    merged = dict(cached or {})
    merged.update(fresh or {})
    return merged


def _alive_map(job: Job) -> dict[str, list[str]]:
    """The alive {host: [ips]} payload, whatever produced it this run."""
    dns = job.progress.get("dns")
    if dns is None or dns.state not in (DONE, SKIPPED) or not dns.summary:
        return {}
    return dns.summary.get("alive") or {}


def _empty_dns_summary() -> dict:
    return {"alive": {}, "alive_count": 0, "shared_ips": {}, "elapsed_seconds": 0.0}


def _dns_summary(alive: dict[str, list[str] | None], elapsed: float) -> dict:
    """dns_verify.summarize() over the stored {host: [ips] | None} map."""
    return dns_verify.summarize(alive) | {"elapsed_seconds": round(elapsed, 2)}


def _http_summary(results: dict[str, dict | None], elapsed: float) -> dict:
    return {
        "results": results,
        "web_count": sum(1 for v in results.values() if v),
        "elapsed_seconds": round(elapsed, 2),
    }


def _empty_ports_summary() -> dict:
    return {
        "ports": [p for p, _ in port_scan.DEFAULT_PORTS],
        "results": {},
        "hosts_with_open": 0,
        "total_open": 0,
        "elapsed_seconds": 0.0,
    }


def _ports_summary(results: dict, elapsed: float) -> dict:
    out = dict(results)
    out.setdefault("ports", [p for p, _ in port_scan.DEFAULT_PORTS])
    out.setdefault("results", {})
    out.setdefault("hosts_with_open", 0)
    out.setdefault("total_open", 0)
    out["elapsed_seconds"] = round(elapsed, 2)
    return out


def _sec_summary(results: dict[str, dict], elapsed: float) -> dict:
    flagged = {
        s: r
        for s, r in results.items()
        if r and (r.get("paths") or (r.get("tls") or {}).get("expiring_soon"))
    }
    return {
        "results": results,
        "flagged_count": len(flagged),
        "checked": len(results),
        "elapsed_seconds": round(elapsed, 2),
    }
