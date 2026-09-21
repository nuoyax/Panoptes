"""FastAPI entrypoint: /api/v1/search, background scans and static frontend."""

import asyncio
import contextlib
import time

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import aggregator, config, jobs
from .cache import Cache
from .jobs import JobRegistry, StageNotRequested
from .store import Store

cache = Cache()
store = Store()
registry = JobRegistry(store, cache)


class ScanRequest(BaseModel):
    """Body of POST /api/v1/scan.

    `stages` accepts both the stage names and the legacy checkbox names
    (dns_check, http_check, port_check, sec_check); dependencies are added
    automatically and reported back as `auto_stages`.
    """

    apex: str
    stages: list[str] = Field(default_factory=lambda: ["dns"])
    force: bool = False


async def _prune_loop():
    while True:
        await asyncio.sleep(config.JOB_PRUNE_INTERVAL_SECONDS)
        with contextlib.suppress(Exception):
            await store.prune()


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    """Own the shared resources for the process lifetime.

    Replaces the deprecated @app.on_event("startup"): the prune task needs a
    matching shutdown hook, which on_event did not give us cleanly.
    """
    await cache.init()
    await store.init()
    # Jobs a previous process left running are marked failed rather than
    # resumed: the inventory and every enrichment row survive, so re-scanning
    # only pays for the stages that are actually missing.
    await store.job_mark_orphans()
    prune_task = asyncio.create_task(_prune_loop())
    try:
        yield
    finally:
        prune_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await prune_task
        await registry.shutdown()
        await store.close()


app = FastAPI(title="Panoptes", version="1.1.0", lifespan=lifespan)


def _bad_apex(apex: str) -> JSONResponse:
    return JSONResponse(
        status_code=400, content={"error": f"invalid apex domain: {apex!r}"}
    )


def _is_apex(apex: str) -> bool:
    # fullmatch, not match: re.match() with a trailing "$" accepts "example.com\n"
    return bool(config.APEX_PATTERN.fullmatch(apex))


def _requested_stages(
    dns_check: bool, http_check: bool, port_check: bool, sec_check: bool
) -> list[str]:
    stages = []
    if dns_check:
        stages.append("dns")
    if http_check:
        stages.append("http")
    if port_check:
        stages.append("ports")
    if sec_check:
        stages.append("security")
    return stages


@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "jobs": {"active": registry.active_count(), "capacity": config.JOB_MAX_CONCURRENT},
    }


@app.get("/api/v1/search")
async def search(
    apex: str = Query(..., description="Apex domain, e.g. baidu.com"),
    format: str = Query("json", pattern="^(json|text)$"),
    refresh: bool = Query(False, description="Bypass cache"),
    dns_check: bool = Query(False, description="Resolve A records for each subdomain"),
    http_check: bool = Query(False, description="Probe HTTP status and page title"),
    port_check: bool = Query(False, description="TCP port scan on DNS-resolved hosts"),
    sec_check: bool = Query(False, description="Sensitive paths, security headers, TLS cert checks"),
    enrich_timeout: float = Query(
        0.0,
        ge=0,
        le=600,
        description="Seconds to wait for enrichment; 0 returns the subdomain list immediately "
        "plus a job id to poll",
    ),
):
    """Subdomain lookup. Enrichment is delegated to a background scan job.

    Backwards compatible: with no *_check flag this returns exactly what it
    always did. With flags, the job is created and waited on for at most
    `enrich_timeout` seconds — 202 means "poll the job", not "failed".
    """
    apex = apex.strip().lower()
    if not _is_apex(apex):
        return _bad_apex(apex)

    cached = False
    fetched_at = None
    meta: dict = {}
    subdomains: list[str] = []

    hit = None if refresh else await cache.get(apex)
    if hit:
        subdomains, meta, fetched_at = hit
        cached = True
    else:
        t0 = time.perf_counter()
        subdomains, meta = await aggregator.aggregate(apex)
        meta = dict(meta)
        meta["elapsed_seconds"] = round(time.perf_counter() - t0, 2)
        meta["count"] = len(subdomains)
        await cache.put(apex, subdomains, meta)
        fetched_at = int(time.time())

    if format == "text":
        return PlainTextResponse("\n".join(subdomains) + ("\n" if subdomains else ""))

    payload = {
        "apex": apex,
        "count": len(subdomains),
        "cached": cached,
        "fetched_at": fetched_at,
        "sources": meta.get("sources") or {},
        "errors": meta.get("errors") or {},
        "elapsed_seconds": meta.get("elapsed_seconds"),
        "subdomains": subdomains,
        "dns": None,
        "http": None,
        "ports": None,
        "security": None,
        "job_id": None,
        "truncated": {},
    }

    stages = _requested_stages(dns_check, http_check, port_check, sec_check)
    if not stages or not subdomains:
        return payload

    job = await registry.create(apex, stages, force=refresh)
    if enrich_timeout > 0:
        await registry.wait(job, timeout=enrich_timeout)

    view = registry.public(job)
    payload.update(
        {
            "dns": view["results"]["dns"],
            "http": view["results"]["http"],
            "ports": view["results"]["ports"],
            "security": view["results"]["security"],
            "job_id": job.id,
            "truncated": view["truncated"],
            "job": {
                "state": job.state,
                "stages": job.stages,
                "auto_stages": job.auto,
                "progress": view["progress"],
            },
        }
    )
    if job.state in jobs.TERMINAL_JOB_STATES:
        return payload
    # Still working: the subdomain list is complete and usable, the enrichment
    # columns are not. 202 says "come back to /api/v1/jobs/{id}".
    return JSONResponse(status_code=202, content=payload)


@app.post("/api/v1/scan", status_code=202)
async def scan(body: ScanRequest):
    """Start a background scan and return its id."""
    apex = body.apex.strip().lower()
    if not _is_apex(apex):
        return _bad_apex(apex)
    try:
        resolved = jobs.expand_stages(body.stages or ["dns"])
    except StageNotRequested as exc:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"unknown stage: {exc.args[0]!r}",
                "valid": sorted(set(jobs.STAGES) | set(jobs.STAGE_ALIASES)),
            },
        )
    if not resolved:
        resolved = ["dns"]

    job = await registry.create(apex, resolved, force=body.force)
    view = registry.public(job)
    return {
        "job_id": job.id,
        "apex": job.apex,
        "stages": job.stages,
        "auto_stages": job.auto,
        "state": job.state,
        "elapsed_seconds": view["elapsed_seconds"],
        "poll": f"/api/v1/jobs/{job.id}",
        "poll_interval_ms": 1000,
    }


@app.get("/api/v1/jobs")
async def list_jobs(
    apex: str | None = Query(None, description="Only jobs for this apex"),
    limit: int = Query(20, ge=1, le=100),
):
    """Recent jobs, so a reloaded page can re-attach to one."""
    if apex is not None:
        apex = apex.strip().lower()
        if not _is_apex(apex):
            return _bad_apex(apex)
    return {"jobs": await store.job_list(apex, limit)}


@app.get("/api/v1/jobs/{job_id}")
async def get_job(job_id: str):
    """Full job view: state, per-stage progress and whatever results exist."""
    live = registry.get(job_id)
    if live is not None:
        return registry.public(live)
    record = await store.job_get(job_id)
    if record is None:
        return JSONResponse(status_code=404, content={"error": "job not found"})
    return JobRegistry.from_record(record)


@app.delete("/api/v1/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Soft-cancel: finished stages stay persisted and stay usable."""
    if await registry.cancel(job_id):
        return {"cancelled": True, "job_id": job_id}
    record = await store.job_get(job_id)
    if record is None:
        return JSONResponse(status_code=404, content={"error": "job not found"})
    return JSONResponse(
        status_code=409,
        content={"cancelled": False, "state": record["state"], "error": "job already finished"},
    )


app.mount(
    "/",
    StaticFiles(directory=str(config.FRONTEND_DIR), html=True),
    name="frontend",
)
