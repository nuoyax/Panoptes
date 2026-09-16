"""FastAPI entrypoint: /api/v1/search + static frontend."""

import re
import time

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config, aggregator
from .cache import Cache

APEX_PATTERN = re.compile(config.APEX_RE)

app = FastAPI(title="Subdomain Query", version="1.0.0")
cache = Cache()


@app.on_event("startup")
async def startup():
    await cache.init()


@app.get("/api/v1/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/search")
async def search(
    apex: str = Query(..., description="Apex domain, e.g. baidu.com"),
    format: str = Query("json", pattern="^(json|text)$"),
    refresh: bool = Query(False, description="Bypass cache"),
):
    apex = apex.strip().lower()
    if not APEX_PATTERN.match(apex):
        return JSONResponse(
            status_code=400,
            content={"error": f"invalid apex domain: {apex!r}"},
        )

    cached = False
    fetched_at = None
    if not refresh:
        hit = await cache.get(apex)
        if hit:
            subdomains, fetched_at = hit
            cached = True

    if not cached:
        t0 = time.perf_counter()
        subdomains, meta = await aggregator.aggregate(apex)
        elapsed = round(time.perf_counter() - t0, 2)
        await cache.put(apex, subdomains)
        meta.update({"elapsed_seconds": elapsed, "count": len(subdomains)})
    else:
        meta = {}

    if format == "text":
        return PlainTextResponse("\n".join(subdomains) + ("\n" if subdomains else ""))

    return {
        "apex": apex,
        "count": len(subdomains),
        "cached": cached,
        "fetched_at": fetched_at,
        **meta,
        "subdomains": subdomains,
    }


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
