"""FastAPI entrypoint: /api/v1/search + static frontend."""

import re
import time

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config, aggregator, dns_verify, http_probe, port_scan, recon
from .cache import Cache

APEX_PATTERN = re.compile(config.APEX_RE)

app = FastAPI(title="Panoptes", version="1.0.0")
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
    dns_check: bool = Query(False, description="Resolve A records for each subdomain"),
    http_check: bool = Query(False, description="Probe HTTP status and page title"),
    port_check: bool = Query(False, description="TCP port scan on DNS-resolved hosts"),
    sec_check: bool = Query(False, description="Sensitive paths, security headers, TLS cert checks"),
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

    dns_summary = None
    if dns_check and subdomains:
        t1 = time.perf_counter()
        results = await dns_verify.verify(subdomains)
        dns_summary = dns_verify.summarize(results)
        dns_summary["elapsed_seconds"] = round(time.perf_counter() - t1, 2)

    http_summary = None
    if http_check and subdomains:
        t2 = time.perf_counter()
        targets = dns_summary["alive"].keys() if dns_summary else subdomains
        http_results = await http_probe.probe(list(targets))
        http_summary = {
            "results": http_results,
            "web_count": sum(1 for v in http_results.values() if v),
            "elapsed_seconds": round(time.perf_counter() - t2, 2),
        }

    port_summary = None
    if port_check and dns_summary:
        t3 = time.perf_counter()
        port_summary = await port_scan.scan(dns_summary["alive"])
        port_summary["elapsed_seconds"] = round(time.perf_counter() - t3, 2)

    sec_summary = None
    if sec_check and http_summary:
        t4 = time.perf_counter()
        sec_summary = await recon.recon(http_summary["results"])
        sec_summary["elapsed_seconds"] = round(time.perf_counter() - t4, 2)

    return {
        "apex": apex,
        "count": len(subdomains),
        "cached": cached,
        "fetched_at": fetched_at,
        **meta,
        "subdomains": subdomains,
        "dns": dns_summary,
        "http": http_summary,
        "ports": port_summary,
        "security": sec_summary,
    }


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
