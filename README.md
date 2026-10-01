# Panoptes

[中文](README.zh-CN.md) | English

**Panoptes** (Πανόπτης, "the all-seeing") — a self-hosted subdomain lookup service powered by Certificate Transparency (CT) log aggregation — inspired by [crt.name](https://crt.name).

> 🔍 Query all known subdomains of any apex domain. Results are aggregated from multiple public CT sources concurrently, deduplicated, normalized, and cached in SQLite.

## Features

- **Multi-source aggregation** — concurrent queries against crt.sh, AlienVault OTX, HackerTarget, the Wayback CDX index and Cert Spotter; a single source failure never breaks the response
- **Background scans with polling** — `POST /api/v1/scan` returns a job id immediately, so a large apex no longer blocks a request for minutes. Progress per stage is pollable and partial results are usable
- **Per-stage persistence** — DNS / HTTP / port / security results are stored per `(apex, host, stage)` with independent TTLs. Re-scanning an apex reuses everything still fresh and only pays for what is missing
- **Automatic stage dependencies** — asking for `security` implies `http` and `dns`; the added stages are reported back rather than silently returning an empty column
- **SQLite cache** — 24h TTL on the subdomain list, second-level response on cache hit, `?refresh=1` to bypass
- **Dual output format** — JSON API + crt.name-style plain text
- **Staged UI** — per-stage progress pills, growing result table, cancel with partial results kept, `?job=` resume on reload
- **Export** — one-click download as TXT / CSV / JSON from the UI
- **Live filtering & copy** — filter results as you type, click any row to copy
- **Input validation** — strict apex-domain regex matched with `fullmatch`; no injection surface

## Quick Start

```bash
git clone https://github.com/nuoyax/Panoptes.git && cd Panoptes
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**

## API

Full reference, including the job state machine and every response shape:
**[docs/API.md](docs/API.md)**.

| Endpoint | Description |
|---|---|
| `GET /api/v1/search?apex=baidu.com` | JSON: `{apex, count, cached, sources, elapsed_seconds, subdomains[]}` |
| `GET /api/v1/search?apex=baidu.com&format=text` | Plain text, one subdomain per line |
| `GET /api/v1/search?apex=baidu.com&refresh=1` | Force refresh, bypass cache |
| `GET /api/v1/search?apex=baidu.com&dns_check=1` | Subdomains plus enrichment; `202` means "poll the job" |
| `POST /api/v1/scan` | Start a background scan → `202` + `{job_id, stages, poll}` |
| `GET /api/v1/jobs/{job_id}` | Job state, per-stage progress and results |
| `GET /api/v1/jobs?apex=baidu.com` | Recent jobs, to re-attach after a reload |
| `DELETE /api/v1/jobs/{job_id}` | Soft-cancel a running job (`409` if already finished) |
| `GET /api/v1/health` | Health check + job concurrency |

Example:

```bash
curl "http://127.0.0.1:8000/api/v1/search?apex=baidu.com&format=text"
```

```text
www.baidu.com
tieba.baidu.com
image.baidu.com
...
```

Scan with enrichment, then poll:

```bash
JOB=$(curl -s -X POST http://127.0.0.1:8000/api/v1/scan \
      -H "Content-Type: application/json" \
      -d '{"apex":"example.com","stages":["dns","http","sec"]}' | jq -r .job_id)
curl -s "http://127.0.0.1:8000/api/v1/jobs/$JOB" | jq '{state, progress}'
```

## Project Structure

```
├── backend/
│   ├── main.py            # FastAPI entrypoint (Panoptes), routes + static hosting
│   ├── config.py          # Single source of truth: timeouts, TTLs, caps, regex
│   ├── aggregator.py      # Concurrent multi-source aggregation + dedup
│   ├── cache.py           # aiosqlite subdomain cache (24h TTL)
│   ├── store.py           # Subdomain inventory, per-stage enrichment and job rows
│   ├── jobs.py            # Background scan registry: stages, deps, progress
│   ├── dns_verify.py      # Concurrent A-record resolution
│   ├── http_probe.py      # HTTP status + page title
│   ├── port_scan.py       # TCP port scan (38 common ports)
│   ├── recon.py           # Sensitive paths, security headers, TLS certs
│   └── sources/
│       ├── base.py        # CTSource abstract base class
│       ├── crtsh.py       # crt.sh JSON API (exclude=expired for speed)
│       ├── otx.py         # AlienVault OTX passive DNS
│       ├── hackertarget.py# HackerTarget hostsearch CSV
│       ├── wayback.py     # Wayback CDX index (slowest source)
│       └── certspotter.py # Cert Spotter v1 issuances
├── frontend/
│   ├── index.html         # Dark-themed single-page UI
│   └── app.js             # Scan, poll, filter, export, copy
├── docs/API.md            # API reference
└── data/                  # SQLite database (gitignored)
```

## Performance Notes

- Cold subdomain query of a large apex (e.g. `baidu.com`): ~5–20s (dominated by upstream CT sources). The Wayback CDX source is the slowest — it is why the scan runs as a background job rather than inline
- `exclude=expired` in `backend/config.py` (`CRTSH_EXCLUDE_EXPIRED`) skips expired certs — 10-20× faster upstream, but returns only active records. Set to `False` for full history (slow).
- Cached subdomain queries respond instantly; a repeat scan with fresh stored rows finishes in milliseconds and reports those stages as `skipped` / `from_cache`
- Enrichment is capped per stage: `MAX_HTTP_HOSTS=3000` for HTTP probing, and `MAX_SCAN_HOSTS=1000` for the port scan and security checks. The cap is arithmetic, not caution — 38 ports × 1000 hosts at the default concurrency and 1.5s timeout is already a 4-6 minute stage, and a 20,000-host apex would multiply that by twenty inside a 900s job budget. `dns` is far cheaper per host and is allowed `MAX_DNS_HOSTS=20000`. Anything dropped is reported in `truncated`.

## Configuration

All knobs live in [`backend/config.py`](backend/config.py):

| Key | Default | Description |
|---|---|---|
| `UPSTREAM_TIMEOUT` | `120.0` | Per-source HTTP timeout (s) |
| `WAYBACK_TIMEOUT` | `120.0` | CDX timeout (s) — kept separate, it is the slowest upstream |
| `SOURCE_HTTP_MAX_BYTES` | `67108864` | Body size cap per source request |
| `CACHE_TTL_SECONDS` | `86400` | Subdomain cache TTL (24h) |
| `TTL_SUBDOMAIN` | `86400` | Subdomain inventory TTL (follows the cache TTL) |
| `TTL_DNS` | `21600` | DNS result TTL (6h) |
| `TTL_HTTP` | `21600` | HTTP result TTL (6h) |
| `TTL_PORTS` | `86400` | Port scan result TTL (24h) |
| `TTL_SECURITY` | `86400` | Security result TTL (24h) |
| `CRTSH_EXCLUDE_EXPIRED` | `True` | Skip expired certs (much faster) |
| `HTTP_VERIFY_TLS` | `False` | Verify TLS when probing targets (often have broken certs) |
| `HTTP_PROBE_TIMEOUT` | `8.0` | Per-host HTTP probe timeout (s) |
| `JOB_MAX_CONCURRENT` | `2` | Scan jobs running at once |
| `JOB_MAX_SECONDS` | `900` | Wall-clock budget per job |
| `JOB_TTL_SECONDS` | `3600` | Finished jobs retained (memory and database) |
| `JOB_PRUNE_INTERVAL_SECONDS` | `3600` | Database prune interval |
| `ENRICHMENT_RETENTION_DAYS` | `30` | Enrichment rows dropped after this |
| `MAX_RESULTS` | `100000` | Hard cap on returned subdomains |
| `MAX_DNS_HOSTS` | `20000` | Hosts fed to the DNS stage |
| `MAX_HTTP_HOSTS` | `3000` | Hosts fed to the HTTP stage |
| `MAX_SCAN_HOSTS` | `1000` | Hosts fed to port scan / security checks |

## Security

- Apex input is validated against a strict regex (`fullmatch`, not `match`) before any upstream call
- Upstream URLs are built from validated input only — no user-controlled URL paths
- The enrichment stages make **active** connections to third-party hosts. See the [Security Policy](SECURITY.md) for what that means for your authorization scope
- See [Security Policy](SECURITY.md) for reporting issues

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)

