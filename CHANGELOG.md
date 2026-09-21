# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-09-21

Scans became background jobs, enrichment results are now persisted per stage,
and three free no-key data sources were added.

### Added

- **Background scan jobs.** `POST /api/v1/scan` returns `202` with a job id
  immediately; `GET /api/v1/jobs/{job_id}` polls state, per-stage progress and
  whatever results already exist; `GET /api/v1/jobs?apex=` lists recent jobs so
  a reloaded page can re-attach; `DELETE /api/v1/jobs/{job_id}` soft-cancels a
  running job. Previously the four enrichment stages were awaited inline in the
  request, so a 20,000-subdomain apex held a connection open for minutes and a
  client timeout threw all the work away.
- **Persistent enrichment store** (`backend/store.py`). Subdomain inventory,
  per-stage enrichment and job records live in SQLite. Enrichment is keyed by
  `(apex, host, stage)` with independent per-stage TTLs, so a rescan reuses
  everything still fresh and only probes what is missing; a partially refreshed
  stage does not look half-stale, because reused rows have their `checked_at`
  refreshed too. A stored row with a `NULL` payload is a cached **negative**
  result (a host that does not resolve), not a missing one.
- **Stage dependency closure** (`backend/jobs.py`). `security` implies `http`
  implies `dns`, resolved transitively. The added stages are reported back as
  `auto_stages`, so a client can say "we also ran DNS for this" instead of
  silently receiving a `null` column.
- **Three new CT/passive-DNS sources**, bringing the total to five:
  - `hackertarget.py` — HackerTarget `hostsearch`, CSV `host,ip`. The exhausted
    free tier answers **HTTP 200 with an error sentence**, so the body is
    string-checked and an error raised rather than silently returning nothing.
  - `wayback.py` — the Wayback CDX index, `fl=original` with `urlsplit` to strip
    the port and path. The slowest upstream by far, which is a large part of why
    scans are background jobs now.
  - `certspotter.py` — Cert Spotter `v1/issuances` (the `v0` endpoint is
    retired), `expand=dns_names`, with `429` raised explicitly as a
    rate-limit signal instead of an empty result.
- **`docs/API.md`** — full endpoint reference, job state machine, stage
  dependency matrix and every response shape.
- **Per-stage progress pills and a growing result table** in the UI, plus
  `?job=<id>` to resume polling after a reload and CSV columns for
  `open_ports` / `security_flags` / `tls_days_left`.
- **`SOURCE_HTTP_MAX_BYTES`** — a body size cap per source request.
- **`truncated`** — the number of hosts dropped by a stage's host cap is
  reported in the response instead of vanishing.
- Config knobs: `WAYBACK_TIMEOUT`, `SOURCE_HTTP_MAX_BYTES`, `TTL_SUBDOMAIN`,
  `TTL_DNS`, `TTL_HTTP`, `TTL_PORTS`, `TTL_SECURITY`, `JOB_MAX_CONCURRENT`,
  `JOB_TTL_SECONDS`, `JOB_MAX_SECONDS`, `JOB_CANCEL_GRACE_SECONDS`,
  `JOB_PRUNE_INTERVAL_SECONDS`, `ENRICHMENT_RETENTION_DAYS`, `MAX_DNS_HOSTS`,
  `MAX_HTTP_HOSTS`, `MAX_SCAN_HOSTS`, `HTTP_VERIFY_TLS`, `HTTP_PROBE_TIMEOUT`,
  `FRONTEND_DIR`.

### Changed

- `GET /api/v1/search` is **additive only**. The key set is unchanged, and with
  no `*_check` flag the response is exactly what it was. The new
  `enrich_timeout` query parameter (default `0`) decides how long to wait for
  the enrichment job before returning `202`; `202` means "poll the job", never
  "failed", and a still-running job returns the complete subdomain list with
  `null` enrichment columns. `format=text` still short-circuits before any
  enrichment.
- `@app.on_event("startup")` → a `lifespan` async context manager, which owns
  the prune task, registry shutdown and store close.
- `StaticFiles(directory=...)` now uses `config.FRONTEND_DIR`, an absolute path.
  It resolves at construction, so the old relative `"frontend"` returned 404 for
  the UI whenever the server was started from another working directory.
- `aggregator._NAME_RE` removed; validation uses the single compiled
  `config.APEX_PATTERN`.
- `recon.py` and `http_probe.py` take TLS verification from
  `config.HTTP_VERIFY_TLS` instead of hard-coding `verify=False`. The default is
  still `False` — the behaviour is unchanged, it is just no longer unreachable.
- Job concurrency (`JOB_MAX_CONCURRENT`) is separate from stage concurrency.
  Each stage module keeps its own semaphore, and the job semaphore counts jobs,
  never hosts, so a 38-port scan cannot starve the DNS stage.
- README (both languages) updated in lockstep, with the `MAX_SCAN_HOSTS=1000`
  rationale spelled out.

### Fixed

- **Apex validation bypass.** `re.match()` with a trailing `$` accepts
  `"a.com\n"`; matching now uses `fullmatch()`. At the HTTP layer `.strip()` and
  URL parsing already normalised the newline away, so this was
  defence-in-depth rather than a live exploit — but `aggregator._normalize()`
  validates names supplied by untrusted upstreams, and that is where the
  fullmatch matters.
- **Cache hits lost all source information.** The cache-hit path set `meta = {}`,
  so `sources` and `errors` came back empty on every cached response.
- **`port_check` and `sec_check` silently returned `null`.** Requesting ports
  without DNS, or security without HTTP, produced an empty column with no
  explanation. Dependencies are now added automatically and the reason is
  carried in the stage's `progress.reason`.
- **`dns` negative results were dropped**, so every non-resolving host was
  re-resolved on every scan.
- `datetime.datetime.utcnow()` (deprecated) → `datetime.datetime.now(datetime.UTC)`
  in `recon.py`.
- Dead in-function imports (`subprocess`, `json`, `os`, `tempfile`) and a
  self-contradicting comment removed from `recon.check_tls`.
- The CSV export dropped the port and security columns even when the user had
  asked for them; both are now included, along with the TLS days remaining.

### Notes

- The job wall-clock budget (`JOB_MAX_SECONDS`) and an explicit cancel both
  leave a terminal state. Finished stages stay persisted either way, so a
  cancelled scan is a partial result rather than lost work.
- Jobs left non-terminal by a previous process are marked failed at startup
  rather than resumed: the inventory and every enrichment row survive, so
  re-running the scan only pays for the missing stages.
- `cancel()` sets the flag and cancels the task; the job's `state` becomes
  `cancelled` when the task unwinds, so a `GET` racing that window can still
  report `running` for a moment.

[Unreleased]: https://github.com/nuoyax/Panoptes/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/nuoyax/Panoptes/compare/v1.0.0...v1.1.0
