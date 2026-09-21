# Panoptes API

Base path: `/api/v1`. All responses are JSON unless stated otherwise.

- [Endpoints](#endpoints)
- [GET /search](#get-search)
- [POST /scan](#post-scan)
- [GET /jobs/{job_id}](#get-jobsjob_id)
- [GET /jobs](#get-jobs)
- [DELETE /jobs/{job_id}](#delete-jobsjob_id)
- [GET /health](#get-health)
- [Scan job state machine](#scan-job-state-machine)
- [Stage dependency matrix](#stage-dependency-matrix)
- [Progress and result shapes](#progress-and-result-shapes)

---

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/search` | Subdomain list, plus optional enrichment |
| `POST` | `/api/v1/scan` | Start a background scan → `202` + job id |
| `GET` | `/api/v1/jobs/{job_id}` | Poll one job |
| `GET` | `/api/v1/jobs` | Recent jobs (re-attach after a reload) |
| `DELETE` | `/api/v1/jobs/{job_id}` | Soft-cancel a running job |
| `GET` | `/api/v1/health` | Liveness + job concurrency |

Stage names are `dns`, `http`, `ports`, `security`. The legacy checkbox names
(`dns_check`, `http_check`, `port_check`, `sec_check`) are accepted anywhere a
stage name is, via `STAGE_ALIASES`.

---

## GET /search

Subdomain lookup. Backwards compatible: with no `*_check` flag the response has
exactly the keys it always had, and `format=text` short-circuits before any
enrichment work.

| Query | Type | Default | Notes |
|---|---|---|---|
| `apex` | string | required | Apex domain, e.g. `baidu.com` |
| `format` | `json` \| `text` | `json` | `text` = one subdomain per line |
| `refresh` | bool | `false` | Bypass the 24h subdomain cache and the per-stage caches |
| `dns_check` | bool | `false` | Resolve A records per subdomain |
| `http_check` | bool | `false` | Status code and page title |
| `port_check` | bool | `false` | TCP port scan on DNS-alive hosts |
| `sec_check` | bool | `false` | Sensitive paths, security headers, TLS |
| `enrich_timeout` | float `0..600` | `0` | Seconds to wait for the job before returning `202` |

```bash
curl "http://127.0.0.1:8000/api/v1/search?apex=example.com&dns_check=1&enrich_timeout=20"
```

`200` — the job reached a terminal state within `enrich_timeout`:

```json
{
  "apex": "example.com",
  "count": 3,
  "cached": false,
  "fetched_at": 1758400000,
  "sources": { "crt.sh": 3, "hackertarget": 2 },
  "errors": {},
  "elapsed_seconds": 1.42,
  "subdomains": ["a.example.com", "b.example.com", "c.example.com"],
  "dns": { "alive": { "a.example.com": ["93.184.216.34"] }, "alive_count": 1, "shared_ips": {}, "elapsed_seconds": 0.8 },
  "http": null,
  "ports": null,
  "security": null,
  "job_id": "9f2c…",
  "truncated": {},
  "job": { "state": "done", "stages": ["dns"], "auto_stages": [], "progress": { "dns": { "state": "done", "checked": 3, "total": 3 } } }
}
```

`202` — still working. **`202` means "poll the job", never "failed".** The
subdomain list is complete and usable; the enrichment columns are `null`:

```bash
curl "http://127.0.0.1:8000/api/v1/jobs/9f2c…"
```

`400` — `{"error": "invalid apex domain: 'bad..apex'"}`.

Notes:

- A cache hit keeps the real `sources` / `errors` counts (this used to be lost).
- `dns` is the only stage summarized as `alive`, so `dns: null` means the stage
  has not produced anything yet, while `dns: {"alive": {}, "alive_count": 0}`
  means it ran and nothing resolved.

---

## POST /scan

Starts a background scan and returns immediately.

```json
{ "apex": "example.com", "stages": ["dns", "http", "sec"], "force": false }
```

`stages` defaults to `["dns"]`. `force: true` ignores every stored row and
re-probes. Unrequested dependencies are added automatically and reported back.

`202`:

```json
{
  "job_id": "9f2c…",
  "apex": "example.com",
  "stages": ["dns", "http", "security"],
  "auto_stages": ["dns", "http"],
  "state": "queued",
  "elapsed_seconds": null,
  "poll": "/api/v1/jobs/9f2c…",
  "poll_interval_ms": 1000
}
```

`400` — invalid apex, or an unknown stage, in which case the response lists the
valid names:

```json
{ "error": "unknown stage: 'nope'", "valid": ["dns", "http", "ports", "security", "dns_check", …] }
```

**Deduplication:** if a job with the same apex and a superset of the requested
stages is already active, its id is returned instead of starting a second scan.
Four overlapping scans of one apex cannot be launched by toggling checkboxes.

---

## GET /jobs/{job_id}

Poll target. Always `200` while the job is known.

```json
{
  "job_id": "9f2c…",
  "apex": "example.com",
  "state": "running",
  "stages": ["dns", "http"],
  "auto_stages": ["dns"],
  "created_at": 1758400000,
  "finished_at": null,
  "elapsed_seconds": 3.1,
  "error": null,
  "force": false,
  "truncated": {},
  "cached": false,
  "fetched_at": 1758400000,
  "count": 3,
  "sources": { "crt.sh": 3 },
  "source_errors": {},
  "subdomains": ["a.example.com", "b.example.com", "c.example.com"],
  "progress": {
    "dns":  { "state": "done", "checked": 3, "total": 3, "elapsed_ms": 820, "from_cache": false, "summary": { "…": "…" } },
    "http": { "state": "running", "checked": 41, "total": 120, "elapsed_ms": null, "from_cache": false, "summary": null }
  },
  "results": {
    "dns": { "alive": { "a.example.com": ["93.184.216.34"] }, "alive_count": 1, "shared_ips": {}, "elapsed_seconds": 0.82 },
    "http": null, "ports": null, "security": null
  }
}
```

- `results[stage]` is the summary of a stage in state `done` or `skipped`, and
  `null` for every other state — including `pending`, so a client never has to
  tell "not asked for" from "asked for, not finished".
- `subdomains` is re-read from the inventory on every poll, so the list can grow
  while the job runs.
- A job that has been reaped from memory is served from the database row in the
  same shape, with `"replayed": true` and `auto_stages: []` (the flag was not
  persisted).
- `404` — `{"error": "job not found"}`: unknown id, or a finished job aged past
  `JOB_TTL_SECONDS` and pruned.

---

## GET /jobs

| Query | Type | Default | Notes |
|---|---|---|---|
| `apex` | string | — | Only jobs for this apex |
| `limit` | int `1..100` | `20` | Newest first |

```json
{ "jobs": [ { "job_id": "9f2c…", "apex": "example.com", "stages": ["dns"], "state": "done", "created_at": 1758400000, "finished_at": 1758400012, "error": null } ] }
```

---

## DELETE /jobs/{job_id}

Soft cancel. Whatever stages already finished stay persisted and stay reusable.

| Status | Body |
|---|---|
| `200` | `{"cancelled": true, "job_id": "9f2c…"}` |
| `404` | `{"error": "job not found"}` |
| `409` | `{"cancelled": false, "state": "done", "error": "job already finished"}` |

`cancel()` sets the flag and cancels the task; the job's `state` becomes
`cancelled` when the task unwinds. A `GET` issued inside that window can still
report `running` for a moment.

---

## GET /health

```json
{ "status": "ok", "jobs": { "active": 1, "capacity": 2 } }
```

`capacity` is `JOB_MAX_CONCURRENT`; `active` counts jobs holding a slot.

---

## Scan job state machine

```
                 ┌──────────┐
   POST /scan ──▶│  queued  │  waiting for a concurrency slot
                 └────┬─────┘
                      │ slot acquired
                 ┌────▼─────┐
                 │ running  │◀── poll here, progress advances
                 └────┬─────┘
        ┌─────────┬───┴────┬───────────┬─────────────┐
        │         │        │           │             │
   ┌────▼───┐ ┌───▼───┐ ┌──▼──────┐ ┌──▼─────┐ ┌─────▼────┐
   │  done  │ │ error │ │ timeout │ │cancelled│ │ (orphan) │
   └────────┘ └───────┘ └─────────┘ └─────────┘ └──────────┘
                                                  → error,
                                                    "server restarted"
```

`done`, `error`, `timeout` and `cancelled` are terminal. `timeout` is the
`JOB_MAX_SECONDS` wall-clock budget; `error` also absorbs jobs a previous
process left non-terminal — they are failed at startup, not resumed, because
the subdomain inventory and every enrichment row survive and re-scanning only
pays for the stages that are actually missing.

Per-stage states are `pending`, `running`, `done`, `skipped`, `error`,
`cancelled`. `skipped` with `from_cache: true` means every target was answered
from a fresh stored row (the whole stage cost is a couple of queries);
`skipped` with a `reason` means the stage had nothing to work on — for example
`http` after a `dns` stage where nothing resolved.

---

## Stage dependency matrix

| Stage | Requires | Auto-added | Targets |
|---|---|---|---|
| `dns` | — | — | Subdomains, capped at `MAX_DNS_HOSTS` |
| `http` | `dns` | `dns` | DNS-alive hosts, capped at `MAX_HTTP_HOSTS` |
| `ports` | `dns` | `dns` | DNS-alive hosts, capped at `MAX_SCAN_HOSTS` |
| `security` | `http` (`→ dns`) | `dns`, `http` | Hosts that answered HTTP, capped at `MAX_SCAN_HOSTS` |

Dependencies are resolved transitively: `["sec"]` becomes
`["dns", "http", "security"]`. The added ones come back in `auto_stages` so a
client can say so out loud, instead of silently returning a null column.

When a target list is capped, the dropped count lands in `truncated` under the
stage name and is served on both `/scan`-created jobs and `/search`.

Stages run in the canonical order `dns → http → ports → security`. Each stage
module keeps its own concurrency semaphore; the job semaphore counts jobs only,
never hosts, so a 38-port scan cannot starve the DNS stage.

---

## Progress and result shapes

`progress[stage]`:

| Field | Meaning |
|---|---|
| `state` | `pending` / `running` / `done` / `skipped` / `error` / `cancelled` |
| `checked` / `total` | Targets processed out of planned |
| `elapsed_ms` | Stage wall clock (`null` until it finishes) |
| `from_cache` | Every target was answered from a stored row |
| `summary` | The stage result (see below), `null` until it finishes |
| `error` | Present only when the stage failed |
| `reason` | Present only when the stage was skipped for lack of input |

`results[stage]` is exactly `progress[stage].summary` for finished stages:

| Stage | Summary shape |
|---|---|
| `dns` | `{alive: {host: [ip, …]}, alive_count, shared_ips, elapsed_seconds}` |
| `http` | `{results: {host: {url, status, title}}, web_count, elapsed_seconds}` |
| `ports` | `{ports: [80, …], results: {host: {port: {ip, service}}}, hosts_with_open, total_open, elapsed_seconds}` |
| `security` | `{results: {host: {paths: [{path, status}], headers: {missing, present}, tls: {…}}}, flagged_count, checked, elapsed_seconds}` |

These are byte-for-byte the shapes the synchronous `/search` response used to
carry, so a client that already parsed them needs no change.

---

## Persistence

Enrichment is stored per `(apex, host, stage)`. A scan that only asks for `dns`
writes only `dns` rows, so a later scan that adds `security` writes only the
missing stage and leaves the `dns` rows untouched — no read-modify-write merge
and no race between concurrent scans of the same apex. A stored row with a
`NULL` payload is a cached **negative** result (a host that does not resolve),
not a missing one, so dead hosts are not re-resolved on every scan.

Each stage's TTL is independent (`TTL_DNS`, `TTL_HTTP`, `TTL_PORTS`,
`TTL_SECURITY`); staleness is a read-time comparison against `checked_at`, so
retuning a TTL needs no migration. Rows are dropped after
`ENRICHMENT_RETENTION_DAYS`.
