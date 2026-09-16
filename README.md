# Subdomain Query

[中文](README.zh-CN.md) | English

A self-hosted subdomain lookup service powered by Certificate Transparency (CT) log aggregation — inspired by [crt.name](https://crt.name).

> 🔍 Query all known subdomains of any apex domain. Results are aggregated from multiple public CT sources concurrently, deduplicated, normalized, and cached in SQLite.

## Features

- **Multi-source aggregation** — concurrent queries against crt.sh and AlienVault OTX; a single source failure never breaks the response
- **SQLite cache** — 24h TTL, second-level response on cache hit, `?refresh=1` to bypass
- **Dual output format** — JSON API + crt.name-style plain text
- **Export** — one-click download as TXT / CSV / JSON from the UI
- **Live filtering & copy** — filter results as you type, click any row to copy
- **Input validation** — strict apex-domain regex; no injection surface

## Quick Start

```bash
git clone <repo-url> && cd query-sub-domin
pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**

## API

| Endpoint | Description |
|---|---|
| `GET /api/v1/search?apex=baidu.com` | JSON: `{apex, count, cached, sources, elapsed_seconds, subdomains[]}` |
| `GET /api/v1/search?apex=baidu.com&format=text` | Plain text, one subdomain per line |
| `GET /api/v1/search?apex=baidu.com&refresh=1` | Force refresh, bypass cache |
| `GET /api/v1/health` | Health check |

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

## Project Structure

```
├── backend/
│   ├── main.py            # FastAPI entrypoint, routes + static hosting
│   ├── config.py          # Timeouts, cache TTL, tuning flags
│   ├── aggregator.py      # Concurrent multi-source aggregation + dedup
│   ├── cache.py           # aiosqlite cache (24h TTL)
│   └── sources/
│       ├── base.py        # CTSource abstract base class
│       ├── crtsh.py       # crt.sh JSON API (exclude=expired for speed)
│       └── otx.py         # AlienVault OTX passive DNS
├── frontend/
│   ├── index.html         # Dark-themed single-page UI
│   └── app.js             # Search, filter, export, copy
└── data/                  # SQLite cache (gitignored)
```

## Performance Notes

- Cold query of a large apex (e.g. `baidu.com`): ~5–20s (dominated by crt.sh upstream)
- `exclude=expired` in `backend/config.py` (`CRTSH_EXCLUDE_EXPIRED`) skips expired certs — 10-20× faster upstream, but returns only active records. Set to `False` for full history (slow).
- Cached queries respond instantly.

## Configuration

All knobs live in [`backend/config.py`](backend/config.py):

| Key | Default | Description |
|---|---|---|
| `UPSTREAM_TIMEOUT` | `120.0` | Per-source HTTP timeout (s) |
| `CACHE_TTL_SECONDS` | `86400` | Cache TTL (24h) |
| `CRTSH_EXCLUDE_EXPIRED` | `True` | Skip expired certs (much faster) |
| `MAX_RESULTS` | `100000` | Hard cap on returned subdomains |

## Security

- Apex input is validated against a strict regex before any upstream call
- Upstream URLs are built from validated input only — no user-controlled URL paths
- See [Security Policy](SECURITY.md) for reporting issues

## License

[MIT](LICENSE)
