# Subdomain Query

A self-hosted subdomain lookup service powered by Certificate Transparency (CT) log aggregation — inspired by crt.name.

- FastAPI backend queries public CT sources concurrently, deduplicates, normalizes, and caches results in SQLite.
- Lightweight dark-themed single-page frontend.

## Quick Start

```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload
# open http://127.0.0.1:8000
```

## API

```
GET /api/v1/search?apex=baidu.com          # JSON
GET /api/v1/search?apex=baidu.com&format=text   # plain text (crt.name style)
GET /api/v1/search?apex=baidu.com&refresh=1     # bypass cache
GET /api/v1/health
```

## License

MIT
