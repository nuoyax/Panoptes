"""Central configuration for the subdomain query service."""

import re
from pathlib import Path

# Project root (backend/..)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "cache.db"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Upstream HTTP settings
UPSTREAM_TIMEOUT = 120.0  # seconds per CT source (crt.sh can be slow)
USER_AGENT = "Panoptes/1.0 (+self-hosted subdomain query)"
SOURCE_HTTP_MAX_BYTES = 64 * 1024 * 1024  # guard against a runaway upstream body
WAYBACK_TIMEOUT = 120.0  # CDX is the slowest upstream

# Outbound HTTP: TLS verification for probing targets that often have broken certs
HTTP_VERIFY_TLS = False
HTTP_PROBE_TIMEOUT = 8.0

# crt.sh query tuning: excluding expired certs is 10-20x faster upstream
CRTSH_EXCLUDE_EXPIRED = True

# Cache settings
CACHE_TTL_SECONDS = 24 * 3600  # 24h
TTL_SUBDOMAIN = CACHE_TTL_SECONDS

# Per-stage enrichment TTLs (seconds) — each stage goes stale independently
TTL_DNS = 6 * 3600
TTL_HTTP = 6 * 3600
TTL_PORTS = 24 * 3600
TTL_SECURITY = 24 * 3600

# Background scan jobs
JOB_MAX_CONCURRENT = 2  # scan jobs running at once
JOB_TTL_SECONDS = 3600  # finished jobs retained this long
JOB_MAX_SECONDS = 900  # wall-clock budget per job
JOB_CANCEL_GRACE_SECONDS = 5.0
JOB_PRUNE_INTERVAL_SECONDS = 3600
ENRICHMENT_RETENTION_DAYS = 30

# Limits
MAX_RESULTS = 100_000
MAX_HTTP_HOSTS = 3000  # hosts fed to http_probe (8s timeout at concurrency 100)
MAX_SCAN_HOSTS = 1000  # hosts fed to port_scan / recon (38 ports x N hosts is not cheap)
MAX_DNS_HOSTS = 20_000  # hosts fed to dns_verify

# Apex domain validation: labels of letters/digits/hyphen, at least one dot.
# NOTE: always match with .fullmatch() — re.match() with a trailing "$"
# accepts "example.com\n", which is a validation bypass.
APEX_RE = r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
APEX_PATTERN = re.compile(APEX_RE)
