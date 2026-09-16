"""Central configuration for the subdomain query service."""

import os
from pathlib import Path

# Project root (backend/..)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "cache.db"

# Upstream HTTP settings
UPSTREAM_TIMEOUT = 30.0  # seconds per CT source
USER_AGENT = "subdomain-query/1.0 (+self-hosted CT aggregator)"

# Cache settings
CACHE_TTL_SECONDS = 24 * 3600  # 24h

# Limits
MAX_RESULTS = 100_000

# Apex domain validation: labels of letters/digits/hyphen, at least one dot
APEX_RE = r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
