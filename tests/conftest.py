"""
Pytest configuration: ensure the project root is on sys.path so `import app.*`
works regardless of where pytest is invoked from.
"""

from __future__ import annotations

import os
import sys

import pytest

# Add the project root (one level up from this tests/ dir) to sys.path
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Set test-wide env vars HERE so they exist before any test file is
# imported. Each test file imports the app (which reads env via
# pydantic-settings at module load), so we need the env set first.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "conftest_test_secret_32_bytes_min!!")
os.environ.setdefault(
    "API_KEYS",
    # One key per test "context" so the per-key rate limit is separate
    "test_api_key_integration,test_api_key_ledger,test_api_key_public,"
    "test_api_key_fuzzy,test_api_key_search,test_api_key_public_asset,"
    "test_api_key_rate_limit",
)
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("WATERMARK_MIN_IMAGE_SIZE", "64")
# Generous rate limits so the 50+ test calls don't hit the 10/minute cap
os.environ.setdefault("RATE_LIMIT_EMBED", "10000/minute")
os.environ.setdefault("RATE_LIMIT_PUBLIC", "10000/minute")
os.environ.setdefault("RATE_LIMIT_AUTHED", "10000/minute")


@pytest.fixture(autouse=True)
def _reset_state_between_tests():
    """Reset slowapi's in-memory rate-limit store + settings cache between
    tests so cross-test pollution doesn't cause flaky failures."""
    # Reset rate-limit storage
    try:
        from app.core.rate_limit import limiter
        if hasattr(limiter, "_storage") and hasattr(limiter._storage, "reset"):
            limiter._storage.reset()
    except Exception:
        pass
    # Clear the settings lru_cache so the next test reads fresh env vars
    try:
        from app.config import get_settings
        get_settings.cache_clear()
    except Exception:
        pass
    yield
    try:
        from app.core.rate_limit import limiter
        if hasattr(limiter, "_storage") and hasattr(limiter._storage, "reset"):
            limiter._storage.reset()
    except Exception:
        pass
