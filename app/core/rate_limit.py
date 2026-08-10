"""
Rate limiting via slowapi.

Per-route limits (configurable via env, read at every request so tests
can override them on the fly):
    - public asset metadata/download:  60 req/min per IP
    - watermark embed (compute-heavy):  10 req/min per IP
    - all other authenticated routes:  600 req/min per API key

In tests / dev, override with high values via env:
    RATE_LIMIT_PUBLIC=10000/minute
    RATE_LIMIT_EMBED=10000/minute
    RATE_LIMIT_AUTHED=10000/minute
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address


def _default_key(request) -> str:  # type: ignore[no-untyped-def]
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"key:{api_key}"
    return f"ip:{get_remote_address(request)}"


# Read defaults at module import; individual `*_limit()` functions
# re-read env on every call so tests can override them dynamically.
_DEFAULT_PUBLIC = "60/minute"
_DEFAULT_EMBED = "10/minute"
_DEFAULT_AUTHED = "600/minute"


limiter = Limiter(
    key_func=_default_key,
    storage_uri="memory://",  # in-process; fine for single-instance Render
    headers_enabled=True,      # adds X-RateLimit-* response headers
)


def public_limit() -> str:
    """60 req/min/IP by default; override via RATE_LIMIT_PUBLIC env var."""
    return os.getenv("RATE_LIMIT_PUBLIC", _DEFAULT_PUBLIC)


def embed_limit() -> str:
    """10 req/min/IP by default; override via RATE_LIMIT_EMBED env var."""
    return os.getenv("RATE_LIMIT_EMBED", _DEFAULT_EMBED)


def authed_limit() -> str:
    """600 req/min/key by default; override via RATE_LIMIT_AUTHED env var."""
    return os.getenv("RATE_LIMIT_AUTHED", _DEFAULT_AUTHED)
