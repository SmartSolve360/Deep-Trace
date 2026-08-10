"""
Encoding helpers — hex, base64url, and timestamp utilities.
"""

from __future__ import annotations

import base64
import binascii
import time
from datetime import datetime, timezone
from typing import Union


def hex_to_bytes(value: str) -> bytes:
    """Parse a hex string. Strips whitespace and 0x prefix."""
    s = value.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    try:
        return bytes.fromhex(s)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid hex string: {exc}") from exc


def bytes_to_hex(value: bytes) -> str:
    """Lowercase hex without prefix."""
    return value.hex()


def b64url_encode(value: Union[bytes, str]) -> str:
    """URL-safe base64 (no padding)."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    """Inverse of `b64url_encode`."""
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("ascii"))


def now_ts() -> float:
    """Current Unix timestamp (seconds, float)."""
    return time.time()


def now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def ts_to_iso(ts: float) -> str:
    """Convert Unix timestamp to ISO-8601 UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
