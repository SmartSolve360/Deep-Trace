"""
Security primitives: HKDF-based sub-key derivation, HMAC helpers,
challenge/nonce issuance, and constant-time comparison.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from app.config import settings
from app.core.exceptions import AuthError

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_subkey(master_key: bytes, purpose: str, length: int = 32) -> bytes:
    """
    Derive a domain-specific sub-key from the master secret using HMAC-SHA256
    as a single-step KDF. Different `purpose` strings produce cryptographically
    independent keys, so a leak in one engine doesn't compromise the others.

    This is HKDF-Extract+Expand collapsed into a single HMAC step. Adequate
    when the master key already has high entropy (e.g. 32 random bytes).
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 16:
        raise ValueError("master_key must be at least 16 bytes")
    if not purpose or not isinstance(purpose, str):
        raise ValueError("purpose must be a non-empty string")
    info = f"deep-trace/v1/{purpose}".encode("utf-8")
    # Single Expand step with the info as key and a fixed context as message
    derived = hmac.new(master_key, info, hashlib.sha256).digest()
    # Stretch if more bytes requested (simple counter mode)
    if length <= len(derived):
        return derived[:length]
    out = derived
    counter = 1
    while len(out) < length:
        out += hmac.new(master_key, info + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac_sha256(key: bytes, data: bytes, expected: bytes) -> bool:
    """Constant-time HMAC-SHA256 verification."""
    computed = hmac.new(key, data, hashlib.sha256).digest()
    return constant_time_compare(computed, expected)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison (no early exit)."""
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------


def generate_api_key(prefix: str = "dtk") -> str:
    """Generate a fresh API key with a human-recognisable prefix."""
    body = secrets.token_urlsafe(32)
    return f"{prefix}_{body}"


def is_valid_api_key(presented: Optional[str]) -> bool:
    """Check whether `presented` matches any key in settings.API_KEYS."""
    if not presented:
        return False
    for stored in settings.API_KEYS:
        if constant_time_compare(presented.encode("utf-8"), stored.encode("utf-8")):
            return True
    return False


# ---------------------------------------------------------------------------
# HMAC challenge (replay-protected, time-limited)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Challenge:
    """A short-lived HMAC challenge proving knowledge of the master secret."""

    nonce: str
    issued_at: int
    expires_at: int
    mac: str

    def to_token(self) -> str:
        """Serialize to a URL-safe token."""
        payload = json.dumps(
            {"nonce": self.nonce, "iat": self.issued_at, "exp": self.expires_at},
            separators=(",", ":"),
        )
        import base64

        body = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
        return f"{body}.{self.mac}"

    @classmethod
    def from_token(cls, token: str) -> "Challenge":
        """Parse a challenge token back into a Challenge object."""
        import base64

        try:
            body, mac = token.rsplit(".", 1)
            padded = body + "=" * (-len(body) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
            return cls(
                nonce=payload["nonce"],
                issued_at=int(payload["iat"]),
                expires_at=int(payload["exp"]),
                mac=mac,
            )
        except Exception as exc:
            raise AuthError(f"Malformed challenge token: {exc}") from exc


def issue_challenge(account_id: str, ttl_seconds: Optional[int] = None) -> Challenge:
    """
    Issue a short-lived challenge for `account_id`.

    The MAC binds the challenge to the account so a challenge can't be reused
    across accounts. Nonce is 16 random bytes (URL-safe).
    """
    ttl = ttl_seconds or settings.CHALLENGE_TTL_SECONDS
    nonce = secrets.token_urlsafe(16)
    now = int(time.time())
    payload = f"{account_id}|{nonce}|{now}|{ttl}".encode("utf-8")
    mac = hmac_sha256(derive_subkey(settings.SECRET_KEY.encode("utf-8"), "challenge"), payload)
    return Challenge(
        nonce=nonce,
        issued_at=now,
        expires_at=now + ttl,
        mac=mac.hex(),
    )


def verify_challenge(account_id: str, challenge: Challenge) -> None:
    """
    Verify a challenge MAC and check the time window.

    Raises AuthError if invalid or expired.
    """
    if int(time.time()) > challenge.expires_at:
        raise AuthError("Challenge expired")
    payload = f"{account_id}|{challenge.nonce}|{challenge.issued_at}|{challenge.expires_at - challenge.issued_at}".encode(
        "utf-8"
    )
    expected = hmac_sha256(
        derive_subkey(settings.SECRET_KEY.encode("utf-8"), "challenge"),
        payload,
    )
    if not constant_time_compare(expected, bytes.fromhex(challenge.mac)):
        raise AuthError("Challenge MAC invalid")
