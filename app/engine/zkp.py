"""
Pedersen commitment — a zero-knowledge-friendly cryptographic commitment.

Properties:
- HIDING:  C = g^v * h^r mod p reveals nothing about v (computational)
- BINDING: infeasible to find (v, r) and (v', r') giving the same C
- HOMOMORPHIC: C(a+b) = C(a) * C(b) mod p (enables ZK range proofs later)

We use the IETF RFC 3526 2048-bit MODP group for `p` (well-vetted, widely
deployed in TLS/Diffie-Hellman). Generator `g = 2` has order q = (p-1)/2
since p is a safe prime.

The second generator `h` is the critical security parameter. We require
log_g(h) to be UNKNOWN for the binding property to hold. We construct
`h` by deriving a random-looking exponent `x` from the deployment's
server secret (via HKDF), then computing `h = g^x mod p`. As long as
the server secret is kept confidential, `log_g(h)` is computationally
infeasible to recover.

SECURITY REQUIREMENT
--------------------
`SECRET_KEY` (or the value passed to `PedersenCommitment(master_key=...)`)
must be a high-entropy random secret of at least 32 bytes that is never
exposed publicly. The default placeholder in `.env.example` is NOT
sufficient for production — rotate before deploying.

The 256-byte commitment is stored in the ledger alongside the opening
(v, r) so any reader can verify the commitment was honestly produced.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

from app.core.security import derive_subkey

# RFC 3526 2048-bit MODP Group (Group 14). p = 2q + 1, q prime.
_MODP_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_MODP_2048_Q = (_MODP_2048_P - 1) // 2
_MODP_2048_G = 2


def _derive_h(master_key: bytes) -> int:
    """
    Derive a second generator `h = g^x mod p` where x is HKDF-derived
    from the server secret. As long as `master_key` is confidential,
    `log_g(h)` is unknown to attackers.
    """
    # Domain-separated HKDF; 64 bytes of output gives ample entropy
    # even after the mod-q reduction.
    h_secret = derive_subkey(master_key, "pedersen/h/v1", 64)
    x = int.from_bytes(h_secret, "big") % _MODP_2048_Q
    if x == 0:
        x = 1
    h = pow(_MODP_2048_G, x, _MODP_2048_P)
    # If h is 1 (impossibly unlikely with mod-q reduction), retry with
    # a different derivation. The probability is < 1/2^2047.
    if h <= 1:
        return _derive_h(master_key + b"\x01")
    return h


# Cache the group parameters keyed by the master secret. If the same
# deployment uses the same SECRET_KEY, h is stable across restarts;
# a different secret yields a different h.
_GROUP_CACHE: dict[bytes, tuple[int, int, int]] = {}


def _get_group(master_key: bytes) -> tuple[int, int, int]:
    """Return (p, g, h) for the Pedersen group, deriving h if not cached."""
    cached = _GROUP_CACHE.get(master_key)
    if cached is None:
        h = _derive_h(master_key)
        _GROUP_CACHE[master_key] = (_MODP_2048_P, _MODP_2048_G, h)
    return _GROUP_CACHE[master_key]


@dataclass(frozen=True)
class PedersenParams:
    """Public parameters of the Pedersen commitment scheme."""

    p: int
    g: int
    h: int
    q: int  # prime order of g, h


class PedersenCommitment:
    """
    Pedersen commitment scheme.

    Commit to a value v in [0, q):
        C, opening = commit(v)        # opening = (v, r)
        verify(C, opening) -> bool

    For privacy-preserving mode, commit to hash(v) instead of v itself.

    `master_key` must be a confidential 32+ byte secret. The same secret
    must be used to verify a commitment later (otherwise h differs and
    verification fails). In production this is the deployment's
    SECRET_KEY.
    """

    def __init__(self, master_key: Optional[bytes] = None) -> None:
        if master_key is None:
            from app.config import settings
            master_key = settings.SECRET_KEY.encode("utf-8")
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 32:
            raise ValueError(
                "PedersenCommitment requires a confidential master_key of at least 32 bytes"
            )
        self._master_key = bytes(master_key)
        p, g, h = _get_group(self._master_key)
        self.params = PedersenParams(p=p, g=g, h=h, q=_MODP_2048_Q)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def commit(self, value: int, randomness: Optional[int] = None) -> tuple[int, tuple[int, int]]:
        """
        Commit to `value`. Returns (C, (v, r)) where (v, r) is the opening.

        If `randomness` is not provided, a cryptographically secure one
        is generated using secrets.randbelow.
        """
        if value < 0 or value >= self.params.q:
            raise ValueError(f"value must be in [0, q); got {value.bit_length()}-bit value")
        r = randomness if randomness is not None else secrets.randbelow(self.params.q)
        if r <= 0 or r >= self.params.q:
            raise ValueError("randomness must be in (0, q)")
        C = (pow(self.params.g, value, self.params.p) * pow(self.params.h, r, self.params.p)) % self.params.p
        return C, (value, r)

    def commit_hash(self, raw_value: bytes, randomness: Optional[int] = None) -> tuple[int, tuple[int, int]]:
        """
        Commit to SHA-256(raw_value) mod q. Useful when `raw_value` is
        an account_id or other identifier you'd rather not store in
        plaintext while still being able to prove membership later.
        """
        h = int.from_bytes(hashlib.sha256(raw_value).digest(), "big") % self.params.q
        return self.commit(h, randomness)

    def verify(self, C: int, opening: tuple[int, int]) -> bool:
        """Verify that C is a valid commitment to (value, randomness)."""
        v, r = opening
        if v < 0 or v >= self.params.q:
            return False
        if r <= 0 or r >= self.params.q:
            return False
        C2 = (pow(self.params.g, v, self.params.p) * pow(self.params.h, r, self.params.p)) % self.params.p
        return C2 == C

    @staticmethod
    def to_hex(c: int) -> str:
        """Serialize a commitment to a fixed-width hex string (256 bytes)."""
        return format(c, "x")

    @staticmethod
    def from_hex(s: str) -> int:
        """Inverse of `to_hex`."""
        return int(s, 16)
