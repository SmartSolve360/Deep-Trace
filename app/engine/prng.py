"""
Keyed pseudo-random number generator (HMAC-DRBG).

NIST SP 800-90A HMAC_DRBG — a deterministic, seedable PRNG whose output
depends on both the master key and the per-call entropy. Used to derive
block permutations, ECC interleaving, and other keyed randomisation in
the watermark engine.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Iterator

from app.core.security import derive_subkey


class KeyedPRNG:
    """
    HMAC-DRBG with a 32-byte security strength.

    State is `(key, value)`. Each call advances the state and yields
    a deterministic byte stream. Different `domain` strings produce
    independent streams from the same master secret.
    """

    def __init__(self, master_key: bytes, domain: str, seed: bytes = b"") -> None:
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 16:
            raise ValueError("master_key must be at least 16 bytes")
        self._key = derive_subkey(master_key, f"prng/{domain}", 32)
        self._value = b"\x01" * 32
        if seed:
            self._update(seed)

    # ------------------------------------------------------------------
    # Internal update (NIST SP 800-90A HMAC_DRBG_Update)
    # ------------------------------------------------------------------

    def _update(self, provided_data: bytes = b"") -> None:
        """One DRBG update step."""
        temp = b""
        while len(temp) < 32:
            self._value = hmac.new(self._key, self._value, hashlib.sha256).digest()
            temp += self._value
        self._key = hmac.new(self._key, temp + b"\x00" + provided_data, hashlib.sha256).digest()
        self._value = hmac.new(self._key, self._value, hashlib.sha256).digest()
        if provided_data:
            temp2 = b""
            while len(temp2) < 32:
                self._value = hmac.new(self._key, self._value, hashlib.sha256).digest()
                temp2 += self._value
            self._key = hmac.new(self._key, temp2 + b"\x01" + provided_data, hashlib.sha256).digest()
            self._value = hmac.new(self._key, self._value, hashlib.sha256).digest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, n: int) -> bytes:
        """Generate `n` random bytes, updating the DRBG state."""
        if n < 0:
            raise ValueError("n must be non-negative")
        out = b""
        while len(out) < n:
            self._value = hmac.new(self._key, self._value, hashlib.sha256).digest()
            out += self._value
        out = out[:n]
        self._update()
        return out

    def randint(self, low: int, high: int) -> int:
        """Uniform integer in [low, high] inclusive."""
        if low > high:
            raise ValueError("low > high")
        span = high - low + 1
        # 8-byte windows are overkill for non-adversarial use
        nbytes = (span.bit_length() + 7) // 8 + 1
        while True:
            r = int.from_bytes(self.generate(nbytes), "big")
            r %= span
            if r < span:
                return low + r

    def permutation(self, n: int) -> list[int]:
        """Return a uniformly random permutation of range(n) (Fisher-Yates)."""
        arr = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.randint(0, i)
            arr[i], arr[j] = arr[j], arr[i]
        return arr

    def stream(self) -> Iterator[int]:
        """Infinite iterator of random bytes (0-255)."""
        while True:
            for b in self.generate(64):
                yield b
