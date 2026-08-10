"""
Reed-Solomon error correction wrapper.

We use the `reedsolo` library which provides RSCodec over GF(2^8).
For 128-bit payloads (16 bytes), we add 32 parity bytes (RS(48, 16))
which corrects up to 16 byte errors — well above what we'd expect from
JPEG recompression, mild filtering, or resize.
"""

from __future__ import annotations

from typing import Tuple

import reedsolo


class ReedSolomonCodec:
    """Thin wrapper around reedsolo with explicit symbol/ECC sizing."""

    def __init__(self, data_bytes: int = 16, ecc_bytes: int = 32) -> None:
        if data_bytes + ecc_bytes > 255:
            raise ValueError("Reed-Solomon total length must be <= 255 bytes")
        self.data_bytes = data_bytes
        self.ecc_bytes = ecc_bytes
        self._codec = reedsolo.RSCodec(ecc_bytes)

    def encode(self, payload: bytes) -> bytes:
        """Encode payload. Returns data + parity (data_bytes + ecc_bytes)."""
        if len(payload) != self.data_bytes:
            raise ValueError(
                f"payload must be exactly {self.data_bytes} bytes, got {len(payload)}"
            )
        encoded = self._codec.encode(payload)
        return bytes(encoded)

    def decode(self, codeword: bytes) -> Tuple[bytes, int]:
        """
        Decode and correct errors. Returns (decoded_payload, num_errors_corrected).

        Raises reedsolo.ReedSolomonError if errors exceed correction capacity.
        """
        if len(codeword) != self.data_bytes + self.ecc_bytes:
            raise ValueError(
                f"codeword must be {self.data_bytes + self.ecc_bytes} bytes, "
                f"got {len(codeword)}"
            )
        decoded, _, errata_pos = self._codec.decode(codeword)
        n_errors = len(errata_pos) if errata_pos else 0
        return bytes(decoded), n_errors

    @property
    def codeword_size(self) -> int:
        return self.data_bytes + self.ecc_bytes

    @property
    def bit_capacity(self) -> int:
        return self.codeword_size * 8
