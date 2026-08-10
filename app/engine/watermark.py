"""
DEEP-TRACE watermark engine — DCT-QIM with Reed-Solomon error correction.

Scheme overview
---------------

Payload (128 bits):
    payload = HMAC-SHA256(subkey_payload, account_id | ts | device_sig)[:16]

Error correction (256 parity bits, RS(48, 16)):
    codeword = reed_solomon_encode(payload)   # 16 data + 32 parity = 48 bytes

Per-block embedding (4 bits per 8x8 block):
    For each 8x8 DCT block of the Y channel:
        Pick 4 mid-band coefficients: (2,1), (1,2), (2,2), (3,1)
        For each coefficient, apply Quantization Index Modulation:
            q  = round(coef / delta)
            if bit == 1: target = q if q is odd, else q+1
            if bit == 0: target = q if q is even, else q+1
            coef = target * delta

Adaptive delta:
    delta_adapt = base_delta * (1 + block_energy / 100)
    Boosts QIM strength in textured regions, preserves imperceptibility
    in smooth regions. Gives a meaningful edge against JPEG recompression.

Extraction (no original needed):
    Read the same coefficients, compute q = round(coef / delta_adapt),
    bit = q mod 2. Pack to bytes, RS-decode, verify.

Robustness
----------
- Reed-Solomon corrects up to 16 byte errors in the 48-byte codeword.
- Adaptive delta helps against amplitude scaling (brightness/contrast).
- Mid-band coefficients survive JPEG @ Q>=70 and mild filtering.
- Imperceptibility: PSNR typically >= 38 dB for natural images.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import cv2
import numpy as np

from app.config import settings
from app.core.exceptions import InsufficientCapacityError, PayloadMismatchError
from app.core.security import derive_subkey
from app.engine.ecc import ReedSolomonCodec


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Mid-band DCT coefficient positions (skipping DC and very low frequencies
# which carry the bulk of the image energy and would be most visible to alter).
DEFAULT_DATA_COEFS: tuple[tuple[int, int], ...] = (
    (2, 1),
    (1, 2),
    (2, 2),
    (3, 1),
)

# Sync/calibration coefficient (one per block). We embed a fixed
# pseudo-random pattern in the first N sync blocks to let the extractor
# estimate the channel gain and recompute the QIM delta more accurately.
SYNC_COEF: tuple[int, int] = (4, 1)
SYNC_BLOCKS: int = 4
SYNC_PATTERN_BIT: int = 1  # always embed a '1' at the sync coefficient


@dataclass(frozen=True)
class WatermarkResult:
    """Return value of `embed_watermark`."""

    watermarked_bgr: np.ndarray
    payload_hex: str
    psnr_db: float
    capacity_blocks: int
    used_blocks: int


class DCTQIMWatermark:
    """
    DCT-QIM watermarking engine.

    Independent instances are safe to use from multiple threads; per-call
    state is limited to numpy arrays which we don't share.
    """

    BLOCK_SIZE: int = 8
    PAYLOAD_BYTES: int = 16
    ECC_BYTES: int = 32
    CODEWORD_BYTES: int = 48
    BITS_PER_BLOCK: int = len(DEFAULT_DATA_COEFS)
    MIN_BLOCKS_NEEDED: int = (PAYLOAD_BYTES + ECC_BYTES) * 8 // BITS_PER_BLOCK  # 96

    DATA_COEFS: tuple[tuple[int, int], ...] = DEFAULT_DATA_COEFS

    def __init__(
        self,
        secret_key: bytes,
        qim_delta: Optional[float] = None,
    ) -> None:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes")
        self.secret_key = bytes(secret_key)
        self.qim_delta = float(qim_delta or settings.WATERMARK_QIM_DELTA)
        self.ecc = ReedSolomonCodec(self.PAYLOAD_BYTES, self.ECC_BYTES)

        # Domain-separated sub-keys
        self._payload_key = derive_subkey(self.secret_key, "watermark/payload/v1", 32)
        self._sync_key = derive_subkey(self.secret_key, "watermark/sync/v1", 32)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_payload(self, account_id: str, timestamp: float, device_sig: str) -> bytes:
        """
        Generate the 128-bit provenance payload.

        `timestamp` should be a Unix timestamp (float, seconds). Float
        precision is normalised to microseconds so embed/extract pairs
        can verify timestamps deterministically.
        """
        ts_us = int(round(float(timestamp) * 1_000_000))
        msg = f"{account_id}|{ts_us}|{device_sig}".encode("utf-8")
        return hmac.new(self._payload_key, msg, hashlib.sha256).digest()[: self.PAYLOAD_BYTES]

    def embed_watermark(
        self,
        image_bgr: np.ndarray,
        account_id: str,
        timestamp: Optional[float] = None,
        device_sig: str = "unknown",
    ) -> WatermarkResult:
        """
        Embed a 128-bit provenance payload in `image_bgr`.

        Returns a WatermarkResult containing the watermarked image (uint8 BGR),
        the payload hex, embedding PSNR, and capacity info.
        """
        if image_bgr is None or image_bgr.ndim != 3 or image_bgr.shape[2] != 3:
            raise ValueError("image_bgr must be a HxWx3 uint8 array")
        if image_bgr.dtype != np.uint8:
            image_bgr = image_bgr.astype(np.uint8)

        h, w = image_bgr.shape[:2]
        self._check_capacity(h, w)

        if timestamp is None:
            timestamp = time.time()

        # 1. Generate payload + RS encode
        payload = self.generate_payload(account_id, timestamp, device_sig)
        codeword = self.ecc.encode(payload)
        bits = self._bytes_to_bits(codeword)  # length CODEWORD_BYTES*8 = 384

        # 2. Convert to YCbCr — embed only in luminance (Y)
        ycrcb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float32)
        Y = ycrcb[:, :, 0].copy()

        # 3. Walk blocks in raster order; first SYNC_BLOCKS are calibration
        blocks_needed = self.CODEWORD_BYTES * 8 // self.BITS_PER_BLOCK  # 96
        block_h, block_w = h // self.BLOCK_SIZE, w // self.BLOCK_SIZE
        total_blocks = block_h * block_w
        if total_blocks < blocks_needed + SYNC_BLOCKS:
            raise InsufficientCapacityError(
                "Image too small for sync + payload",
                details={
                    "blocks_needed": blocks_needed + SYNC_BLOCKS,
                    "blocks_available": total_blocks,
                },
            )

        # Embed sync pattern in the first SYNC_BLOCKS blocks
        for r in range(SYNC_BLOCKS):
            br, bc = divmod(r, block_w)
            y0, x0 = br * self.BLOCK_SIZE, bc * self.BLOCK_SIZE
            self._embed_sync_coefficient(Y, y0, x0)

        # Embed data bits in the next blocks_needed blocks
        bit_idx = 0
        block_idx = SYNC_BLOCKS
        while bit_idx < len(bits) and block_idx < total_blocks:
            br, bc = divmod(block_idx, block_w)
            y0, x0 = br * self.BLOCK_SIZE, bc * self.BLOCK_SIZE

            block = Y[y0 : y0 + self.BLOCK_SIZE, x0 : x0 + self.BLOCK_SIZE]
            dct_block = cv2.dct(block)
            energy = self._block_energy(dct_block)
            adaptive_delta = self._adaptive_delta(energy)

            chunk = bits[bit_idx : bit_idx + self.BITS_PER_BLOCK]
            for k, (i, j) in enumerate(self.DATA_COEFS):
                dct_block[i, j] = self._qim_embed(dct_block[i, j], int(chunk[k]), adaptive_delta)

            Y[y0 : y0 + self.BLOCK_SIZE, x0 : x0 + self.BLOCK_SIZE] = cv2.idct(dct_block)
            bit_idx += self.BITS_PER_BLOCK
            block_idx += 1

        # 4. Reconstruct, clip, compute PSNR
        Y = np.clip(Y, 0, 255)
        ycrcb[:, :, 0] = Y
        result_bgr = cv2.cvtColor(ycrcb.astype(np.uint8), cv2.COLOR_YCrCb2BGR)
        psnr = self._psnr(image_bgr, result_bgr)

        return WatermarkResult(
            watermarked_bgr=result_bgr,
            payload_hex=payload.hex(),
            psnr_db=psnr,
            capacity_blocks=total_blocks,
            used_blocks=SYNC_BLOCKS + blocks_needed,
        )

    def extract_watermark(self, image_bgr: np.ndarray) -> Tuple[str, str, int]:
        """
        Extract a 128-bit payload from `image_bgr`.

        Returns (payload_hex, status, errors_corrected):
            - payload_hex: 32-char hex string on success, "" on failure
            - status: "OK" | "DECODE_FAILED:<reason>"
            - errors_corrected: integer number of byte errors RS corrected
        """
        if image_bgr is None or image_bgr.ndim != 3 or image_bgr.shape[2] != 3:
            raise ValueError("image_bgr must be a HxWx3 uint8 array")
        if image_bgr.dtype != np.uint8:
            image_bgr = image_bgr.astype(np.uint8)

        h, w = image_bgr.shape[:2]
        block_h, block_w = h // self.BLOCK_SIZE, w // self.BLOCK_SIZE
        total_blocks = block_h * block_w
        blocks_needed = self.CODEWORD_BYTES * 8 // self.BITS_PER_BLOCK

        if total_blocks < blocks_needed + SYNC_BLOCKS:
            raise InsufficientCapacityError(
                "Image too small to contain DEEP-TRACE payload",
                details={"blocks_needed": blocks_needed + SYNC_BLOCKS, "blocks_available": total_blocks},
            )

        ycrcb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2YCrCb).astype(np.float32)
        Y = ycrcb[:, :, 0]

        # Read sync blocks, estimate channel gain
        sync_values: list[float] = []
        for r in range(SYNC_BLOCKS):
            br, bc = divmod(r, block_w)
            y0, x0 = br * self.BLOCK_SIZE, bc * self.BLOCK_SIZE
            block = Y[y0 : y0 + self.BLOCK_SIZE, x0 : x0 + self.BLOCK_SIZE]
            dct_block = cv2.dct(block)
            i, j = SYNC_COEF
            sync_values.append(float(dct_block[i, j]))
        # The sync pattern is a known QIM-encoded '1'. The expected
        # output value (mod delta) is odd * delta. We use the residual
        # to compute a global amplitude correction factor.
        gain_correction = self._estimate_gain(sync_values)

        # Read data blocks
        bits: list[int] = []
        block_idx = SYNC_BLOCKS
        while len(bits) < self.CODEWORD_BYTES * 8 and block_idx < total_blocks:
            br, bc = divmod(block_idx, block_w)
            y0, x0 = br * self.BLOCK_SIZE, bc * self.BLOCK_SIZE
            block = Y[y0 : y0 + self.BLOCK_SIZE, x0 : x0 + self.BLOCK_SIZE]
            dct_block = cv2.dct(block)
            energy = self._block_energy(dct_block)
            adaptive_delta = self._adaptive_delta(energy) * gain_correction

            for (i, j) in self.DATA_COEFS:
                bits.append(self._qim_extract(dct_block[i, j], adaptive_delta))
            block_idx += 1

        # Pack bits → bytes
        if len(bits) < self.CODEWORD_BYTES * 8:
            return "", "DECODE_FAILED:insufficient_bits", 0
        codeword = self._bits_to_bytes(bits[: self.CODEWORD_BYTES * 8])

        # RS decode
        try:
            payload, n_errors = self.ecc.decode(codeword)
            return payload.hex(), f"OK (corrected {n_errors} byte errors)", n_errors
        except Exception as exc:
            return "", f"DECODE_FAILED:{type(exc).__name__}", 0

    def verify_payload(
        self,
        image_bgr: np.ndarray,
        expected_payload_hex: str,
    ) -> Tuple[bool, str]:
        """Extract and compare against a known payload."""
        extracted_hex, status, _ = self.extract_watermark(image_bgr)
        if not extracted_hex:
            return False, f"extraction failed: {status}"
        if extracted_hex.lower() != expected_payload_hex.lower():
            raise PayloadMismatchError(
                "Extracted payload does not match expected",
                details={"expected": expected_payload_hex, "extracted": extracted_hex},
            )
        return True, status

    # ------------------------------------------------------------------
    # Internal: capacity / QIM / sync
    # ------------------------------------------------------------------

    def _check_capacity(self, h: int, w: int) -> None:
        block_h, block_w = h // self.BLOCK_SIZE, w // self.BLOCK_SIZE
        total_blocks = block_h * block_w
        if total_blocks < self.MIN_BLOCKS_NEEDED + SYNC_BLOCKS:
            raise InsufficientCapacityError(
                f"Image too small: need {self.MIN_BLOCKS_NEEDED + SYNC_BLOCKS} blocks, have {total_blocks}",
                details={
                    "blocks_needed": self.MIN_BLOCKS_NEEDED + SYNC_BLOCKS,
                    "blocks_available": total_blocks,
                },
            )

    def _block_energy(self, dct_block: np.ndarray) -> float:
        """Average magnitude of AC coefficients — proxy for texture density."""
        ac = dct_block.copy()
        ac[0, 0] = 0.0
        return float(np.sum(np.abs(ac))) / 63.0  # 64 - 1 (DC)

    def _adaptive_delta(self, energy: float) -> float:
        """Scale QIM delta by local block energy."""
        return self.qim_delta * (1.0 + energy / 100.0)

    def _qim_embed(self, value: float, bit: int, delta: float) -> float:
        """Embed `bit` into `value` using even/odd QIM parity."""
        q = int(round(value / delta))
        if bit == 1 and q % 2 == 0:
            q += 1
        elif bit == 0 and q % 2 != 0:
            q += 1
        return float(q * delta)

    def _qim_extract(self, value: float, delta: float) -> int:
        """Recover the embedded bit from `value`."""
        q = int(round(value / delta))
        return q % 2

    def _embed_sync_coefficient(self, Y: np.ndarray, y0: int, x0: int) -> None:
        """Embed a fixed '1' in the SYNC_COEF of a block."""
        block = Y[y0 : y0 + self.BLOCK_SIZE, x0 : x0 + self.BLOCK_SIZE]
        dct_block = cv2.dct(block)
        i, j = SYNC_COEF
        dct_block[i, j] = self._qim_embed(dct_block[i, j], SYNC_PATTERN_BIT, self.qim_delta)
        Y[y0 : y0 + self.BLOCK_SIZE, x0 : x0 + self.BLOCK_SIZE] = cv2.idct(dct_block)

    def _estimate_gain(self, sync_values: list[float]) -> float:
        """
        Estimate a global amplitude scaling factor from the sync pattern.

        If the sync coefficient was embedded as `1` (odd multiple of delta)
        and we observe `sync_observed`, the implicit gain is:
            gain = sync_observed / expected
        where `expected` is the median odd multiple of delta near zero.
        We use a robust estimate: divide each observed value by the
        nearest odd multiple of delta.
        """
        if not sync_values:
            return 1.0
        ratios: list[float] = []
        for v in sync_values:
            if abs(v) < 1e-6:
                continue
            q = round(v / self.qim_delta)
            # Snap to nearest odd
            if q % 2 == 0:
                q_adj = q + (1 if v > 0 else -1)
            else:
                q_adj = q
            expected = q_adj * self.qim_delta
            if abs(expected) > 1e-6:
                ratios.append(v / expected)
        if not ratios:
            return 1.0
        # Median is robust to outliers
        return float(np.median(ratios))

    # ------------------------------------------------------------------
    # Bit ↔ byte conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _bytes_to_bits(data: bytes) -> np.ndarray:
        return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        arr = np.array(bits, dtype=np.uint8)
        if arr.size % 8 != 0:
            arr = np.concatenate([arr, np.zeros(8 - arr.size % 8, dtype=np.uint8)])
        return np.packbits(arr).tobytes()

    @staticmethod
    def _psnr(a: np.ndarray, b: np.ndarray) -> float:
        """PSNR between two uint8 images of identical shape."""
        a = a.astype(np.float64)
        b = b.astype(np.float64)
        mse = float(np.mean((a - b) ** 2))
        if mse <= 1e-12:
            return 99.0
        return float(20.0 * np.log10(255.0 / np.sqrt(mse)))
