"""
Perceptual image hashing.

We compute four complementary hashes for robust content matching:

- pHash : DCT-based, robust to scaling, minor colour shifts
- dHash : gradient-based, fast, good for cropping/duplication
- aHash : average hash, very fast, good baseline
- wHash : wavelet-based, most robust to small geometric changes

Implementation:
- Pure-Python fallback (always available) using only numpy + Pillow.
- Optional `imagehash` library if installed; provides a battle-tested
  implementation. We prefer it when present.
- `wHash` falls back to a simple Haar-wavelet approximation if PyWavelets
  is not available.

All four are stored in the provenance ledger and indexed so a forensic
search can match a suspect image against registered assets even after
modest editing.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import numpy as np
from PIL import Image


# ---------------------------------------------------------------------------
# Optional: prefer the `imagehash` library if installed
# ---------------------------------------------------------------------------

try:
    import imagehash  # type: ignore

    _IMAGEHASH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _IMAGEHASH_AVAILABLE = False


try:
    import pywt  # type: ignore  # noqa: F401

    _PYWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYWT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PerceptualHashes:
    """Container for the four perceptual hashes (each 64-bit, hex-encoded)."""

    phash: str
    dhash: str
    ahash: str
    whash: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "phash": self.phash,
            "dhash": self.dhash,
            "ahash": self.ahash,
            "whash": self.whash,
        }

    def hamming_distance(self, other: "PerceptualHashes") -> Dict[str, int]:
        """Per-hash Hamming distance vs. another PerceptualHashes."""
        return {
            "phash": _hex_hamming(self.phash, other.phash),
            "dhash": _hex_hamming(self.dhash, other.dhash),
            "ahash": _hex_hamming(self.ahash, other.ahash),
            "whash": _hex_hamming(self.whash, other.whash),
        }


def _hex_hamming(a: str, b: str) -> int:
    """Hamming distance between two hex-encoded 64-bit hashes."""
    if len(a) != len(b):
        return max(len(a), len(b)) * 4
    ba = bytes.fromhex(a)
    bb = bytes.fromhex(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(ba, bb))


# ---------------------------------------------------------------------------
# Pure-Python hash implementations (numpy + Pillow only)
# ---------------------------------------------------------------------------


def _bits_to_hex(bits: np.ndarray) -> str:
    """Pack a 64-bit array into a 16-char hex string."""
    if bits.size != 64:
        bits = bits.flatten()[:64]
    byte_arr = np.packbits(bits.astype(np.uint8))
    return byte_arr.tobytes().hex()


def _ahash_impl(img_gray: np.ndarray) -> str:
    """Average hash: 8x8 downsample, compare to mean."""
    pil = Image.fromarray(img_gray).resize((8, 8), Image.Resampling.LANCZOS)
    arr = np.asarray(pil, dtype=np.float32)
    mean = arr.mean()
    bits = (arr > mean).flatten()
    return _bits_to_hex(bits)


def _dhash_impl(img_gray: np.ndarray) -> str:
    """Difference hash: 9x8 downsample, compare adjacent pixels."""
    pil = Image.fromarray(img_gray).resize((9, 8), Image.Resampling.LANCZOS)
    arr = np.asarray(pil, dtype=np.float32)
    bits = arr[:, 1:] > arr[:, :-1]
    return _bits_to_hex(bits.flatten())


def _phash_impl(img_gray: np.ndarray) -> str:
    """DCT-based perceptual hash: 32x32 → DCT → top-left 8x8 (low-freq) → threshold."""
    pil = Image.fromarray(img_gray).resize((32, 32), Image.Resampling.LANCZOS)
    arr = np.asarray(pil, dtype=np.float32)
    # 2D DCT via separable 1D DCTs
    dct = _dct2d(arr)
    # Take the 8x8 low-frequency block (excluding DC at [0,0])
    low = dct[:8, :8]
    # Threshold against the median (excluding DC for robustness)
    med = np.median(low[1:, 1:]) if low.size > 1 else 0.0
    bits = (low > med).flatten()
    return _bits_to_hex(bits)


def _dct2d(arr: np.ndarray) -> np.ndarray:
    """Plain 2D DCT-II, O(N^4) — fine for 32x32 inputs."""
    n = arr.shape[0]
    basis = np.zeros((n, n), dtype=np.float32)
    for k in range(n):
        for i in range(n):
            basis[k, i] = np.cos(np.pi * k * (2 * i + 1) / (2 * n))
    # Normalise to make it orthonormal (matches OpenCV's behaviour closely enough)
    norm = np.ones(n, dtype=np.float32) * np.sqrt(2.0 / n)
    norm[0] = np.sqrt(1.0 / n)
    basis = basis * norm[:, None]
    return basis @ arr @ basis.T


def _whash_impl(img_gray: np.ndarray) -> str:
    """Wavelet hash using Haar wavelet (or a simple approximation if pywt missing)."""
    pil = Image.fromarray(img_gray).resize((32, 32), Image.Resampling.LANCZOS)
    arr = np.asarray(pil, dtype=np.float32)
    if _PYWT_AVAILABLE:
        coeffs = pywt.dwt2(arr, "haar")  # type: ignore[name-defined]
        cA, _ = coeffs
        # Use the approximation coefficients at half resolution
        arr2 = cA[:8, :8]
    else:
        # Simple 2x2 Haar approximation: average over 4x4 blocks → 8x8
        arr2 = arr.reshape(8, 4, 8, 4).mean(axis=(1, 3))
    med = np.median(arr2)
    bits = (arr2 > med).flatten()
    return _bits_to_hex(bits)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _imagehash_compat(img_pil: Image.Image) -> Optional[PerceptualHashes]:
    """Use imagehash library if available."""
    if not _IMAGEHASH_AVAILABLE:
        return None
    try:
        return PerceptualHashes(
            phash=str(imagehash.phash(img_pil)),  # type: ignore[name-defined]
            dhash=str(imagehash.dhash(img_pil)),  # type: ignore[name-defined]
            ahash=str(imagehash.average_hash(img_pil)),  # type: ignore[name-defined]
            whash=str(imagehash.whash(img_pil)),  # type: ignore[name-defined]
        )
    except Exception:  # pragma: no cover
        return None


def _pure_python_hashes(img_gray: np.ndarray) -> PerceptualHashes:
    """Compute all four hashes using only numpy + Pillow."""
    return PerceptualHashes(
        phash=_phash_impl(img_gray),
        dhash=_dhash_impl(img_gray),
        ahash=_ahash_impl(img_gray),
        whash=_whash_impl(img_gray),
    )


class PerceptualHasher:
    """Stateless perceptual hashing utility.

    Prefers the `imagehash` library when available; falls back to a
    pure-Python implementation using numpy + Pillow.
    """

    @staticmethod
    def _prepare(image_bytes: bytes) -> Tuple[Image.Image, np.ndarray]:
        """Decode bytes to a PIL Image (RGB) and a grayscale numpy array."""
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != "RGB":
            img = img.convert("RGB")
        gray = np.asarray(img.convert("L"))
        return img, gray

    @staticmethod
    def compute_hashes(image_bytes: bytes) -> PerceptualHashes:
        """Compute all four perceptual hashes from raw image bytes."""
        img_pil, img_gray = PerceptualHasher._prepare(image_bytes)
        if _IMAGEHASH_AVAILABLE:
            result = _imagehash_compat(img_pil)
            if result is not None:
                return result
        return _pure_python_hashes(img_gray)

    @staticmethod
    def compute_hashes_from_array(image_bgr) -> PerceptualHashes:
        """Compute hashes from an OpenCV BGR ndarray (no PNG roundtrip)."""
        import cv2

        rgb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(rgb)
        gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY)
        if _IMAGEHASH_AVAILABLE:
            result = _imagehash_compat(pil_img)
            if result is not None:
                return result
        return _pure_python_hashes(gray)

    @staticmethod
    def nearest_match(
        query_hashes: PerceptualHashes,
        candidates: list[PerceptualHashes],
        threshold: int = 10,
    ) -> Tuple[Optional[int], int]:
        """Find the candidate closest to `query_hashes` by pHash distance."""
        best_idx: Optional[int] = None
        best_dist: int = 10**9
        for i, cand in enumerate(candidates):
            d = _hex_hamming(query_hashes.phash, cand.phash)
            if d < best_dist:
                best_dist = d
                best_idx = i
        if best_idx is not None and best_dist <= threshold:
            return best_idx, best_dist
        return None, best_dist
