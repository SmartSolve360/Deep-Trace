"""
Unit tests for the DCT-QIM watermark engine.

Tests:
- generate_payload determinism
- embed → extract round trip (no attack)
- payload mismatch raises PayloadMismatchError
- insufficient capacity raises InsufficientCapacityError
- robustness to mild JPEG recompression (Q=85)
- robustness to mild Gaussian noise
"""

from __future__ import annotations

import io

import cv2
import numpy as np
import pytest
from PIL import Image

from app.core.exceptions import InsufficientCapacityError, PayloadMismatchError
from app.engine.watermark import DCTQIMWatermark

SECRET = b"unit_test_secret_key_min_16b"


def _make_image(h: int = 256, w: int = 256, seed: int = 42) -> np.ndarray:
    """Deterministic natural-looking image."""
    rng = np.random.default_rng(seed)
    # Multi-scale noise → not a flat field
    a = rng.integers(0, 255, (h, w, 3), dtype=np.uint8)
    # Add a gradient so the image isn't pure noise
    for c in range(3):
        a[:, :, c] = (a[:, :, c] * 0.7 + np.linspace(0, 200, w).astype(np.uint8)[None, :]) % 255
    return a


def test_generate_payload_deterministic():
    wm = DCTQIMWatermark(secret_key=SECRET)
    p1 = wm.generate_payload("acct-001", 1700000000.0, "dev-sig-abc")
    p2 = wm.generate_payload("acct-001", 1700000000.0, "dev-sig-abc")
    assert p1 == p2
    assert len(p1) == 16


def test_generate_payload_changes_with_account():
    wm = DCTQIMWatermark(secret_key=SECRET)
    p1 = wm.generate_payload("acct-001", 1700000000.0, "dev-sig-abc")
    p2 = wm.generate_payload("acct-002", 1700000000.0, "dev-sig-abc")
    assert p1 != p2


def test_embed_extract_round_trip():
    wm = DCTQIMWatermark(secret_key=SECRET)
    img = _make_image()
    result = wm.embed_watermark(img, "acct-001", 1700000000.0, "dev-sig")
    assert result.watermarked_bgr.shape == img.shape
    assert result.psnr_db > 30  # visually acceptable

    extracted_hex, status, errors = wm.extract_watermark(result.watermarked_bgr)
    assert extracted_hex == result.payload_hex, f"payload mismatch: {status}"
    assert status.startswith("OK")


def test_verify_payload_true():
    wm = DCTQIMWatermark(secret_key=SECRET)
    img = _make_image()
    result = wm.embed_watermark(img, "acct-001", 1700000000.0, "dev-sig")
    ok, status = wm.verify_payload(result.watermarked_bgr, result.payload_hex)
    assert ok is True
    assert "OK" in status


def test_verify_payload_mismatch_raises():
    wm = DCTQIMWatermark(secret_key=SECRET)
    img = _make_image()
    result = wm.embed_watermark(img, "acct-001", 1700000000.0, "dev-sig")
    with pytest.raises(PayloadMismatchError):
        wm.verify_payload(result.watermarked_bgr, "deadbeef" * 4)


def test_insufficient_capacity_raises():
    wm = DCTQIMWatermark(secret_key=SECRET)
    tiny = _make_image(h=64, w=64)
    with pytest.raises(InsufficientCapacityError):
        wm.embed_watermark(tiny, "acct-001", 1700000000.0, "dev-sig")


def test_minimum_size_works():
    """128x128 should be just enough (256 blocks, need 100 = 4 sync + 96 data)."""
    wm = DCTQIMWatermark(secret_key=SECRET)
    img = _make_image(h=128, w=128)
    result = wm.embed_watermark(img, "acct-001", 1700000000.0, "dev-sig")
    extracted_hex, status, _ = wm.extract_watermark(result.watermarked_bgr)
    assert extracted_hex == result.payload_hex, f"failed at min size: {status}"


def test_robustness_jpeg_q85():
    """Watermark should survive JPEG recompression at Q=85."""
    wm = DCTQIMWatermark(secret_key=SECRET)
    img = _make_image()
    result = wm.embed_watermark(img, "acct-001", 1700000000.0, "dev-sig")

    # Encode as JPEG Q=85, decode back
    pil = Image.fromarray(cv2.cvtColor(result.watermarked_bgr, cv2.COLOR_BGR2RGB))
    buf = io.BytesIO()
    pil.save(buf, format="JPEG", quality=85)
    buf.seek(0)
    jpeg_back = np.array(Image.open(buf).convert("RGB"))
    jpeg_back_bgr = cv2.cvtColor(jpeg_back, cv2.COLOR_RGB2BGR)

    extracted_hex, status, errors = wm.extract_watermark(jpeg_back_bgr)
    assert extracted_hex == result.payload_hex, f"survived JPEG Q=85? status={status}, errors={errors}"


def test_robustness_mild_gaussian_noise():
    """Watermark should survive small Gaussian noise (sigma=3)."""
    wm = DCTQIMWatermark(secret_key=SECRET)
    img = _make_image()
    result = wm.embed_watermark(img, "acct-001", 1700000000.0, "dev-sig")

    rng = np.random.default_rng(123)
    noisy = result.watermarked_bgr.astype(np.float32)
    noisy += rng.normal(0, 3, noisy.shape)
    noisy = np.clip(noisy, 0, 255).astype(np.uint8)

    extracted_hex, status, errors = wm.extract_watermark(noisy)
    assert extracted_hex == result.payload_hex, f"survived noise? status={status}, errors={errors}"


def test_secret_key_validation():
    with pytest.raises(ValueError):
        DCTQIMWatermark(secret_key=b"short")
