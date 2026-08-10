"""
Unit tests for the perceptual hasher.
"""

from __future__ import annotations

import io

import cv2
import numpy as np
import pytest
from PIL import Image

from app.engine.perceptual import PerceptualHasher


def _make_png_bytes(h: int = 256, w: int = 256, seed: int = 1) -> bytes:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 255, (h, w, 3), dtype=np.uint8)
    pil = Image.fromarray(arr)
    buf = io.BytesIO()
    pil.save(buf, format="PNG")
    return buf.getvalue()


def test_compute_hashes_returns_all_four():
    hashes = PerceptualHasher.compute_hashes(_make_png_bytes())
    assert hashes.phash and hashes.dhash and hashes.ahash and hashes.whash
    # Each hash is imagehash's default length — 8 hex chars (64-bit) typically
    for h in (hashes.phash, hashes.dhash, hashes.ahash, hashes.whash):
        bytes.fromhex(h)  # raises if not hex


def test_same_image_same_hashes():
    a = PerceptualHasher.compute_hashes(_make_png_bytes(seed=1))
    b = PerceptualHasher.compute_hashes(_make_png_bytes(seed=1))
    assert a.phash == b.phash
    assert a.dhash == b.dhash


def test_different_images_different_hashes():
    a = PerceptualHasher.compute_hashes(_make_png_bytes(seed=1))
    b = PerceptualHasher.compute_hashes(_make_png_bytes(seed=2))
    assert a.phash != b.phash


def test_hamming_distance_zero_for_identical():
    a = PerceptualHasher.compute_hashes(_make_png_bytes())
    b = PerceptualHasher.compute_hashes(_make_png_bytes())
    dist = a.hamming_distance(b)
    for k, v in dist.items():
        assert v == 0, f"{k} distance {v} should be 0 for identical images"


def test_hamming_distance_grows_with_difference():
    a = PerceptualHasher.compute_hashes(_make_png_bytes(seed=1))
    b = PerceptualHasher.compute_hashes(_make_png_bytes(seed=99))
    dist = a.hamming_distance(b)
    assert all(v > 0 for v in dist.values())


def test_compute_from_array_matches_png():
    """compute_hashes and compute_hashes_from_array should agree on the same image."""
    arr = np.random.default_rng(0).integers(0, 255, (128, 128, 3), dtype=np.uint8)
    pil = Image.fromarray(arr)
    buf = io.BytesIO()
    pil.save(buf, format="PNG")
    png_bytes = buf.getvalue()
    a = PerceptualHasher.compute_hashes(png_bytes)
    bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
    b = PerceptualHasher.compute_hashes_from_array(bgr)
    assert a.phash == b.phash
