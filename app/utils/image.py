"""
Image I/O utilities — OpenCV-backed with defensive validation.

The forensic boundary: every image entering or leaving the system goes
through one of these helpers. We normalise to a known dtype, enforce
size limits, and return decoded arrays ready for the engine layer.
"""

from __future__ import annotations

import io
from typing import Tuple

import cv2
import numpy as np
from PIL import Image

from app.config import settings
from app.core.exceptions import InvalidImageError


def decode_image(contents: bytes) -> np.ndarray:
    """
    Decode raw image bytes to a uint8 BGR ndarray.

    Accepts PNG, JPEG, WebP, BMP, TIFF. Rejects anything else.
    """
    if not contents or len(contents) > 50 * 1024 * 1024:  # 50 MB hard cap
        raise InvalidImageError("Image too large or empty", details={"bytes": len(contents)})

    nparr = np.frombuffer(contents, dtype=np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise InvalidImageError("Could not decode image — unsupported format or corrupt data")

    if img.dtype != np.uint8:
        img = img.astype(np.uint8)

    h, w = img.shape[:2]
    if h < settings.WATERMARK_MIN_IMAGE_SIZE or w < settings.WATERMARK_MIN_IMAGE_SIZE:
        raise InvalidImageError(
            f"Image too small: {w}x{h}. Minimum is {settings.WATERMARK_MIN_IMAGE_SIZE}x{settings.WATERMARK_MIN_IMAGE_SIZE}",
            details={"width": w, "height": h, "min_size": settings.WATERMARK_MIN_IMAGE_SIZE},
        )
    if h > settings.WATERMARK_MAX_IMAGE_SIZE or w > settings.WATERMARK_MAX_IMAGE_SIZE:
        raise InvalidImageError(
            f"Image too large: {w}x{h}. Maximum is {settings.WATERMARK_MAX_IMAGE_SIZE}x{settings.WATERMARK_MAX_IMAGE_SIZE}",
            details={"width": w, "height": h, "max_size": settings.WATERMARK_MAX_IMAGE_SIZE},
        )
    return img


def encode_png(image_bgr: np.ndarray) -> Tuple[bytes, int]:
    """Encode a BGR ndarray to PNG bytes. Returns (bytes, file_size)."""
    if image_bgr is None or image_bgr.dtype != np.uint8:
        raise InvalidImageError("image_bgr must be a uint8 array")
    ok, buf = cv2.imencode(".png", image_bgr)
    if not ok:
        raise InvalidImageError("Failed to encode image as PNG")
    return bytes(buf), int(buf.nbytes)


def validate_image(image_bgr: np.ndarray) -> None:
    """Raise InvalidImageError if the image is not a valid 8-bit BGR array."""
    if image_bgr is None:
        raise InvalidImageError("Image is None")
    if image_bgr.ndim != 3 or image_bgr.shape[2] != 3:
        raise InvalidImageError(f"Image must be HxWx3, got shape {image_bgr.shape}")
    if image_bgr.dtype != np.uint8:
        raise InvalidImageError(f"Image dtype must be uint8, got {image_bgr.dtype}")
    h, w = image_bgr.shape[:2]
    if h < settings.WATERMARK_MIN_IMAGE_SIZE or w < settings.WATERMARK_MIN_IMAGE_SIZE:
        raise InvalidImageError(f"Image too small: {w}x{h}")


def normalize_image(image_bgr: np.ndarray) -> np.ndarray:
    """Return a contiguous uint8 BGR array (defensive copy if needed)."""
    if not image_bgr.flags["C_CONTIGUOUS"]:
        image_bgr = np.ascontiguousarray(image_bgr)
    if image_bgr.dtype != np.uint8:
        image_bgr = image_bgr.astype(np.uint8)
    return image_bgr


def pil_to_bgr(pil_image: Image.Image) -> np.ndarray:
    """Convert a PIL Image to OpenCV BGR ndarray."""
    rgb = np.asarray(pil_image.convert("RGB"))
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def bgr_to_rgb_bytes(image_bgr: np.ndarray) -> bytes:
    """Return a base64-style byte string of the RGB representation (for thumbnails)."""
    rgb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
    return rgb.tobytes()
