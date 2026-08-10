"""
Public asset endpoints — no API key required.

These routes let the Wix frontend (and anyone with the asset_id) re-fetch
the metadata and the watermarked image for a previously-registered asset.

Rate-limited per IP (see `app.main.create_app` for the limiter setup).

GET /api/v1/asset/{asset_id}          public asset metadata
GET /api/v1/asset/{asset_id}/image    watermarked PNG (binary)
GET /api/v1/asset/{asset_id}/thumb    128x128 perceptual thumbnail (PNG)
"""

from __future__ import annotations

import io
import uuid

import cv2
import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_ledger_service
from app.core.logging import get_logger
from app.core.rate_limit import limiter, public_limit
from app.database import get_db
from app.services.ledger import LedgerService
from app.utils.image import encode_png

logger = get_logger(__name__)

router = APIRouter(prefix="/asset", tags=["public-asset"])


# ---------------------------------------------------------------------------
# Public metadata
# ---------------------------------------------------------------------------


@router.get(
    "/{asset_id}",
    summary="Public asset metadata (no API key required, rate-limited 60/min/IP)",
    responses={
        200: {"description": "Asset metadata"},
        404: {"description": "Asset not found"},
    },
)
@limiter.limit(public_limit)
async def get_public_asset(
    request: Request,
    response: Response,
    asset_id: str,
    ledger: LedgerService = Depends(get_ledger_service),
) -> dict:
    """Return sanitised asset metadata. Excludes secret material."""
    try:
        uid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="asset_id must be a UUID")

    entry = await ledger.get_by_id(uid)
    if entry is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    d = entry.to_dict()
    # Strip secret material from the public view
    d.pop("zkp_opening_value", None)
    d.pop("zkp_opening_randomness", None)
    d["public_endpoint"] = True
    d["image_url"] = f"/api/v1/asset/{asset_id}/image"
    d["thumb_url"] = f"/api/v1/asset/{asset_id}/thumb"
    return d


# ---------------------------------------------------------------------------
# Public image
# ---------------------------------------------------------------------------


@router.get(
    "/{asset_id}/image",
    summary="Download the watermarked image (PNG, no API key, rate-limited)",
    responses={
        200: {"content": {"image/png": {}}, "description": "Watermarked PNG"},
        404: {"description": "Asset not found or image not stored"},
    },
    response_class=Response,
)
@limiter.limit(public_limit)
async def get_public_asset_image(
    request: Request,
    response: Response,
    asset_id: str,
    ledger: LedgerService = Depends(get_ledger_service),
) -> Response:
    """Stream the watermarked PNG. 4xx if not stored for this asset."""
    try:
        uid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="asset_id must be a UUID")

    entry = await ledger.get_by_id(uid)
    if entry is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not entry.watermarked_image:
        raise HTTPException(
            status_code=410,
            detail="Watermarked image not stored for this asset. Re-embed to populate.",
        )

    return Response(
        content=entry.watermarked_image,
        media_type=entry.content_type or "image/png",
        headers={
            "Content-Disposition": f'inline; filename="deep-trace-{asset_id}.png"',
            "Cache-Control": "public, max-age=3600",
            "X-Asset-Id": asset_id,
            "X-Image-Size": str(len(entry.watermarked_image)),
        },
    )


# ---------------------------------------------------------------------------
# Thumbnail (low-res, useful for UI previews)
# ---------------------------------------------------------------------------


@router.get(
    "/{asset_id}/thumb",
    summary="128x128 perceptual thumbnail (PNG, no API key, rate-limited)",
    responses={
        200: {"content": {"image/png": {}}, "description": "128x128 PNG thumbnail"},
        404: {"description": "Asset not found"},
    },
    response_class=Response,
)
@limiter.limit(public_limit)
async def get_public_asset_thumb(
    request: Request,
    response: Response,
    asset_id: str,
    ledger: LedgerService = Depends(get_ledger_service),
) -> Response:
    """Return a 128x128 thumbnail of the watermarked image."""
    try:
        uid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="asset_id must be a UUID")

    entry = await ledger.get_by_id(uid)
    if entry is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not entry.watermarked_image:
        raise HTTPException(
            status_code=410,
            detail="Watermarked image not stored for this asset.",
        )

    # Decode, resize, re-encode
    arr = np.frombuffer(entry.watermarked_image, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(status_code=500, detail="Stored image could not be decoded")
    thumb = cv2.resize(img, (128, 128), interpolation=cv2.INTER_AREA)
    ok, buf = cv2.imencode(".png", thumb)
    if not ok:
        raise HTTPException(status_code=500, detail="Thumbnail encoding failed")
    return Response(
        content=buf.tobytes(),
        media_type="image/png",
        headers={
            "Content-Disposition": f'inline; filename="deep-trace-{asset_id}-thumb.png"',
            "Cache-Control": "public, max-age=3600",
        },
    )
