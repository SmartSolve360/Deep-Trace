"""
POST /api/v1/watermark/embed

Embeds a 128-bit provenance payload into the luminance DCT coefficients
of the image, computes perceptual hashes, builds a Pedersen commitment,
generates a C2PA manifest, and registers the result in the ledger.

Request (multipart/form-data):
    - file:             the image (PNG, JPEG, WebP, BMP, TIFF)
    - account_id:       the binding account identifier
    - account_public_key: the account's hex-encoded public key
    - device_signature: hardware-derived device fingerprint
    - timestamp:        (optional) Unix ts; defaults to server clock
    - original_filename:(optional) human-friendly filename
    - notes:            (optional) free-text annotation

Authentication:
    X-API-Key header (required)

Response (200):
    EmbedResponse JSON describing the new asset_id, payload, hashes,
    C2PA manifest, and the watermarked image as base64-encoded PNG.

Errors:
    400 InvalidImageError      — image unreadable / wrong size
    401 AuthError              — missing/invalid API key
    413 InsufficientCapacityError — image too small for the payload
    500 DeepTraceError         — engine failure
"""

import base64
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status

from app.api.deps import get_forensics_service, get_ledger_service
from app.config import settings
from app.core.exceptions import InsufficientCapacityError, InvalidImageError
from app.core.logging import get_logger
from app.core.rate_limit import embed_limit, limiter
from app.core.security import derive_subkey
from app.schemas.asset import EmbedResponse
from app.services.auth import AuthService
from app.services.forensics import ForensicsService
from app.services.ledger import LedgerService
from app.utils.image import encode_png

logger = get_logger(__name__)

router = APIRouter(prefix="/watermark", tags=["watermark"])


@router.post(
    "/embed",
    response_model=EmbedResponse,
    status_code=status.HTTP_200_OK,
    summary="Embed provenance watermark and register in ledger",
)
@limiter.limit(embed_limit)
async def embed_watermark(
    request: Request,
    response: Response,
    file: UploadFile = File(..., description="Image to watermark (PNG/JPEG/WebP/BMP/TIFF)"),
    account_id: str = Form(..., min_length=1, max_length=128),
    device_signature: str = Form(..., min_length=1, max_length=128),
    account_public_key: Optional[str] = Form(None, min_length=32, max_length=128),
    timestamp: Optional[float] = Form(None),
    original_filename: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    api_key: str = Depends(AuthService.require_api_key),
    forensics: ForensicsService = Depends(get_forensics_service),
    ledger: LedgerService = Depends(get_ledger_service),  # ensures session is wired
) -> EmbedResponse:
    """Embed a watermark and register the asset. See module docstring."""
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")

    # If the client didn't supply an account_public_key (e.g. the Wix
    # Velo client which doesn't manage keypairs), derive a stable one
    # from the account_id + master secret. This still ties every asset
    # to a per-account deterministic identifier without forcing the
    # UI to manage a public key.
    if not account_public_key:
        derived = derive_subkey(
            settings.SECRET_KEY.encode("utf-8"),
            f"account_pubkey/v1/{account_id}",
            32,
        )
        account_public_key = "04" + derived.hex()
        logger.debug("account_public_key.derived", account_id=account_id)

    try:
        result = await forensics.embed_and_register(
            image_bytes=contents,
            account_id=account_id,
            account_public_key=account_public_key,
            device_signature=device_signature,
            original_filename=original_filename or file.filename,
            timestamp=timestamp,
            notes=notes,
        )
    except InvalidImageError as exc:
        raise HTTPException(status_code=400, detail=exc.message)
    except InsufficientCapacityError as exc:
        raise HTTPException(status_code=413, detail=exc.message)

    logger.info(
        "api.embed.success",
        asset_id=result.asset_id,
        account_id=account_id,
        psnr_db=result.psnr_db,
    )
    return result
