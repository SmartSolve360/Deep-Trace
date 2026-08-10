"""
Forensic extraction + verification endpoints.

POST /api/v1/forensics/extract
    Extract a latent watermark from an image and try to match it
    against the ledger. Returns the recovered payload, perceptual hashes,
    and any matching ledger entry.

POST /api/v1/forensics/verify
    Given an asset_id, extract the watermark from a suspect image and
    verify it matches the expected payload. Requires an X-Challenge
    header (replay-protected) tied to the account.
"""

from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status

from app.api.deps import get_forensics_service
from app.core.exceptions import InsufficientCapacityError, InvalidImageError
from app.core.logging import get_logger
from app.schemas.asset import ExtractResponse, VerifyResponse
from app.services.auth import AuthService
from app.services.forensics import ForensicsService

logger = get_logger(__name__)

router = APIRouter(prefix="/forensics", tags=["forensics"])


@router.post(
    "/extract",
    response_model=ExtractResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract watermark and match against ledger",
)
async def extract_watermark(
    file: UploadFile = File(..., description="Suspect image"),
    account_id: Optional[str] = Form(None),
    api_key: str = Depends(AuthService.require_api_key),
    forensics: ForensicsService = Depends(get_forensics_service),
) -> ExtractResponse:
    """Extract a watermark and return forensic match info."""
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        result = await forensics.extract_and_lookup(
            image_bytes=contents,
            account_id=account_id,
        )
    except InvalidImageError as exc:
        raise HTTPException(status_code=400, detail=exc.message)
    except InsufficientCapacityError as exc:
        raise HTTPException(status_code=413, detail=exc.message)

    logger.info(
        "api.extract.success",
        status=result.status,
        asset_id=result.asset_id,
        payload_hex_prefix=(result.payload_hex or "")[:16],
    )
    return result


@router.post(
    "/verify/{asset_id}",
    response_model=VerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify that an image matches a specific ledger entry (challenge required)",
)
async def verify_against_asset(
    asset_id: str,
    file: UploadFile = File(..., description="Suspect image to verify"),
    api_key: str = Depends(AuthService.require_api_key),
    challenge: tuple = Depends(AuthService.require_challenge_for_verify),
    forensics: ForensicsService = Depends(get_forensics_service),
) -> VerifyResponse:
    """Extract and compare against the expected asset_id.

    Requires a fresh X-Challenge token in the request headers. The
    challenge is bound to an account_id issued via POST /api/v1/auth/challenge.
    The X-Account-Id header must match the account the challenge was
    issued for.
    """
    challenge_account_id, _ch = challenge

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        result = await forensics.verify(image_bytes=contents, expected_asset_id=asset_id)
    except InvalidImageError as exc:
        raise HTTPException(status_code=400, detail=exc.message)
    except InsufficientCapacityError as exc:
        raise HTTPException(status_code=413, detail=exc.message)

    logger.info(
        "api.verify.complete",
        asset_id=asset_id,
        challenge_account_id=challenge_account_id,
        verified=result.verified,
    )
    return result
