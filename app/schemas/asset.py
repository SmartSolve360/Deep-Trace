"""
Pydantic schemas for the public API.

These models are the source of truth for request/response shapes
documented in the OpenAPI spec. We use Pydantic v2 syntax.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Embed endpoint
# ---------------------------------------------------------------------------


class EmbedRequestHeaders(BaseModel):
    """Headers that may accompany a /watermark/embed request."""

    model_config = ConfigDict(extra="forbid")

    x_api_key: str = Field(..., description="Service-to-service API key")
    x_challenge: Optional[str] = Field(None, description="Optional pre-issued HMAC challenge token")
    x_account_id: str = Field(..., min_length=1, max_length=128, description="Account identifier (hashed for storage)")


class EmbedResponse(BaseModel):
    """Response of POST /api/v1/watermark/embed."""

    model_config = ConfigDict(extra="forbid")

    status: str = "SUCCESS"
    asset_id: str
    payload_hex: str
    zkp_commitment_hex: str
    perceptual_hashes: dict[str, str]
    c2pa: dict
    image_width: int
    image_height: int
    file_size_bytes: int
    psnr_db: float
    watermarked_image_b64: str = Field(
        ...,
        description="Base64-encoded PNG of the watermarked image, ready for download.",
    )
    created_at: datetime
    evidence_handling_standard: str = "ISO/IEC 27037:2012"


# ---------------------------------------------------------------------------
# Extract endpoint
# ---------------------------------------------------------------------------


class ExtractResponse(BaseModel):
    """Response of POST /api/v1/forensics/extract."""

    model_config = ConfigDict(extra="forbid")

    status: str
    asset_id: Optional[str] = None
    payload_hex: Optional[str] = None
    zkp_commitment_hex: Optional[str] = None
    perceptual_hashes: dict[str, str]
    ledger_match: Optional["LedgerMatch"] = None
    c2pa_manifest: Optional[dict] = None
    extraction_status: str
    errors_corrected: int = 0
    admissibility_standard: str = "ISO/IEC 27037:2012"


class LedgerMatch(BaseModel):
    """A matched ledger entry returned alongside an extract."""

    asset_id: str
    account_id: str
    creation_timestamp: datetime
    payload_match: bool
    perceptual_distance: dict[str, int]
    within_threshold: bool = Field(
        ...,
        description="True if any per-hash distance is within the configured tolerance for that hash.",
    )


class VerifyResponse(BaseModel):
    """Response of POST /api/v1/forensics/verify."""

    model_config = ConfigDict(extra="forbid")

    verified: bool
    status: str
    asset_id: Optional[str] = None
    payload_match: bool
    perceptual_distance: Optional[dict[str, int]] = None


# ---------------------------------------------------------------------------
# Ledger endpoints
# ---------------------------------------------------------------------------


class LedgerEntry(BaseModel):
    """A single ledger row, public-facing shape."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    asset_id: str
    payload_hex: str
    zkp_commitment_hex: str
    perceptual_hashes: dict[str, str]
    c2pa: dict
    creation_timestamp: datetime
    account_id: str
    device_signature: str
    generator_model_id: str
    image_width: int
    image_height: int
    file_size_bytes: int
    psnr_db: Optional[float] = None
    created_at: datetime


class LedgerSearchResult(BaseModel):
    """A search hit on the ledger."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    account_id: str
    creation_timestamp: datetime
    perceptual_hashes: dict[str, str]
    perceptual_distance: dict[str, int]
    payload_match: bool


# Resolve forward reference
ExtractResponse.model_rebuild()
