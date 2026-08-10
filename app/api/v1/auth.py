"""
Authentication / challenge endpoint.

POST /api/v1/auth/challenge
    Issue a short-lived HMAC challenge for a given account_id.
    The challenge must be presented as the X-Challenge header to
    replay-protected endpoints (e.g. /forensics/verify).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.security import Challenge
from app.services.auth import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


class ChallengeRequest(BaseModel):
    """Request body for issuing a challenge."""

    account_id: str = Field(..., min_length=1, max_length=128)


class ChallengeResponse(BaseModel):
    """Response carrying the challenge token + parameters."""

    challenge_token: str
    nonce: str
    issued_at: int
    expires_at: int
    ttl_seconds: int


@router.post(
    "/challenge",
    response_model=ChallengeResponse,
    status_code=status.HTTP_200_OK,
    summary="Issue an HMAC challenge token for an account",
)
async def issue_challenge(
    body: ChallengeRequest,
    api_key: str = Depends(AuthService.require_api_key),
) -> ChallengeResponse:
    challenge: Challenge = AuthService.issue_challenge_for_account(body.account_id)
    return ChallengeResponse(
        challenge_token=challenge.to_token(),
        nonce=challenge.nonce,
        issued_at=challenge.issued_at,
        expires_at=challenge.expires_at,
        ttl_seconds=challenge.expires_at - challenge.issued_at,
    )
