"""
Auth service — wraps the core security primitives for HTTP use.

The embed endpoint requires a valid API key (X-API-Key header). Optionally,
clients may present an X-Challenge token for replay protection on the
sensitive /forensics/verify endpoint.

This service is stateless and thread-safe.
"""

from __future__ import annotations

from typing import Optional

from fastapi import Header, HTTPException, status

from app.config import settings
from app.core.exceptions import AuthError, ChallengeRequiredError
from app.core.security import (
    Challenge,
    is_valid_api_key,
    issue_challenge,
    verify_challenge,
)


class AuthService:
    """Stateless authentication helper for FastAPI dependencies."""

    @staticmethod
    async def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
        """FastAPI dependency: validate the X-API-Key header."""
        if not x_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-API-Key header",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if not is_valid_api_key(x_api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return x_api_key

    @staticmethod
    async def require_challenge_for_verify(
        x_account_id: str = Header(..., min_length=1, max_length=128),
        x_challenge: Optional[str] = Header(default=None),
    ) -> tuple[str, Optional[Challenge]]:
        """FastAPI dependency: require a valid HMAC challenge for /forensics/verify."""
        if not x_challenge:
            raise ChallengeRequiredError(
                "X-Challenge header required for this endpoint",
                details={"endpoint": "/api/v1/forensics/verify", "account_id": x_account_id},
            )
        try:
            challenge = Challenge.from_token(x_challenge)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        try:
            verify_challenge(x_account_id, challenge)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        return x_account_id, challenge

    @staticmethod
    def issue_challenge_for_account(account_id: str) -> Challenge:
        """Public helper to mint a challenge for a given account."""
        if not account_id:
            raise AuthError("account_id required to issue challenge")
        return issue_challenge(account_id)
