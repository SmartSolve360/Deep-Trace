"""
Custom exception hierarchy.

All DEEP-TRACE errors descend from `DeepTraceError`, which the FastAPI
exception handler maps to a JSON response with `error_code` and `message`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class DeepTraceError(Exception):
    """Root of the DEEP-TRACE exception hierarchy."""

    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


class InvalidImageError(DeepTraceError):
    status_code = 400
    error_code = "INVALID_IMAGE"


class PayloadMismatchError(DeepTraceError):
    status_code = 422
    error_code = "PAYLOAD_MISMATCH"


class LedgerIntegrityError(DeepTraceError):
    status_code = 500
    error_code = "LEDGER_INTEGRITY"


class AuthError(DeepTraceError):
    status_code = 401
    error_code = "AUTH_FAILED"


class InsufficientCapacityError(DeepTraceError):
    """The image is too small to host the full watermark payload."""

    status_code = 413
    error_code = "INSUFFICIENT_CAPACITY"


class AssetNotFoundError(DeepTraceError):
    status_code = 404
    error_code = "ASSET_NOT_FOUND"


class ChallengeRequiredError(DeepTraceError):
    """Embed endpoint requires a valid challenge; client should re-request."""

    status_code = 401
    error_code = "CHALLENGE_REQUIRED"
