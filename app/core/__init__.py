"""
Cross-cutting concerns: security primitives, structured logging, exception types.
"""

from app.core.security import (
    derive_subkey,
    hmac_sha256,
    verify_hmac_sha256,
    constant_time_compare,
    generate_api_key,
    issue_challenge,
    verify_challenge,
)
from app.core.logging import get_logger, configure_logging
from app.core.exceptions import (
    DeepTraceError,
    InvalidImageError,
    PayloadMismatchError,
    LedgerIntegrityError,
    AuthError,
    InsufficientCapacityError,
)

__all__ = [
    "derive_subkey",
    "hmac_sha256",
    "verify_hmac_sha256",
    "constant_time_compare",
    "generate_api_key",
    "issue_challenge",
    "verify_challenge",
    "get_logger",
    "configure_logging",
    "DeepTraceError",
    "InvalidImageError",
    "PayloadMismatchError",
    "LedgerIntegrityError",
    "AuthError",
    "InsufficientCapacityError",
]
