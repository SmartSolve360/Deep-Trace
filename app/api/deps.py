"""
Shared FastAPI dependencies.

The `get_ledger_service` and `get_forensics_service` factories build
request-scoped service instances from the per-request AsyncSession.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.engine.c2pa_wrapper import C2PAWrapper
from app.config import settings
from app.services.forensics import ForensicsService
from app.services.ledger import LedgerService


def get_ledger_service(session: AsyncSession = Depends(get_db)) -> LedgerService:
    """FastAPI dependency: build a LedgerService bound to the request session."""
    return LedgerService(session)


def get_forensics_service(
    ledger: LedgerService = Depends(get_ledger_service),
) -> ForensicsService:
    """FastAPI dependency: build a ForensicsService."""
    c2pa = C2PAWrapper(
        signing_key_path=settings.C2PA_SIGNING_KEY_PATH,
        signing_cert_path=settings.C2PA_SIGNING_CERT_PATH,
    )
    return ForensicsService(ledger=ledger, c2pa=c2pa)
