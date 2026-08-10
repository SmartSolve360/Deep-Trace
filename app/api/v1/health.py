"""
Health and readiness endpoints.

GET /health   — liveness, always returns 200 if the process is up
GET /ready    — readiness, pings the database
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.database import get_db

logger = get_logger(__name__)

router = APIRouter(tags=["meta"])


@router.get("/health", summary="Liveness probe")
async def health() -> dict:
    return {"status": "alive", "service": "deep-trace", "version": "1.0.0"}


@router.get("/ready", summary="Readiness probe (verifies DB connectivity)")
async def ready(db: AsyncSession = Depends(get_db)) -> dict:
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception as exc:  # pragma: no cover
        logger.error("readiness.db.failed", error=str(exc))
        return {"status": "degraded", "database": "down", "error": str(exc)}
