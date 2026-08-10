"""
DEEP-TRACE Engine — FastAPI application entrypoint.

Architecture
------------
- Async FastAPI with lifespan-managed database engine.
- Per-request AsyncSession injected via `get_db`.
- All endpoints under `/api/v1`; health/ready at root for k8s probes.
- CORS permissive by default; tighten in production via CORS_ALLOW_ORIGINS.
- Per-IP / per-API-key rate limiting via slowapi.
- Custom JSON exception handler maps `DeepTraceError` subclasses to
  consistent error envelopes.

Run
---
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Or via Docker Compose (recommended for local dev):
    docker compose up --build
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1 import auth as auth_router
from app.api.v1 import forensics as forensics_router
from app.api.v1 import health as health_router
from app.api.v1 import ledger as ledger_router
from app.api.v1 import public_asset as public_asset_router
from app.api.v1 import watermark as watermark_router
from app.config import settings
from app.core.exceptions import DeepTraceError
from app.core.logging import configure_logging, get_logger
from app.core.rate_limit import limiter
from app.database import dispose_db, init_db

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Process lifespan: configure logging, init DB on startup, dispose on shutdown."""
    configure_logging()
    logger.info(
        "app.startup",
        env=settings.ENVIRONMENT,
        project=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
    )
    try:
        await init_db()
    except Exception as exc:  # pragma: no cover - bootstrap path
        logger.error("app.db.init_failed", error=str(exc))
        if settings.ENVIRONMENT == "production":
            raise
        else:
            logger.warn("app.db.init_skipped", detail="DB not reachable in dev; continuing")
    yield
    await dispose_db()
    logger.info("app.shutdown")


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
        description=(
            "DEEP-TRACE is a forensic content-provenance engine. "
            "It embeds cryptographic watermarks in the frequency domain, "
            "computes perceptual hashes, builds Pedersen commitments, "
            "emits C2PA manifests, and persists every asset to a tamper-"
            "evident ledger. Evidence handling follows ISO/IEC 27037:2012."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ---- Rate limiter (slowapi) ----
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    # NOTE: We deliberately do NOT add SlowAPIMiddleware. It conflicts
    # with FastAPI's Request parameter handling. The @limiter.limit
    # decorators on each route still enforce the limit via the
    # exception handler above.

    # ---- Middleware ----
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOW_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Asset-Id",
            "X-Image-Size",
        ],
    )

    # ---- Exception handlers ----
    @app.exception_handler(DeepTraceError)
    async def _handle_deep_trace_error(request: Request, exc: DeepTraceError) -> JSONResponse:
        logger.warn(
            "app.error.deep_trace",
            path=str(request.url),
            code=exc.error_code,
            message=exc.message,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.to_dict()},
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        logger.warn("app.error.validation", path=str(request.url), errors=exc.errors())
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "error_code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": {"errors": exc.errors()},
                }
            },
        )

    # ---- Routers ----
    app.include_router(health_router.router)
    app.include_router(public_asset_router.router, prefix=settings.API_V1_PREFIX)  # public, no auth
    app.include_router(auth_router.router, prefix=settings.API_V1_PREFIX)
    app.include_router(watermark_router.router, prefix=settings.API_V1_PREFIX)
    app.include_router(forensics_router.router, prefix=settings.API_V1_PREFIX)
    app.include_router(ledger_router.router, prefix=settings.API_V1_PREFIX)

    return app


# Module-level ASGI app for uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=settings.LOG_LEVEL.lower(),
    )
