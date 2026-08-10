"""
Async SQLAlchemy 2.0 engine, session factory, and FastAPI dependency.

We use asyncpg as the async driver for high-throughput Postgres access.
Sessions are short-lived and created per-request via the `get_db` dependency.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# Engine is created lazily so tests can override the URL.
_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine() -> AsyncEngine:
    """Return (or create) the global async engine."""
    global _engine
    if _engine is None:
        url = settings.DATABASE_URL
        is_sqlite = url.startswith("sqlite")
        if is_sqlite:
            # SQLite in-memory needs a shared connection so every
            # session sees the same database. StaticPool maintains a
            # single connection for the lifetime of the engine.
            from sqlalchemy.pool import StaticPool

            _engine = create_async_engine(
                url,
                echo=settings.DATABASE_ECHO,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
        else:
            _engine = create_async_engine(
                url,
                echo=settings.DATABASE_ECHO,
                pool_size=settings.DATABASE_POOL_SIZE,
                max_overflow=settings.DATABASE_MAX_OVERFLOW,
                pool_pre_ping=True,
                future=True,
            )
        logger.info("database.engine.created", url=mask_dsn(url), sqlite=is_sqlite)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the global session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )
    return _session_factory


def mask_dsn(dsn: str) -> str:
    """Hide password in DSN for logging."""
    if "@" not in dsn:
        return dsn
    scheme_userpass, host_part = dsn.rsplit("@", 1)
    if "://" in scheme_userpass:
        scheme, userpass = scheme_userpass.split("://", 1)
    else:
        scheme, userpass = "", scheme_userpass
    if ":" in userpass:
        user, _ = userpass.split(":", 1)
        userpass = f"{user}:***"
    return f"{scheme}://{userpass}@{host_part}" if scheme else f"{userpass}@{host_part}"


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a request-scoped AsyncSession.

    Commits on clean exit, rolls back on exception, always closes.
    Services that perform writes should add their entries to the
    session; the commit happens here at the request boundary.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for ad-hoc session use outside FastAPI dependency injection."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables (used in dev/test; in prod use Alembic)."""
    from app.models import Base as ModelsBase  # local import to avoid cycle

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(ModelsBase.metadata.create_all)
    logger.info("database.schema.initialized")


async def dispose_db() -> None:
    """Dispose of the engine on shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("database.engine.disposed")
