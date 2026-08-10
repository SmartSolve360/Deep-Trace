"""
Structured logging.

In production set LOG_JSON=true to emit line-delimited JSON, which the
container runtime (Docker / k8s) can ship straight to Loki / ELK / Datadog.
In development we emit human-readable coloured lines.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

import structlog

from app.config import settings


def configure_logging(level: Optional[str] = None) -> None:
    """Configure stdlib logging + structlog once at process start."""
    log_level = (level or settings.LOG_LEVEL).upper()

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if settings.LOG_JSON:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, log_level, logging.INFO)),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Bridge stdlib logging (uvicorn, sqlalchemy) into structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level, logging.INFO),
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a bound logger. Configures logging on first call."""
    if not structlog.is_configured():
        configure_logging()
    return structlog.get_logger(name)
