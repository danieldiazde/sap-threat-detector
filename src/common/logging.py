"""
logging.py
----------
Centralized logger configuration.

- Dev mode: human-readable format with timestamps and colors via stdlib
  (no ANSI injection — CF log drains swallow them anyway).
- Production mode (ENVIRONMENT=production): structured JSON lines so SAP
  log aggregation can parse them.

Usage in every module::

    from src.common.logging import get_logger
    logger = get_logger(__name__)
    logger.info("fetched batch", extra={"rows": len(df)})

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from src.common.config import settings

# ─── Constants ─────────────────────────────────────────────────────────────

_DEV_FORMAT: str = "%(asctime)s %(levelname)-5s %(name)s :: %(message)s"
_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"

_configured: bool = False


class _JsonFormatter(logging.Formatter):
    """Minimal JSON formatter — no third-party dependency required."""

    # Standard LogRecord attributes we *don't* want duplicated in the JSON payload.
    _RESERVED: frozenset[str] = frozenset(
        {
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "message", "module",
            "msecs", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName", "taskName",
        }
    )

    def format(self, record: logging.LogRecord) -> str:
        import json

        payload: dict[str, Any] = {
            "ts": self.formatTime(record, _DATE_FORMAT),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Pick up any `extra=` kwargs passed by the caller.
        for key, value in record.__dict__.items():
            if key in self._RESERVED or key.startswith("_"):
                continue
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def _configure_root() -> None:
    """Install a single StreamHandler on the root logger, once."""
    global _configured
    if _configured:
        return

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    # Clear any pre-existing handlers (pytest/uvicorn can add their own).
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    if settings.is_production:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(_DEV_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(handler)

    # Tame noisy third-party libraries.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger bound to *name*.

    Configures the root logger on first call. Safe to call from multiple
    modules — configuration is idempotent.
    """
    _configure_root()
    return logging.getLogger(name)
