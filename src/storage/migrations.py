"""
migrations.py
-------------
Idempotent schema application. Reads ``schema.sql`` and executes each
statement, swallowing "already exists" errors so it's safe to run on
every FastAPI startup.

This is deliberately CREATE-only. If the schema evolves after go-live,
any ALTERs need to be run by hand via SAP HANA cockpit.

Owner: Data Architect & Backend Developer
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from src.common.config import settings
from src.common.logging import get_logger
from src.storage.pool import pool

logger = get_logger(__name__)

SCHEMA_PATH: Path = Path(__file__).resolve().parent / "schema.sql"

# HANA error codes for "object already exists". Catching by substring is
# safer than code matching because hdbcli wraps these inconsistently.
_ALREADY_EXISTS_HINTS: tuple[str, ...] = (
    "already exists",
    "existing object",
    "cannot use duplicate",
)


async def apply_schema() -> None:
    """
    Execute every statement in ``schema.sql`` against HANA.

    No-op in mock mode. Failures other than "already exists" are re-raised.
    """
    if settings.mock_hana:
        logger.info("migrations.apply_schema.mock_skip")
        return

    statements = _load_statements(SCHEMA_PATH)
    logger.info("migrations.apply_schema.start", extra={"statements": len(statements)})

    async with pool.acquire() as conn:
        if conn is None:
            return
        await asyncio.to_thread(_apply_sync, conn, statements)

    logger.info("migrations.apply_schema.done")


def _load_statements(path: Path) -> list[str]:
    """Split a SQL file into individual statements, stripping comments."""
    raw = path.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("--")]
    cleaned = "\n".join(lines)
    return [stmt.strip() for stmt in cleaned.split(";") if stmt.strip()]


def _apply_sync(conn: Any, statements: list[str]) -> None:
    cursor = conn.cursor()
    try:
        for stmt in statements:
            try:
                cursor.execute(stmt)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if any(hint in msg for hint in _ALREADY_EXISTS_HINTS):
                    logger.debug("migrations.skip_existing", extra={"preview": stmt[:60]})
                    continue
                logger.error(
                    "migrations.statement_failed",
                    extra={"preview": stmt[:120], "error": str(exc)},
                )
                raise
        conn.commit()
    finally:
        cursor.close()
