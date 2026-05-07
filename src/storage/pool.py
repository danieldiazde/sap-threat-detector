"""
pool.py
-------
Async-compatible connection pool for SAP HANA.

``hdbcli`` is a synchronous DB-API driver — there is no native async support.
To avoid blocking the FastAPI event loop, we hand out connections from an
``asyncio.Queue`` and run cursor operations in a thread executor via
``asyncio.to_thread``.

In mock mode (no HANA_HOST), the pool is a no-op: ``acquire()`` yields ``None``
and repositories treat that as "in-memory backend".

Owner: Data Architect & Backend Developer
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from src.common.config import settings
from src.common.logging import get_logger

if TYPE_CHECKING:
    from hdbcli.dbapi import Connection

logger = get_logger(__name__)


class HanaPool:
    """Fixed-size pool of ``hdbcli`` connections."""

    def __init__(self, size: int | None = None) -> None:
        self._size: int = size or settings.hana_pool_size
        self._queue: asyncio.Queue[Any] | None = None
        self._initialized: bool = False
        self._closed: bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Open *size* connections and place them in the queue."""
        if self._initialized or settings.mock_hana:
            self._initialized = True
            return

        logger.info("hana_pool.init", extra={"size": self._size, "host": settings.hana_host})
        self._queue = asyncio.Queue(maxsize=self._size)
        for _ in range(self._size):
            conn = await asyncio.to_thread(self._open_connection)
            await self._queue.put(conn)
        self._initialized = True

    async def close(self) -> None:
        """Close every connection in the pool."""
        if self._closed or settings.mock_hana or self._queue is None:
            self._closed = True
            return
        logger.info("hana_pool.close")
        while not self._queue.empty():
            conn = await self._queue.get()
            try:
                await asyncio.to_thread(conn.close)
            except Exception as exc:
                logger.warning("hana_pool.close_connection_failed", extra={"error": str(exc)})
        self._closed = True

    # ── Checkout / checkin ────────────────────────────────────────────

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[Any]:
        """
        Check out a connection from the pool for the duration of the block.

        In mock mode yields ``None`` — callers must handle that.
        """
        if settings.mock_hana:
            yield None
            return

        if not self._initialized:
            await self.initialize()
        assert self._queue is not None

        conn = await self._queue.get()
        try:
            yield conn
        finally:
            await self._queue.put(conn)

    async def ping(self) -> bool:
        """Return True if a fresh connection can execute a trivial query.

        Opens a brand-new TCP connection with a 10 s timeout so that a stale
        pooled socket kept alive by HANA Cloud's proxy does not mask a paused
        engine.  The connection is closed immediately and never returned to the
        pool.
        """
        if settings.mock_hana:
            return True

        def _fresh_ping() -> None:
            from hdbcli import dbapi

            conn = dbapi.connect(
                address=settings.hana_host,
                port=settings.hana_port,
                user=settings.hana_user,
                password=settings.hana_password,
                databaseName=settings.hana_database,
                communicationTimeout=10000,
            )
            try:
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT 1 FROM DUMMY")
                    cursor.fetchall()
                finally:
                    cursor.close()
            finally:
                conn.close()

        try:
            await asyncio.to_thread(_fresh_ping)
            return True
        except Exception as exc:
            logger.warning("hana_pool.ping_failed", extra={"error": str(exc)})
            return False

    # ── Internal ──────────────────────────────────────────────────────

    @staticmethod
    def _open_connection() -> Connection:  # type: ignore[valid-type]
        from hdbcli import dbapi

        return dbapi.connect(
            address=settings.hana_host,
            port=settings.hana_port,
            user=settings.hana_user,
            password=settings.hana_password,
            databaseName=settings.hana_database,
        )

    @staticmethod
    def _ping_sync(conn: Any) -> None:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT 1 FROM DUMMY")
            cursor.fetchall()
        finally:
            cursor.close()


# Module-level singleton. Import via ``from src.storage.pool import pool``.
pool: HanaPool = HanaPool()
