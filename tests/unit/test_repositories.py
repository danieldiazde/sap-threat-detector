"""Unit tests for src/storage/repositories.py.

Regression tests for the 2026-04-28 silent-data-loss incident: a missing
LOG_ID column on prod HANA caused every INSERT to fail, but the bulk
insert helper swallowed the per-row errors and the fetcher acknowledged
the window anyway. ~36h of ingestion was lost before anyone noticed.

These tests pin two invariants:
1. Schema-shape errors (invalid column, missing table) re-raise instead
   of falling back to row-by-row.
2. ``insert_logs`` raises when a non-empty batch persists zero rows, so
   ``Pipeline.run_once`` trips ``reset_window_start()``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pandas as pd
import pytest
from src.storage.repositories import LogRepository


def _df_with_one_row() -> pd.DataFrame:
    return pd.DataFrame(
        [{"datetime": "2026-04-28 10:00:00", "source_ip": "10.0.0.1"}]
    )


class _FakeCursor:
    """Records calls and raises pre-programmed errors."""

    def __init__(self, *, executemany_raises: Exception | None = None,
                 execute_raises: Exception | None = None):
        self._executemany_raises = executemany_raises
        self._execute_raises = execute_raises
        self.executemany_calls = 0
        self.execute_calls = 0

    def executemany(self, _sql, rows):
        self.executemany_calls += 1
        if self._executemany_raises is not None:
            raise self._executemany_raises

    def execute(self, _sql, _row):
        self.execute_calls += 1
        if self._execute_raises is not None:
            raise self._execute_raises

    def close(self):
        pass


class _FakeConn:
    def __init__(self, cursor: _FakeCursor):
        self._cursor = cursor
        self.commits = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1


class TestBulkInsertStructuralErrors:
    def test_invalid_column_reraises(self):
        """LOG_ID-missing-in-prod scenario: must propagate, not row-skip."""
        cursor = _FakeCursor(
            executemany_raises=Exception("invalid column name: LOG_ID"),
        )
        conn = _FakeConn(cursor)
        repo = LogRepository()

        with pytest.raises(Exception, match="invalid column name"):
            repo._bulk_insert_sync(conn, [{"source_ip": "1.2.3.4"}])

        assert cursor.execute_calls == 0, "row-by-row fallback must not run"

    def test_missing_table_reraises(self):
        cursor = _FakeCursor(
            executemany_raises=Exception("could not find table SECURITY_LOGS"),
        )
        conn = _FakeConn(cursor)
        repo = LogRepository()

        with pytest.raises(Exception, match="could not find table"):
            repo._bulk_insert_sync(conn, [{"source_ip": "1.2.3.4"}])

    def test_per_row_constraint_still_falls_back(self):
        """Non-structural chunk failures still get the row-by-row fallback."""
        cursor = _FakeCursor(
            executemany_raises=Exception("constraint violation: NOT NULL"),
        )
        conn = _FakeConn(cursor)
        repo = LogRepository()

        persisted = repo._bulk_insert_sync(
            conn, [{"source_ip": "1.2.3.4"}, {"source_ip": "5.6.7.8"}]
        )
        assert cursor.execute_calls == 2
        assert persisted == 2

    def test_returns_persisted_count_on_clean_insert(self):
        cursor = _FakeCursor()
        conn = _FakeConn(cursor)
        repo = LogRepository()

        persisted = repo._bulk_insert_sync(
            conn, [{"source_ip": "1.2.3.4"}, {"source_ip": "5.6.7.8"}]
        )
        assert persisted == 2
        assert conn.commits == 1


class TestInsertLogsAllRejected:
    @pytest.mark.asyncio
    async def test_raises_when_zero_rows_persist(self):
        """If every row is rejected, surface so the pipeline can reset the window."""
        repo = LogRepository()

        class _Acquire:
            async def __aenter__(self_inner):
                return object()  # non-None placeholder conn

            async def __aexit__(self_inner, *_):
                return False

        with patch.object(repo._pool, "acquire", return_value=_Acquire()), \
             patch("src.storage.repositories.settings") as mock_settings, \
             patch.object(repo, "_bulk_insert_sync", return_value=0):
            mock_settings.mock_hana = False

            with pytest.raises(RuntimeError, match="all_rows_rejected"):
                await repo.insert_logs(_df_with_one_row(), datetime.now(UTC))

    @pytest.mark.asyncio
    async def test_returns_persisted_count(self):
        repo = LogRepository()

        class _Acquire:
            async def __aenter__(self_inner):
                return object()

            async def __aexit__(self_inner, *_):
                return False

        with patch.object(repo._pool, "acquire", return_value=_Acquire()), \
             patch("src.storage.repositories.settings") as mock_settings, \
             patch.object(repo, "_bulk_insert_sync", return_value=1):
            mock_settings.mock_hana = False

            count = await repo.insert_logs(_df_with_one_row(), datetime.now(UTC))
            assert count == 1
