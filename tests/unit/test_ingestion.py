"""
test_ingestion.py
-----------------
Unit tests for the SAP log fetcher.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pandas as pd
import pytest
from src.ingestion import sap_log_fetcher
from src.ingestion.sap_log_fetcher import _fetch_mock_logs, fetch_all_logs, fetch_logs


class TestMockFetcher:
    def test_returns_dataframe(self):
        df = _fetch_mock_logs()
        assert isinstance(df, pd.DataFrame)

    def test_has_expected_columns(self):
        df = _fetch_mock_logs()
        for col in ("datetime", "source_ip", "event_description", "status"):
            assert col in df.columns, f"Missing column: {col}"

    def test_not_empty(self):
        df = _fetch_mock_logs()
        assert len(df) > 0

    def test_has_ingested_at(self):
        df = _fetch_mock_logs()
        assert "ingested_at" in df.columns


class TestFetchLogs:
    @pytest.mark.asyncio
    async def test_mock_mode_returns_data(self):
        with patch("src.ingestion.sap_log_fetcher.settings") as mock_settings:
            mock_settings.mock_api = True
            df = await fetch_logs()
        assert isinstance(df, pd.DataFrame)
        assert "ingested_at" in df.columns

    @pytest.mark.asyncio
    async def test_ingested_at_is_datetime(self):
        with patch("src.ingestion.sap_log_fetcher.settings") as mock_settings:
            mock_settings.mock_api = True
            df = await fetch_logs()
        if not df.empty:
            val = df["ingested_at"].iloc[0]
            from datetime import datetime
            assert isinstance(val, datetime)


def _row(ip: str = "10.0.0.1") -> dict:
    return {
        "datetime": "2026-04-26T17:00:00Z",
        "source_ip": ip,
        "status": "200",
        "event_description": "GET /healthz",
    }


def _logs_page(page: int, total_pages: int, n_rows: int = 2) -> dict:
    return {
        "request_time_utc": "2026-04-26T17:01:00+00:00",
        "window_start": "2026-04-26T17:00:00+00:00",
        "window_end": "2026-04-26T17:30:00+00:00",
        "total_records": total_pages * n_rows,
        "batch_size": 500,
        "current_page": page,
        "total_pages": total_pages,
        "records_in_page": n_rows,
        "data": [_row(f"10.0.0.{page * 10 + i}") for i in range(n_rows)],
    }


def _info(total_pages: int, window_start: str = "2026-04-26T17:00:00+00:00") -> dict:
    return {
        "batch_size": 500,
        "window_start": window_start,
        "window_end": "2026-04-26T17:30:00+00:00",
        "total_records": total_pages * 2,
        "total_pages": total_pages,
    }


class TestFetchAllLogsSpecCompliance:
    """fetch_all_logs must drive pagination from /info.total_pages."""

    @pytest.fixture(autouse=True)
    def _reset_window(self):
        sap_log_fetcher._last_window_start = None
        yield
        sap_log_fetcher._last_window_start = None

    @pytest.mark.asyncio
    async def test_uses_total_pages_from_info(self):
        responses = [_info(total_pages=3), _logs_page(1, 3), _logs_page(2, 3), _logs_page(3, 3)]
        get_mock = AsyncMock(side_effect=responses)
        with patch("src.ingestion.sap_log_fetcher.settings") as s, patch(
            "src.ingestion.sap_log_fetcher._get_with_retry", get_mock
        ):
            s.mock_api = False
            s.sap_api_url = "https://api.test"
            s.sap_api_key = "tok"
            df = await fetch_all_logs()
        assert get_mock.await_count == 4  # 1x /info + 3x /logs/current
        assert len(df) == 6  # 3 pages * 2 rows

    @pytest.mark.asyncio
    async def test_does_not_send_page_size_param(self):
        """Spec: clients send only `page`. Server controls batch size."""
        responses = [_info(total_pages=1), _logs_page(1, 1)]
        get_mock = AsyncMock(side_effect=responses)
        with patch("src.ingestion.sap_log_fetcher.settings") as s, patch(
            "src.ingestion.sap_log_fetcher._get_with_retry", get_mock
        ):
            s.mock_api = False
            s.sap_api_url = "https://api.test"
            s.sap_api_key = "tok"
            await fetch_all_logs()
        page_call = get_mock.await_args_list[1]
        params = page_call.kwargs["params"]
        assert "page_size" not in params
        assert params == {"page": 1}

    @pytest.mark.asyncio
    async def test_503_on_info_returns_empty(self):
        get_mock = AsyncMock(return_value=None)  # non-fatal 503 short-circuit
        with patch("src.ingestion.sap_log_fetcher.settings") as s, patch(
            "src.ingestion.sap_log_fetcher._get_with_retry", get_mock
        ):
            s.mock_api = False
            s.sap_api_url = "https://api.test"
            s.sap_api_key = "tok"
            df = await fetch_all_logs()
        assert df.empty
        assert get_mock.await_count == 1  # only /info called

    @pytest.mark.asyncio
    async def test_422_mid_loop_breaks_gracefully(self):
        """If a page 422s mid-loop (e.g., window rolled), keep what we have."""
        responses = [_info(total_pages=3), _logs_page(1, 3), _logs_page(2, 3), None]
        get_mock = AsyncMock(side_effect=responses)
        with patch("src.ingestion.sap_log_fetcher.settings") as s, patch(
            "src.ingestion.sap_log_fetcher._get_with_retry", get_mock
        ):
            s.mock_api = False
            s.sap_api_url = "https://api.test"
            s.sap_api_key = "tok"
            df = await fetch_all_logs()
        assert len(df) == 4  # pages 1+2 only

    @pytest.mark.asyncio
    async def test_skip_on_duplicate_window(self):
        """Same window_start → no /logs/current calls."""
        sap_log_fetcher._last_window_start = "2026-04-26T17:00:00+00:00"
        get_mock = AsyncMock(return_value=_info(total_pages=3))
        with patch("src.ingestion.sap_log_fetcher.settings") as s, patch(
            "src.ingestion.sap_log_fetcher._get_with_retry", get_mock
        ):
            s.mock_api = False
            s.sap_api_url = "https://api.test"
            s.sap_api_key = "tok"
            df = await fetch_all_logs()
        assert df.empty
        assert get_mock.await_count == 1  # only /info


class TestGetWithRetryNonFatalStatuses:
    @pytest.mark.asyncio
    async def test_returns_none_on_non_fatal_status(self):
        """Status codes in non_fatal_statuses short-circuit to None, no raise."""
        from unittest.mock import MagicMock

        response = MagicMock()
        response.status_code = 503
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=response
        )
        client = MagicMock()
        client.get = AsyncMock(return_value=response)
        with patch("src.ingestion.sap_log_fetcher._get_client", return_value=client):
            result = await sap_log_fetcher._get_with_retry(
                url="https://api.test/info",
                headers={},
                params={},
                non_fatal_statuses=(503,),
            )
        assert result is None
