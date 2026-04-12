"""
test_ingestion.py
-----------------
Unit tests for the SAP log fetcher and parser.
Owner: Data Architect & Backend Developer
"""

import pytest
import pandas as pd
from unittest.mock import patch, AsyncMock

from src.ingestion.sap_log_fetcher import _fetch_mock_logs, fetch_logs


class TestMockFetcher:
    def test_mock_logs_returns_dataframe(self):
        df = _fetch_mock_logs()
        assert isinstance(df, pd.DataFrame)

    def test_mock_logs_has_expected_columns(self):
        df = _fetch_mock_logs()
        expected_cols = ["datetime", "source_ip", "event_description", "status"]
        for col in expected_cols:
            assert col in df.columns, f"Missing column: {col}"

    def test_mock_logs_not_empty(self):
        df = _fetch_mock_logs()
        assert len(df) > 0


class TestFetchLogs:
    @pytest.mark.asyncio
    async def test_fetch_logs_mock_mode(self):
        """In mock mode (no SAP_API_URL), should return mock data."""
        df = await fetch_logs()
        assert isinstance(df, pd.DataFrame)

    # TODO: Add real API tests after April 13
    # @pytest.mark.asyncio
    # async def test_fetch_logs_real_api(self):
    #     ...
