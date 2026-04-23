"""
test_ingestion.py
-----------------
Unit tests for the SAP log fetcher.
"""

from __future__ import annotations
from unittest.mock import patch

import pandas as pd
import pytest
from src.ingestion.sap_log_fetcher import _fetch_mock_logs, fetch_logs


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
