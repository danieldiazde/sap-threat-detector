"""Unit tests for src/common/time_utils.py."""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from src.common.time_utils import elapsed_ms, iso, parse_log_datetime, utcnow


class TestUtcnow:
    def test_returns_tz_aware(self):
        now = utcnow()
        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc


class TestIso:
    def test_naive_datetime(self):
        dt = datetime(2026, 4, 4, 14, 0, 0)
        result = iso(dt)
        assert result.endswith("Z")
        assert "2026-04-04" in result

    def test_utc_datetime(self):
        dt = datetime(2026, 4, 4, 14, 0, 0, tzinfo=timezone.utc)
        assert iso(dt) == "2026-04-04T14:00:00Z"


class TestParseLogDatetime:
    def test_iso_string(self):
        result = parse_log_datetime("2026-04-04T14:45:01Z")
        assert result is not None
        assert result.tzinfo is not None

    def test_sap_csv_format(self):
        result = parse_log_datetime("2026-04-04 14:45:01")
        assert result is not None
        assert result.year == 2026

    def test_pandas_timestamp(self):
        ts = pd.Timestamp("2026-04-04 14:45:01")
        result = parse_log_datetime(ts)
        assert isinstance(result, datetime)

    def test_none_returns_none(self):
        assert parse_log_datetime(None) is None

    def test_nan_returns_none(self):
        assert parse_log_datetime(float("nan")) is None


class TestElapsedMs:
    def test_positive_delta(self):
        start = datetime(2026, 4, 4, 14, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 4, 4, 14, 0, 1, tzinfo=timezone.utc)
        assert elapsed_ms(start, end) == 1000

    def test_negative_delta_returns_zero(self):
        start = datetime(2026, 4, 4, 14, 0, 1, tzinfo=timezone.utc)
        end = datetime(2026, 4, 4, 14, 0, 0, tzinfo=timezone.utc)
        assert elapsed_ms(start, end) == 0

    def test_naive_datetimes(self):
        start = datetime(2026, 4, 4, 14, 0, 0)
        end = datetime(2026, 4, 4, 14, 0, 0, 500_000)
        assert elapsed_ms(start, end) == 500
