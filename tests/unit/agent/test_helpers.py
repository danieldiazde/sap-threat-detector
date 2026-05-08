"""Unit tests for ``src.agent.helpers`` whitelists (§6)."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from src.agent import helpers
from src.agent.helpers import (
    breakdown_by,
    compare_windows,
    correlate,
    time_series,
)


@pytest.fixture
def mock_hana():
    with patch.object(helpers, "settings") as s:
        s.mock_hana = True
        yield


def _run(coro):
    return asyncio.run(coro)


# ─── breakdown_by validation ───────────────────────────────────────────────


def test_breakdown_by_unknown_metric_rejected(mock_hana):
    out = _run(breakdown_by(metric="DROP TABLE", dimension="source_ip", hours=1))
    assert "error" in out
    assert "unknown metric" in out["error"]


def test_breakdown_by_unknown_dimension_rejected(mock_hana):
    out = _run(breakdown_by(metric="anomaly_count", dimension="DROP TABLE", hours=1))
    assert "error" in out
    assert "unknown dimension" in out["error"]


def test_breakdown_by_dimension_table_mismatch_rejected(mock_hana):
    # threat_level lives on ANOMALIES; log_volume's table is SECURITY_LOGS.
    out = _run(breakdown_by(metric="log_volume", dimension="threat_level", hours=1))
    assert "error" in out
    assert "lives on" in out["error"]


def test_breakdown_by_hours_out_of_range_rejected(mock_hana):
    out = _run(breakdown_by(metric="anomaly_count", dimension="source_ip", hours=0))
    assert "error" in out and "hours" in out["error"]
    out = _run(breakdown_by(metric="anomaly_count", dimension="source_ip", hours=10_000))
    assert "error" in out and "hours" in out["error"]


def test_breakdown_by_top_n_out_of_range_rejected(mock_hana):
    out = _run(breakdown_by(metric="anomaly_count", dimension="source_ip", top_n=0))
    assert "error" in out and "top_n" in out["error"]
    out = _run(breakdown_by(metric="anomaly_count", dimension="source_ip", top_n=999))
    assert "error" in out and "top_n" in out["error"]


def test_breakdown_by_valid_returns_mock_shape(mock_hana):
    out = _run(breakdown_by(metric="anomaly_count", dimension="source_ip", hours=24))
    assert out["_render"] == "bar_chart"
    assert out["metric"] == "anomaly_count"
    assert out["dimension"] == "source_ip"
    assert out["hours"] == 24
    assert out.get("_mock") is True


# ─── time_series validation ────────────────────────────────────────────────


def test_time_series_invalid_bucket_rejected(mock_hana):
    out = _run(time_series(metric="anomaly_count", hours=24, bucket_minutes=7))
    assert "error" in out
    assert "bucket_minutes" in out["error"]


def test_time_series_valid_bucket_accepted(mock_hana):
    out = _run(time_series(metric="anomaly_count", hours=24, bucket_minutes=60))
    assert out["_render"] == "line_chart"
    assert out["bucket_minutes"] == 60


# ─── compare_windows validation ────────────────────────────────────────────


def test_compare_windows_unknown_metric_rejected(mock_hana):
    out = _run(compare_windows(metric="bogus", window_a_h=1, window_b_h=24))
    assert "error" in out


def test_compare_windows_valid_mock_zeroes(mock_hana):
    out = _run(compare_windows(metric="anomaly_count", window_a_h=1, window_b_h=24))
    assert out["_render"] == "scalar"
    assert out["window_a"]["hours"] == 1
    assert out["window_b"]["hours"] == 24
    # Mock backend gives no rows -> both windows zero, delta computed safely.
    assert out["window_a"]["value"] == 0
    assert out["window_b"]["value"] == 0
    assert out["delta_abs"] == 0
    assert out["delta_pct"] is None  # divide-by-zero guard


# ─── correlate validation ──────────────────────────────────────────────────


def test_correlate_dimension_must_be_log_side(mock_hana):
    # threat_level lives on ANOMALIES; correlate is SECURITY_LOGS-only.
    out = _run(correlate(dim_a="source_ip", dim_b="threat_level", hours=24))
    assert "error" in out


def test_correlate_rejects_same_dimension(mock_hana):
    out = _run(correlate(dim_a="source_ip", dim_b="source_ip", hours=24))
    assert "error" in out
    assert "must differ" in out["error"]


def test_correlate_valid_returns_table(mock_hana):
    out = _run(correlate(dim_a="source_ip", dim_b="log_type", hours=24, top_n=10))
    assert out["_render"] == "table"
    assert out["dim_a"] == "source_ip"
    assert out["dim_b"] == "log_type"


# ─── No SQL injection via whitelisted enums ────────────────────────────────


def test_breakdown_by_injection_attempt_blocked_before_sql(mock_hana):
    # The validator runs before any SQL is built. We assert the dimension
    # whitelist rejects the payload string.
    out = _run(breakdown_by(
        metric="anomaly_count",
        dimension="source_ip; DROP TABLE ANOMALIES;--",
        hours=1,
    ))
    assert "error" in out
    assert "unknown dimension" in out["error"]
