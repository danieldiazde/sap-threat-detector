"""Unit tests for src/common/metrics.py."""

from __future__ import annotations

from src.common.metrics import MetricsRegistry


class TestMetricsRegistry:
    def test_initial_counters_zero(self, in_memory_metrics: MetricsRegistry):
        snap = in_memory_metrics.snapshot()
        assert snap["counters"]["logs_processed_total"] == 0
        assert snap["counters"]["anomalies_detected_total"] == 0

    def test_incr_logs_processed(self, in_memory_metrics: MetricsRegistry):
        in_memory_metrics.incr_logs_processed(10)
        in_memory_metrics.incr_logs_processed(5)
        snap = in_memory_metrics.snapshot()
        assert snap["counters"]["logs_processed_total"] == 15

    def test_incr_anomalies(self, in_memory_metrics: MetricsRegistry):
        in_memory_metrics.incr_anomalies(3)
        assert in_memory_metrics.snapshot()["counters"]["anomalies_detected_total"] == 3

    def test_pipeline_mttd_p50(self, in_memory_metrics: MetricsRegistry):
        for ms in [10, 20, 30, 40, 50]:
            in_memory_metrics.observe_pipeline_mttd(ms)
        snap = in_memory_metrics.snapshot()
        assert snap["pipeline_mttd_ms"]["p50"] == 30.0

    def test_pipeline_mttd_p95(self, in_memory_metrics: MetricsRegistry):
        for ms in range(1, 101):
            in_memory_metrics.observe_pipeline_mttd(ms)
        snap = in_memory_metrics.snapshot()
        assert snap["pipeline_mttd_ms"]["p95"] >= 90

    def test_e2e_mttd(self, in_memory_metrics: MetricsRegistry):
        in_memory_metrics.observe_e2e_mttd(100)
        snap = in_memory_metrics.snapshot()
        assert snap["e2e_mttd_ms"]["count"] == 1
        assert snap["e2e_mttd_ms"]["p50"] == 100.0

    def test_negative_mttd_clamped(self, in_memory_metrics: MetricsRegistry):
        in_memory_metrics.observe_pipeline_mttd(-50)
        snap = in_memory_metrics.snapshot()
        assert snap["pipeline_mttd_ms"]["max"] == 0

    def test_reset(self, in_memory_metrics: MetricsRegistry):
        in_memory_metrics.incr_logs_processed(100)
        in_memory_metrics.reset()
        assert in_memory_metrics.snapshot()["counters"]["logs_processed_total"] == 0

    def test_last_run_at_updated(self, in_memory_metrics: MetricsRegistry):
        assert in_memory_metrics.snapshot()["last_run_at"] is None
        in_memory_metrics.incr_pipeline_runs()
        assert in_memory_metrics.snapshot()["last_run_at"] is not None

    def test_errors_tracked(self, in_memory_metrics: MetricsRegistry):
        in_memory_metrics.incr_errors("test error")
        snap = in_memory_metrics.snapshot()
        assert snap["counters"]["errors_total"] == 1
        assert snap["last_error"] == "test error"
