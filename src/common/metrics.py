"""
metrics.py
----------
In-process metrics registry surfaced by the FastAPI ``/metrics`` endpoint.

This is deliberately not Prometheus — a hackathon CF deployment doesn't have
a scrape target, and we want the dashboard to be able to pull JSON directly.
All state is in a single thread-safe singleton.

Critical metrics (MTTD is 40% of the grade):
- ``pipeline_mttd_ms``  — detected_at - ingested_at, what we control
- ``e2e_mttd_ms``       — detected_at - log.datetime, what judges will ask about

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import statistics
import threading
from collections import deque
from datetime import datetime
from typing import Any

from src.common.time_utils import iso, utcnow

# ─── Constants ─────────────────────────────────────────────────────────────

MTTD_SAMPLE_WINDOW: int = 500  # Rolling window size for percentile computation.


class MetricsRegistry:
    """Thread-safe in-process counters + rolling MTTD samples."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at: datetime = utcnow()

        # Counters
        self.logs_processed_total: int = 0
        self.anomalies_detected_total: int = 0
        self.alerts_sent_total: int = 0
        self.alerts_failed_total: int = 0
        self.alerts_suppressed_total: int = 0
        self.pipeline_runs_total: int = 0
        self.errors_total: int = 0

        # Rolling samples
        self._pipeline_mttd_ms: deque[int] = deque(maxlen=MTTD_SAMPLE_WINDOW)
        self._e2e_mttd_ms: deque[int] = deque(maxlen=MTTD_SAMPLE_WINDOW)

        self.last_run_at: datetime | None = None
        self.last_error: str | None = None

    # ── Counter operations ────────────────────────────────────────────

    def incr_logs_processed(self, n: int = 1) -> None:
        with self._lock:
            self.logs_processed_total += n

    def incr_anomalies(self, n: int = 1) -> None:
        with self._lock:
            self.anomalies_detected_total += n

    def incr_alerts_sent(self, n: int = 1) -> None:
        with self._lock:
            self.alerts_sent_total += n

    def incr_alerts_failed(self, n: int = 1) -> None:
        with self._lock:
            self.alerts_failed_total += n

    def incr_alerts_suppressed(self, n: int = 1) -> None:
        with self._lock:
            self.alerts_suppressed_total += n

    def incr_pipeline_runs(self, n: int = 1) -> None:
        with self._lock:
            self.pipeline_runs_total += n
            self.last_run_at = utcnow()

    def incr_errors(self, message: str) -> None:
        with self._lock:
            self.errors_total += 1
            self.last_error = message

    # ── MTTD observations ─────────────────────────────────────────────

    def observe_pipeline_mttd(self, millis: int) -> None:
        with self._lock:
            self._pipeline_mttd_ms.append(max(millis, 0))

    def observe_e2e_mttd(self, millis: int) -> None:
        with self._lock:
            self._e2e_mttd_ms.append(max(millis, 0))

    # ── Read helpers ──────────────────────────────────────────────────

    @staticmethod
    def _percentile(samples: list[int], p: float) -> float:
        if not samples:
            return 0.0
        # statistics.quantiles needs n>=2; short-circuit for n==1.
        if len(samples) == 1:
            return float(samples[0])
        quantiles = statistics.quantiles(samples, n=100, method="inclusive")
        index = min(max(int(p) - 1, 0), len(quantiles) - 1)
        return float(quantiles[index])

    def snapshot(self) -> dict[str, Any]:
        """Return a plain-dict snapshot suitable for JSON serialization."""
        with self._lock:
            pipeline_samples = list(self._pipeline_mttd_ms)
            e2e_samples = list(self._e2e_mttd_ms)
            return {
                "started_at": iso(self._started_at),
                "last_run_at": iso(self.last_run_at) if self.last_run_at else None,
                "counters": {
                    "logs_processed_total": self.logs_processed_total,
                    "anomalies_detected_total": self.anomalies_detected_total,
                    "alerts_sent_total": self.alerts_sent_total,
                    "alerts_failed_total": self.alerts_failed_total,
                    "alerts_suppressed_total": self.alerts_suppressed_total,
                    "pipeline_runs_total": self.pipeline_runs_total,
                    "errors_total": self.errors_total,
                },
                "pipeline_mttd_ms": {
                    "count": len(pipeline_samples),
                    "p50": self._percentile(pipeline_samples, 50),
                    "p95": self._percentile(pipeline_samples, 95),
                    "max": max(pipeline_samples) if pipeline_samples else 0,
                },
                "e2e_mttd_ms": {
                    "count": len(e2e_samples),
                    "p50": self._percentile(e2e_samples, 50),
                    "p95": self._percentile(e2e_samples, 95),
                    "max": max(e2e_samples) if e2e_samples else 0,
                },
                "last_error": self.last_error,
            }

    def reset(self) -> None:
        """Reset all counters. Used by tests — avoid calling in production."""
        with self._lock:
            self._started_at = utcnow()
            self.logs_processed_total = 0
            self.anomalies_detected_total = 0
            self.alerts_sent_total = 0
            self.alerts_failed_total = 0
            self.alerts_suppressed_total = 0
            self.pipeline_runs_total = 0
            self.errors_total = 0
            self._pipeline_mttd_ms.clear()
            self._e2e_mttd_ms.clear()
            self.last_run_at = None
            self.last_error = None


# Module-level singleton. Import as: ``from src.common.metrics import metrics``.
metrics: MetricsRegistry = MetricsRegistry()
