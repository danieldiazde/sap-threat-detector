"""
pipeline.py
-----------
Full OBSERVE → ANALYZE → DETECT → RESPOND orchestrator.

``Pipeline.run_once`` executes a single pass: fetch → features → predict →
alert → store. ``Pipeline.run_forever`` loops with exponential back-off on
transient errors and stops cleanly on SIGTERM / ``stop_event``.

Used by:
- ``src/api/main.py`` — as a background task in the FastAPI lifespan
- ``scripts/run_pipeline_local.py`` — standalone local driver

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import asyncio
import signal
from datetime import datetime
from typing import Any

import pandas as pd

from src.alerting.incident_report import build_incident_report, write_report
from src.alerting.sap_webhook import send_alert
from src.common.config import settings
from src.common.logging import get_logger
from src.common.metrics import metrics
from src.common.time_utils import utcnow
from src.ingestion.sap_log_fetcher import fetch_all_logs
from src.model.features import extract_features
from src.model.predict import anomalies_only, predict
from src.storage.repositories import anomaly_repository, log_repository

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

BACKOFF_BASE: float = 2.0
BACKOFF_MAX: float = 60.0
BACKOFF_RESET_AFTER_SUCCESS: bool = True


class Pipeline:
    """End-to-end detection pipeline with graceful shutdown."""

    def __init__(self, *, stop_event: asyncio.Event | None = None) -> None:
        self._stop = stop_event or asyncio.Event()
        self._consecutive_errors: int = 0

    # ── Single pass ──────────────────────────────────────────────────

    async def run_once(self) -> dict[str, Any]:
        """
        Execute one pipeline cycle. Returns a summary dict.

        Raises on unrecoverable errors so the caller can decide whether to
        abort or retry.
        """
        ingested_at = utcnow()

        # OBSERVE
        df = await fetch_all_logs()
        if df.empty:
            logger.info("pipeline.run_once.no_data")
            metrics.incr_pipeline_runs()
            return {"status": "no_data", "logs": 0}

        metrics.incr_logs_processed(len(df))
        await log_repository.insert_logs(df, ingested_at)

        # ANALYZE
        features_df = extract_features(df)
        if features_df.empty:
            logger.info("pipeline.run_once.no_features")
            metrics.incr_pipeline_runs()
            return {"status": "no_features", "logs": len(df)}

        # DETECT
        batch_min_log_time = _earliest_log_time(df)
        scored = predict(features_df, ingested_at=ingested_at, batch_min_log_time=batch_min_log_time)
        anomalies = anomalies_only(scored)

        anomaly_count = len(anomalies)
        metrics.incr_anomalies(anomaly_count)

        # RESPOND
        alerts_sent = 0
        for _, row in anomalies.iterrows():
            anomaly_dict = row.to_dict()
            evidence = _evidence_for_ip(df, str(anomaly_dict.get("source_ip", "")))

            # Generate incident report for high-severity
            report_path: str | None = None
            if str(anomaly_dict.get("threat_level", "")).lower() == "high":
                report_md = build_incident_report(anomaly_dict, evidence, metrics.snapshot())
                incident_id = f"INC-{utcnow().strftime('%Y%m%dT%H%M%S')}-{str(anomaly_dict.get('source_ip', 'unknown')).replace('.', '-')}"
                path = write_report(report_md, incident_id)
                report_path = str(path)
                anomaly_dict["incident_report_path"] = report_path

            sent = await send_alert(anomaly_dict, evidence)
            anomaly_dict["webhook_sent"] = sent
            if sent:
                alerts_sent += 1

            await anomaly_repository.insert_anomaly(anomaly_dict)

        metrics.incr_pipeline_runs()

        summary = {
            "status": "ok",
            "logs": len(df),
            "features": len(features_df),
            "anomalies": anomaly_count,
            "alerts_sent": alerts_sent,
            "pipeline_mttd_ms": int(scored["pipeline_mttd_ms"].mean()) if not scored.empty else 0,
        }
        logger.info("pipeline.run_once.done", extra=summary)
        return summary

    # ── Continuous loop ──────────────────────────────────────────────

    async def run_forever(self) -> None:
        """
        Loop ``run_once`` with ``settings.poll_interval_seconds`` between
        cycles. Uses exponential back-off after consecutive errors and
        resets on success.
        """
        _install_signal_handlers(self._stop)
        interval = settings.poll_interval_seconds
        logger.info(
            "pipeline.run_forever.start",
            extra={"interval_s": interval, "mock_api": settings.mock_api},
        )

        while not self._stop.is_set():
            try:
                await self.run_once()
                self._consecutive_errors = 0
            except Exception as exc:
                self._consecutive_errors += 1
                delay = min(
                    BACKOFF_BASE ** self._consecutive_errors, BACKOFF_MAX
                )
                metrics.incr_errors(str(exc))
                logger.error(
                    "pipeline.run_forever.error",
                    extra={
                        "error": str(exc),
                        "consecutive": self._consecutive_errors,
                        "backoff_s": delay,
                    },
                )
                await _interruptible_sleep(delay, self._stop)
                continue

            await _interruptible_sleep(interval, self._stop)

        logger.info("pipeline.run_forever.stopped")

    # ── Control ──────────────────────────────────────────────────────

    def request_stop(self) -> None:
        """Signal the loop to stop after the current cycle."""
        self._stop.set()

    @property
    def is_running(self) -> bool:
        return not self._stop.is_set()


# ─── Helpers ──────────────────────────────────────────────────────────────


def _earliest_log_time(df: pd.DataFrame) -> datetime | None:
    if "datetime" not in df.columns:
        return None
    parsed = pd.to_datetime(df["datetime"], errors="coerce", utc=True)
    valid = parsed.dropna()
    if valid.empty:
        return None
    return valid.min().to_pydatetime()


def _evidence_for_ip(df: pd.DataFrame, source_ip: str) -> pd.DataFrame:
    if source_ip and "source_ip" in df.columns:
        return df[df["source_ip"] == source_ip].head(10)
    return df.head(10)


async def _interruptible_sleep(seconds: float, stop: asyncio.Event) -> None:
    """Sleep that wakes early if *stop* is set."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


def _install_signal_handlers(stop: asyncio.Event) -> None:
    """Register SIGTERM / SIGINT handlers to set the stop event."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
