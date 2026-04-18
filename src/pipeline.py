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
import contextlib
import signal
from datetime import datetime
from typing import Any

import pandas as pd
from src.alerting.deduplication import deduper
from src.alerting.incident_report import build_incident_report, write_report
from src.alerting.sap_webhook import build_alert_id, send_alert
from src.common.config import settings
from src.common.logging import get_logger
from src.common.metrics import metrics
from src.common.time_utils import utcnow
from src.ingestion.sap_log_fetcher import fetch_all_logs
from src.model.features import extract_features
from src.model.predict import anomalies_only, predict, reset_active_model
from src.storage.repositories import anomaly_repository, log_repository, model_version_repository

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

BACKOFF_BASE: float = 2.0
BACKOFF_MAX: float = 60.0
BACKOFF_RESET_AFTER_SUCCESS: bool = True


RETRAIN_DATA_PATH = "data/samples/sample_logs.csv"
RETRAIN_LOG_BUFFER_MAX_ROWS: int = 50_000  # cap memory usage


class Pipeline:
    """End-to-end detection pipeline with graceful shutdown."""

    def __init__(self, *, stop_event: asyncio.Event | None = None) -> None:
        self._stop = stop_event or asyncio.Event()
        self._consecutive_errors: int = 0
        self._cycle_count: int = 0
        self._log_buffer: list[pd.DataFrame] = []
        self._retraining: bool = False
        self._retrain_task: asyncio.Task | None = None

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

            # Stamp alert_id and dedup_key so they persist to the DB
            anomaly_dict["alert_id"] = build_alert_id(
                str(anomaly_dict.get("source_ip", "")),
                str(anomaly_dict.get("threat_level", "")),
                anomaly_dict.get("detected_at"),
            )
            dedup_tuple = deduper.key_for(anomaly_dict)
            anomaly_dict["dedup_key"] = f"{dedup_tuple[0]}:{dedup_tuple[1]}"

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
        self._cycle_count += 1

        # Accumulate logs for periodic retraining
        self._log_buffer.append(df)

        # Trim buffer so it never exceeds RETRAIN_LOG_BUFFER_MAX_ROWS
        total_buffered = sum(len(d) for d in self._log_buffer)
        while total_buffered > RETRAIN_LOG_BUFFER_MAX_ROWS and len(self._log_buffer) > 1:
            removed = self._log_buffer.pop(0)
            total_buffered -= len(removed)

        # Trigger background retrain every N cycles
        retrain_every = settings.retrain_every_n_cycles
        if self._cycle_count % retrain_every == 0 and not self._retraining:
            self._retrain_task = asyncio.create_task(self._retrain())

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

    async def _retrain(self) -> None:
        """
        Retrain the model in a background thread using accumulated logs.

        Runs via asyncio.to_thread so the detection loop is never paused.
        After training, invalidates the model cache so the next predict()
        call automatically picks up the new model.
        """
        self._retraining = True
        buffered_rows = sum(len(d) for d in self._log_buffer)
        logger.info(
            "pipeline.retrain.start",
            extra={"cycle": self._cycle_count, "buffered_rows": buffered_rows},
        )
        if not self._log_buffer:
            logger.warning("pipeline.retrain.skip_empty_buffer")
            self._retraining = False
            return
        try:
            # Snapshot the buffer (don't hold a reference during the slow train)
            combined = pd.concat(self._log_buffer, ignore_index=True)

            def _do_train() -> dict:
                from pathlib import Path

                from src.model.train import train

                # Save combined logs so train() can read them
                Path(RETRAIN_DATA_PATH).parent.mkdir(parents=True, exist_ok=True)
                combined.to_csv(RETRAIN_DATA_PATH, index=False)

                return train(combined)

            report = await asyncio.to_thread(_do_train)

            # Hot-swap: clear the in-process model cache so next predict()
            # loads the freshly saved model automatically
            reset_active_model()

            # Persist model metadata to HANA MODEL_VERSIONS table
            await model_version_repository.register(report)

            logger.info(
                "pipeline.retrain.done",
                extra={
                    "version": report.get("version_tag"),
                    "samples": report.get("training_samples"),
                    "anomaly_rate": report.get("anomaly_rate"),
                },
            )
        except Exception as exc:
            logger.error("pipeline.retrain.error", extra={"error": str(exc)})
        finally:
            self._retraining = False

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
    with contextlib.suppress(asyncio.TimeoutError, TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


def _install_signal_handlers(stop: asyncio.Event) -> None:
    """Register SIGTERM / SIGINT handlers to set the stop event."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
