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
from src.ingestion.sap_log_fetcher import fetch_all_logs, reset_window_start
from src.model.features import extract_features
from src.model.llm_predict import predict_llm
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

        # Everything after this point uses the fetched data. If any step fails,
        # reset_window_start() un-acknowledges the window so the next 30-second
        # cycle re-fetches it rather than silently skipping it for up to 30 minutes.
        try:
            metrics.incr_logs_processed(len(df))
            await log_repository.insert_logs(df, ingested_at)

            # ANALYZE
            features_df = extract_features(df)
            if features_df.empty:
                logger.info("pipeline.run_once.no_features")
                metrics.incr_pipeline_runs()
                return {"status": "no_features", "logs": len(df)}

            # DETECT — SAP detector (per-source-IP) + LLM detector (per-cohort).
            batch_min_log_time = _earliest_log_time(df)
            sap_scored = predict(features_df, ingested_at=ingested_at, batch_min_log_time=batch_min_log_time)
            sap_anomalies = anomalies_only(sap_scored)
            sap_anomalies = sap_anomalies.assign(detector="sap") if not sap_anomalies.empty else sap_anomalies

            llm_anomalies = _safe_predict_llm(df, ingested_at, batch_min_log_time)

            anomalies = _concat_anomalies(sap_anomalies, llm_anomalies)
            anomaly_count = len(anomalies)
            metrics.incr_anomalies(anomaly_count)

            # RESPOND
            alerts_sent = 0
            for _, row in anomalies.iterrows():
                anomaly_dict = row.to_dict()
                detector = str(anomaly_dict.get("detector") or "sap").lower()
                if detector == "llm":
                    evidence = _evidence_for_cohort(
                        df,
                        str(anomaly_dict.get("llm_model_id", "")),
                        str(anomaly_dict.get("llm_prompt_category", "")),
                    )
                    entity = f"{anomaly_dict.get('llm_model_id', 'unknown')}|{anomaly_dict.get('llm_prompt_category', 'unknown')}"
                else:
                    evidence = _evidence_for_ip(df, str(anomaly_dict.get("source_ip", "")))
                    entity = str(anomaly_dict.get("source_ip", ""))

                # Stamp alert_id and dedup_key so they persist to the DB
                anomaly_dict["alert_id"] = build_alert_id(
                    entity,
                    str(anomaly_dict.get("threat_level", "")),
                    anomaly_dict.get("detected_at"),
                    detector=detector,
                )
                dedup_tuple = deduper.key_for(anomaly_dict)
                anomaly_dict["dedup_key"] = ":".join(dedup_tuple)

                # Generate incident report for high-severity
                report_path: str | None = None
                if str(anomaly_dict.get("threat_level", "")).lower() == "high":
                    report_md = build_incident_report(anomaly_dict, evidence, metrics.snapshot())
                    incident_id = _incident_id_for(anomaly_dict, detector)
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
            # Treat non-positive env values as "disabled" to avoid modulo-by-zero
            # crashes from a copied or partially edited .env file.
            if retrain_every > 0 and self._cycle_count % retrain_every == 0 and not self._retraining:
                self._retrain_task = asyncio.create_task(self._retrain())

            summary = {
                "status": "ok",
                "logs": len(df),
                "features": len(features_df),
                "anomalies": anomaly_count,
                "alerts_sent": alerts_sent,
                "pipeline_mttd_ms": int(sap_scored["pipeline_mttd_ms"].mean()) if not sap_scored.empty else 0,
                "llm_anomalies": int(len(llm_anomalies)),
            }
            logger.info("pipeline.run_once.done", extra=summary)
            return summary

        except Exception:
            reset_window_start()
            raise

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

                from src.model.train import train_split

                Path(RETRAIN_DATA_PATH).parent.mkdir(parents=True, exist_ok=True)
                combined.to_csv(RETRAIN_DATA_PATH, index=False)

                # train_split handles extract_features + legacy/modern split.
                # Returns {"legacy": <report>, "modern": <report>}.
                return train_split(combined)

            reports = await asyncio.to_thread(_do_train)

            # Hot-swap: clear the in-process model cache so next predict()
            # loads the freshly saved models automatically
            reset_active_model()

            # Persist both model metadata records to HANA MODEL_VERSIONS table
            for report in reports.values():
                await model_version_repository.register(report)

            logger.info(
                "pipeline.retrain.done",
                extra={
                    "splits": list(reports.keys()),
                    "versions": {k: v.get("version_tag") for k, v in reports.items()},
                    "samples": {k: v.get("training_samples") for k, v in reports.items()},
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


def _evidence_for_cohort(df: pd.DataFrame, model_id: str, category: str) -> pd.DataFrame:
    """Pull up to 10 rows for the (model_id, prompt_category) cohort, prioritizing
    the most-suspicious ones (errors / timeouts / high cost)."""
    if df is None or df.empty:
        return df
    if "llm_model_id" not in df.columns or "llm_prompt_category" not in df.columns:
        return df.head(10)
    mask = (df["llm_model_id"].astype(str) == model_id) & (
        df["llm_prompt_category"].astype(str) == category
    )
    cohort = df[mask]
    if cohort.empty:
        return cohort
    if "llm_status" in cohort.columns:
        suspicious_mask = ~cohort["llm_status"].astype(str).str.lower().isin(["success", "ok", "200"])
        suspicious = cohort[suspicious_mask]
        if not suspicious.empty:
            return suspicious.head(10)
    return cohort.head(10)


def _safe_predict_llm(
    df: pd.DataFrame, ingested_at: datetime, batch_min_log_time: datetime | None
) -> pd.DataFrame:
    """Run LLM detector; on failure log and return empty rather than killing the cycle."""
    try:
        return predict_llm(df, ingested_at=ingested_at, batch_min_log_time=batch_min_log_time)
    except Exception as exc:
        logger.warning("pipeline.llm_predict.skipped", extra={"error": str(exc)})
        return pd.DataFrame()


def _concat_anomalies(sap_df: pd.DataFrame, llm_df: pd.DataFrame) -> pd.DataFrame:
    """Concat SAP + LLM anomaly frames, preserving union of columns."""
    frames = [d for d in (sap_df, llm_df) if d is not None and not d.empty]
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True, sort=False)


def _incident_id_for(anomaly_dict: dict, detector: str) -> str:
    ts = utcnow().strftime("%Y%m%dT%H%M%S")
    if detector == "llm":
        model = str(anomaly_dict.get("llm_model_id", "unknown")).replace("/", "-")
        category = str(anomaly_dict.get("llm_prompt_category", "unknown")).replace("/", "-")
        return f"INC-LLM-{ts}-{model}-{category}"
    ip = str(anomaly_dict.get("source_ip", "unknown")).replace(".", "-")
    return f"INC-{ts}-{ip}"


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
