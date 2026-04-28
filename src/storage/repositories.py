"""
repositories.py
---------------
Data-access classes for the three HANA tables.

Each repository has:
- a real HANA implementation that uses :mod:`src.storage.pool` with
  ``executemany`` batch inserts, and
- an in-memory fallback that kicks in automatically when
  ``settings.mock_hana`` is true — writes go to a plain list so the
  pipeline / dashboard / tests can run end-to-end without a live HANA
  instance.

Owner: Data Architect & Backend Developer
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import pandas as pd
from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow
from src.storage.pool import HanaPool, pool

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

LOG_INSERT_BATCH_SIZE: int = 500


def _to_int_or_none(v: object) -> int | None:
    try:
        return int(float(v)) if v is not None and str(v).strip() else None  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


def _to_float_or_none(v: object) -> float | None:
    try:
        return float(v) if v is not None and str(v).strip() else None  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


class LogRepository:
    """Persist and query raw security logs."""

    def __init__(self, hana_pool: HanaPool | None = None) -> None:
        self._pool = hana_pool or pool
        # In-memory fallback (mock mode + tests). Capped at 10k rows.
        self._memory: list[dict[str, Any]] = []
        self._memory_cap: int = 10_000

    async def insert_logs(self, df: pd.DataFrame, ingested_at: datetime) -> int:
        """
        Persist a batch of logs. Returns number of rows written.

        Uses ``executemany`` with ``LOG_INSERT_BATCH_SIZE`` chunks for speed.
        LLM telemetry rows (null/blank source_ip) are skipped — SOURCE_IP is
        NOT NULL in SECURITY_LOGS and LLM rows carry no network identity.
        """
        if df.empty:
            return 0

        # LLM rows have no source_ip; SECURITY_LOGS.SOURCE_IP is NOT NULL.
        # Filter them out before building records to avoid constraint violations.
        if "source_ip" in df.columns:
            llm_mask = df["source_ip"].isna() | (df["source_ip"].astype(str).str.strip() == "")
            skipped = int(llm_mask.sum())
            if skipped:
                logger.info(
                    "log_repo.skip_null_source_ip",
                    extra={"skipped": skipped, "total": len(df)},
                )
            df = df[~llm_mask]

        if df.empty:
            return 0

        records = df.to_dict(orient="records")
        for record in records:
            record["ingested_at"] = ingested_at

        if settings.mock_hana:
            self._memory.extend(records)
            # Keep the in-memory store bounded.
            if len(self._memory) > self._memory_cap:
                self._memory = self._memory[-self._memory_cap :]
            logger.debug("log_repo.memory_insert", extra={"rows": len(records)})
            return len(records)

        async with self._pool.acquire() as conn:
            if conn is None:
                return 0
            await asyncio.to_thread(self._bulk_insert_sync, conn, records)

        logger.info("log_repo.hana_insert", extra={"rows": len(records)})
        return len(records)

    async def recent_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent logs (newest first)."""
        if settings.mock_hana:
            return list(reversed(self._memory[-limit:]))

        async with self._pool.acquire() as conn:
            if conn is None:
                return []
            return await asyncio.to_thread(self._query_recent_sync, conn, limit)

    # ── Internal sync helpers (run in executor) ──────────────────────

    @staticmethod
    def _row_tuple(r: dict[str, Any]) -> tuple:
        log_id = r.get("log_id")
        return (
            (str(log_id) if log_id is not None and str(log_id).strip() else None),
            r.get("datetime"),
            r.get("source_ip"),
            r.get("port_service"),
            r.get("event_description"),
            r.get("status"),
            r.get("log_type"),
            r.get("request_path"),
            r.get("sap_application"),
            r.get("region_code"),
            r.get("macro_region"),
            r.get("http_method"),
            r.get("sap_source_type"),
            r.get("sap_app_env"),
            _to_int_or_none(r.get("llm_total_tokens")),
            _to_float_or_none(r.get("llm_cost_usd")),
            r.get("llm_finish_reason"),
            r.get("llm_status"),
            _to_float_or_none(r.get("llm_response_time_ms")),
            r.get("llm_prompt_category"),
            r.get("llm_error_message"),
            r.get("llm_model_id"),
            _to_int_or_none(r.get("llm_prompt_tokens")),
            r.get("ingested_at"),
        )

    _INSERT_SQL: str = """
        INSERT INTO SECURITY_LOGS
        (LOG_ID, DATETIME, SOURCE_IP, PORT_SERVICE, EVENT_DESCRIPTION,
         STATUS, LOG_TYPE, REQUEST_PATH, SAP_APPLICATION,
         REGION_CODE, MACRO_REGION, HTTP_METHOD,
         SAP_SOURCE_TYPE, SAP_APP_ENV,
         LLM_TOTAL_TOKENS, LLM_COST_USD, LLM_FINISH_REASON,
         LLM_STATUS, LLM_RESPONSE_TIME_MS, LLM_PROMPT_CATEGORY,
         LLM_ERROR_MESSAGE, LLM_MODEL_ID, LLM_PROMPT_TOKENS,
         INGESTED_AT)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    # HANA error fragments that indicate a duplicate LOG_ID — silenced (info-level)
    # since the UNIQUE index is doing its job. Anything else still surfaces as an error.
    _UNIQUE_VIOLATION_HINTS: tuple[str, ...] = (
        "unique constraint",
        "uniqueness violation",
        "duplicate key",
    )

    def _bulk_insert_sync(self, conn: Any, records: list[dict[str, Any]]) -> None:
        rows = [self._row_tuple(r) for r in records]
        cursor = conn.cursor()
        try:
            for i in range(0, len(rows), LOG_INSERT_BATCH_SIZE):
                chunk = rows[i : i + LOG_INSERT_BATCH_SIZE]
                try:
                    cursor.executemany(self._INSERT_SQL, chunk)
                except Exception as chunk_exc:
                    # One bad row poisons the chunk — fall back to row-by-row
                    # so the rest of the chunk is not lost.
                    logger.warning(
                        "log_repo.chunk_fallback",
                        extra={"chunk_start": i, "error": str(chunk_exc)},
                    )
                    for row in chunk:
                        try:
                            cursor.execute(self._INSERT_SQL, row)
                        except Exception as row_exc:
                            msg = str(row_exc).lower()
                            if any(h in msg for h in self._UNIQUE_VIOLATION_HINTS):
                                # Duplicate LOG_ID — the dedup index is working.
                                logger.info(
                                    "log_repo.dedup_skip",
                                    extra={"log_id": row[0], "source_ip": row[2]},
                                )
                            else:
                                logger.error(
                                    "log_repo.row_skip",
                                    extra={"source_ip": row[2], "error": str(row_exc)},
                                )
            conn.commit()
        finally:
            cursor.close()

    @staticmethod
    def _query_recent_sync(conn: Any, limit: int) -> list[dict[str, Any]]:
        cursor = conn.cursor()
        try:
            cursor.execute(
                f"""
                SELECT TOP {int(limit)} DATETIME, SOURCE_IP, PORT_SERVICE,
                             EVENT_DESCRIPTION, STATUS, LOG_TYPE, INGESTED_AT
                FROM SECURITY_LOGS
                ORDER BY INGESTED_AT DESC
                """,
            )
            cols = [d[0].lower() for d in cursor.description]
            return [dict(zip(cols, row, strict=False)) for row in cursor.fetchall()]
        finally:
            cursor.close()


class AnomalyRepository:
    """Persist and query detected anomalies."""

    def __init__(self, hana_pool: HanaPool | None = None) -> None:
        self._pool = hana_pool or pool
        self._memory: list[dict[str, Any]] = []
        self._memory_cap: int = 2_000

    async def insert_anomaly(self, anomaly: dict[str, Any]) -> None:
        """Persist a single anomaly row."""
        record = dict(anomaly)
        record.setdefault("created_at", utcnow())

        if settings.mock_hana:
            self._memory.append(record)
            if len(self._memory) > self._memory_cap:
                self._memory = self._memory[-self._memory_cap :]
            logger.debug(
                "anomaly_repo.memory_insert",
                extra={"source_ip": record.get("source_ip"), "level": record.get("threat_level")},
            )
            return

        async with self._pool.acquire() as conn:
            if conn is None:
                return
            await asyncio.to_thread(self._insert_sync, conn, record)

    async def recent_anomalies(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent anomalies (newest first)."""
        if settings.mock_hana:
            return list(reversed(self._memory[-limit:]))

        async with self._pool.acquire() as conn:
            if conn is None:
                return []
            return await asyncio.to_thread(self._query_recent_sync, conn, limit)

    async def mttd_samples(self, window_minutes: int = 60) -> list[int]:
        """
        Return the pipeline_mttd_ms values from the last *window_minutes*.

        Used by the dashboard to render MTTD distribution charts.
        """
        if settings.mock_hana:
            cutoff = utcnow().timestamp() - window_minutes * 60
            return [
                int(r["pipeline_mttd_ms"])
                for r in self._memory
                if r.get("pipeline_mttd_ms") is not None
                and r.get("detected_at")
                and _timestamp_of(r["detected_at"]) >= cutoff
            ]
        async with self._pool.acquire() as conn:
            if conn is None:
                return []
            return await asyncio.to_thread(self._query_mttd_sync, conn, window_minutes)

    # ── Internal sync helpers ────────────────────────────────────────

    @staticmethod
    def _insert_sync(conn: Any, record: dict[str, Any]) -> None:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO ANOMALIES
                (DETECTED_AT, INGESTED_AT, DETECTOR, SOURCE_IP,
                 LLM_MODEL_ID, LLM_PROMPT_CATEGORY,
                 THREAT_LEVEL, ANOMALY_SCORE,
                 IF_GLOBAL_SCORE, IF_CATEGORY_SCORE, RULE_IDS,
                 TOTAL_REQUESTS, ERROR_RATE, PIPELINE_MTTD_MS, E2E_MTTD_MS,
                 ALERT_ID, DEDUP_KEY, WEBHOOK_SENT, INCIDENT_REPORT_PATH)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.get("detected_at"),
                    record.get("ingested_at"),
                    str(record.get("detector") or "sap"),
                    record.get("source_ip"),
                    record.get("llm_model_id"),
                    record.get("llm_prompt_category"),
                    record.get("threat_level"),
                    float(record.get("anomaly_score", 0) or 0),
                    _to_float_or_none(record.get("if_global_score")),
                    _to_float_or_none(record.get("if_category_score")),
                    record.get("rule_ids"),
                    int(record.get("total_requests", 0) or 0),
                    float(record.get("error_rate", 0) or 0),
                    record.get("pipeline_mttd_ms"),
                    record.get("e2e_mttd_ms"),
                    record.get("alert_id"),
                    record.get("dedup_key"),
                    bool(record.get("webhook_sent", False)),
                    record.get("incident_report_path"),
                ),
            )
            conn.commit()
        finally:
            cursor.close()

    @staticmethod
    def _query_recent_sync(conn: Any, limit: int) -> list[dict[str, Any]]:
        cursor = conn.cursor()
        try:
            cursor.execute(
                f"""
                SELECT TOP {int(limit)} DETECTED_AT, SOURCE_IP, THREAT_LEVEL, ANOMALY_SCORE,
                             TOTAL_REQUESTS, ERROR_RATE, PIPELINE_MTTD_MS, E2E_MTTD_MS,
                             WEBHOOK_SENT, INCIDENT_REPORT_PATH
                FROM ANOMALIES
                ORDER BY DETECTED_AT DESC
                """,
            )
            cols = [d[0].lower() for d in cursor.description]
            return [dict(zip(cols, row, strict=False)) for row in cursor.fetchall()]
        finally:
            cursor.close()

    @staticmethod
    def _query_mttd_sync(conn: Any, window_minutes: int) -> list[int]:
        cursor = conn.cursor()
        try:
            offset_seconds = -(window_minutes * 60)
            cursor.execute(
                """
                SELECT PIPELINE_MTTD_MS FROM ANOMALIES
                WHERE DETECTED_AT >= ADD_SECONDS(CURRENT_TIMESTAMP, ?)
                  AND PIPELINE_MTTD_MS IS NOT NULL
                """,
                (offset_seconds,),
            )
            return [int(row[0]) for row in cursor.fetchall() if row[0] is not None]
        finally:
            cursor.close()


class ModelVersionRepository:
    """Persist trained model metadata."""

    def __init__(self, hana_pool: HanaPool | None = None) -> None:
        self._pool = hana_pool or pool
        self._memory: list[dict[str, Any]] = []

    async def register(self, manifest: dict[str, Any]) -> None:
        """Record a newly trained model version."""
        if settings.mock_hana:
            self._memory.append(dict(manifest))
            logger.debug(
                "model_repo.memory_register",
                extra={"version_tag": manifest.get("version_tag")},
            )
            return

        async with self._pool.acquire() as conn:
            if conn is None:
                return
            await asyncio.to_thread(self._register_sync, conn, manifest)

    @staticmethod
    def _register_sync(conn: Any, manifest: dict[str, Any]) -> None:
        import json

        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO MODEL_VERSIONS
                (VERSION_TAG, MODEL_TYPE, TRAINED_AT, CONTAMINATION, TRAINING_SAMPLES,
                 FEATURE_COLUMNS, HYPERPARAMS, CV_SCORES, IS_ACTIVE, NOTES)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.get("version_tag"),
                    manifest.get("model_type"),
                    manifest.get("trained_at"),
                    float(manifest.get("contamination", 0) or 0),
                    int(manifest.get("training_samples", 0) or 0),
                    json.dumps(manifest.get("feature_columns", [])),
                    json.dumps(manifest.get("hyperparams", {})),
                    json.dumps(manifest.get("cv_scores", {})),
                    bool(manifest.get("is_active", True)),
                    (manifest.get("notes") or "")[:500],
                ),
            )
            conn.commit()
        finally:
            cursor.close()


# ─── Helpers ───────────────────────────────────────────────────────────────


def _timestamp_of(dt: Any) -> float:
    """Coerce a datetime-like to a POSIX timestamp for in-memory filtering."""
    if isinstance(dt, datetime):
        return dt.timestamp()
    try:
        return pd.Timestamp(dt).timestamp()
    except (ValueError, TypeError):
        return 0.0


# Module-level singletons used by the pipeline + API.
log_repository: LogRepository = LogRepository()
anomaly_repository: AnomalyRepository = AnomalyRepository()
model_version_repository: ModelVersionRepository = ModelVersionRepository()
