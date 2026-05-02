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
import math
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
        f = float(v) if v is not None and str(v).strip() else None  # type: ignore[arg-type]
        if f is None or math.isnan(f):
            return None
        return f
    except (ValueError, TypeError):
        return None


def _to_float_or_zero(v: object) -> float:
    """Like _to_float_or_none but maps None/NaN to 0.0 for NOT-NULL columns."""
    f = _to_float_or_none(v)
    return f if f is not None else 0.0


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
            persisted = await asyncio.to_thread(self._bulk_insert_sync, conn, records)

        logger.info(
            "log_repo.hana_insert",
            extra={"rows": persisted, "attempted": len(records)},
        )
        if persisted == 0 and len(records) > 0:
            # Every row in a non-empty batch was rejected. Surface this so
            # the pipeline trips reset_window_start() and re-fetches the
            # window on the next cycle, instead of acknowledging a window
            # that landed nothing in HANA.
            raise RuntimeError(
                f"log_repo.all_rows_rejected attempted={len(records)}"
            )
        return persisted

    async def recent_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent logs (newest first)."""
        if settings.mock_hana:
            return list(reversed(self._memory[-limit:]))

        async with self._pool.acquire() as conn:
            if conn is None:
                return []
            return await asyncio.to_thread(self._query_recent_sync, conn, limit)

    async def count_since(self, hours: int) -> int:
        """Count logs ingested in the last *hours* hours."""
        if settings.mock_hana:
            cutoff = utcnow().timestamp() - hours * 3600
            return sum(
                1 for r in self._memory
                if r.get("ingested_at") and _timestamp_of(r["ingested_at"]) >= cutoff
            )
        async with self._pool.acquire() as conn:
            if conn is None:
                return 0
            return await asyncio.to_thread(self._count_since_sync, conn, hours)

    @staticmethod
    def _count_since_sync(conn: Any, hours: int) -> int:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM SECURITY_LOGS "
                "WHERE INGESTED_AT >= ADD_SECONDS(CURRENT_TIMESTAMP, ?)",
                (-(hours * 3600),),
            )
            row = cursor.fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        finally:
            cursor.close()

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

    # Schema-shape errors. Per-row fallback cannot rescue these — every row in
    # the chunk will fail identically. Re-raise so the pipeline trips
    # reset_window_start() instead of silently dropping the window.
    # Incident 2026-04-28: LOG_ID column missing in prod swallowed ~36h of data.
    _STRUCTURAL_ERROR_HINTS: tuple[str, ...] = (
        "invalid column name",
        "unknown column",
        "column not found",
        "invalid table name",
        "could not find table",
        "table not found",
    )

    def _bulk_insert_sync(self, conn: Any, records: list[dict[str, Any]]) -> int:
        """Insert *records* in chunks. Returns count of persisted rows.

        Re-raises on structural/schema errors so the caller can react —
        per-row fallback is only useful for per-row constraint violations.
        """
        rows = [self._row_tuple(r) for r in records]
        persisted = 0
        cursor = conn.cursor()
        try:
            for i in range(0, len(rows), LOG_INSERT_BATCH_SIZE):
                chunk = rows[i : i + LOG_INSERT_BATCH_SIZE]
                try:
                    cursor.executemany(self._INSERT_SQL, chunk)
                    persisted += len(chunk)
                except Exception as chunk_exc:
                    msg = str(chunk_exc).lower()
                    if any(h in msg for h in self._STRUCTURAL_ERROR_HINTS):
                        logger.error(
                            "log_repo.structural_error",
                            extra={"chunk_start": i, "error": str(chunk_exc)},
                        )
                        raise
                    # One bad row poisons the chunk — fall back to row-by-row
                    # so the rest of the chunk is not lost.
                    logger.warning(
                        "log_repo.chunk_fallback",
                        extra={"chunk_start": i, "error": str(chunk_exc)},
                    )
                    for row in chunk:
                        try:
                            cursor.execute(self._INSERT_SQL, row)
                            persisted += 1
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
        return persisted

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
                    _to_float_or_zero(record.get("anomaly_score")),
                    _to_float_or_none(record.get("if_global_score")),
                    _to_float_or_none(record.get("if_category_score")),
                    record.get("rule_ids"),
                    int(record.get("total_requests", 0) or 0),
                    _to_float_or_zero(record.get("error_rate")),
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

    # ── Agent-facing read methods (added 2026-04-29) ─────────────────────
    # These power src/agent/tools.py via the /agent/tool dispatcher.

    async def count_since(self, hours: int) -> int:
        """Count anomalies detected in the last *hours* hours."""
        if settings.mock_hana:
            cutoff = utcnow().timestamp() - hours * 3600
            return sum(
                1 for r in self._memory
                if r.get("detected_at") and _timestamp_of(r["detected_at"]) >= cutoff
            )
        async with self._pool.acquire() as conn:
            if conn is None:
                return 0
            return await asyncio.to_thread(self._count_since_sync, conn, hours)

    async def top_source_ips(
        self, hours: int = 1, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Top source IPs by anomaly count in the last *hours*.

        Returns ``[{source_ip, count, min_score}]`` sorted by count desc.
        ``min_score`` is the most-negative ANOMALY_SCORE seen for that IP —
        isolation-forest scores are negative and lower means more
        anomalous, so this is "the worst score we saw from this IP".
        """
        if settings.mock_hana:
            cutoff = utcnow().timestamp() - hours * 3600
            agg: dict[str, dict[str, Any]] = {}
            for r in self._memory:
                if not r.get("source_ip"):
                    continue
                if not r.get("detected_at"):
                    continue
                if _timestamp_of(r["detected_at"]) < cutoff:
                    continue
                ip = r["source_ip"]
                bucket = agg.setdefault(
                    ip, {"source_ip": ip, "count": 0, "min_score": None}
                )
                bucket["count"] += 1
                score = _to_float_or_none(r.get("anomaly_score"))
                if score is not None and (
                    bucket["min_score"] is None or score < bucket["min_score"]
                ):
                    bucket["min_score"] = score
            ranked = sorted(agg.values(), key=lambda b: b["count"], reverse=True)
            return ranked[:limit]
        async with self._pool.acquire() as conn:
            if conn is None:
                return []
            return await asyncio.to_thread(
                self._top_source_ips_sync, conn, hours, limit
            )

    @staticmethod
    def _top_source_ips_sync(
        conn: Any, hours: int, limit: int
    ) -> list[dict[str, Any]]:
        cursor = conn.cursor()
        try:
            cursor.execute(
                f"""
                SELECT TOP {int(limit)} SOURCE_IP, COUNT(*) AS CNT,
                       MIN(ANOMALY_SCORE) AS MIN_SCORE
                FROM ANOMALIES
                WHERE DETECTED_AT >= ADD_SECONDS(CURRENT_TIMESTAMP, ?)
                  AND SOURCE_IP IS NOT NULL
                GROUP BY SOURCE_IP
                ORDER BY CNT DESC
                """,
                (-(hours * 3600),),
            )
            return [
                {
                    "source_ip": row[0],
                    "count": int(row[1]),
                    "min_score": float(row[2]) if row[2] is not None else None,
                }
                for row in cursor.fetchall()
            ]
        finally:
            cursor.close()

    async def query_anomalies(
        self,
        limit: int = 20,
        threat_level: str | None = None,
        hours: int | None = None,
    ) -> list[dict[str, Any]]:
        """Filtered anomaly query for the agent.

        Distinct from :meth:`recent_anomalies` (which has no filters and is
        used by the dashboard) so existing callers stay untouched.
        """
        threat = (threat_level or "").upper().strip() or None
        if threat is not None and threat not in {"HIGH", "MEDIUM", "LOW"}:
            return []  # silent reject; the schema in the system prompt names the valid values

        if settings.mock_hana:
            cutoff = (
                utcnow().timestamp() - hours * 3600 if hours is not None else None
            )
            rows = []
            for r in reversed(self._memory):  # newest first
                if threat and (r.get("threat_level") or "").upper() != threat:
                    continue
                if cutoff is not None:
                    if not r.get("detected_at"):
                        continue
                    if _timestamp_of(r["detected_at"]) < cutoff:
                        continue
                rows.append(r)
                if len(rows) >= limit:
                    break
            return rows

        async with self._pool.acquire() as conn:
            if conn is None:
                return []
            return await asyncio.to_thread(
                self._query_anomalies_sync, conn, limit, threat, hours
            )

    @staticmethod
    def _query_anomalies_sync(
        conn: Any, limit: int, threat: str | None, hours: int | None
    ) -> list[dict[str, Any]]:
        cursor = conn.cursor()
        try:
            clauses: list[str] = []
            params: list[Any] = []
            if threat:
                clauses.append("THREAT_LEVEL = ?")
                params.append(threat)
            if hours is not None:
                clauses.append("DETECTED_AT >= ADD_SECONDS(CURRENT_TIMESTAMP, ?)")
                params.append(-(hours * 3600))
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            cursor.execute(
                f"""
                SELECT TOP {int(limit)} DETECTED_AT, SOURCE_IP, THREAT_LEVEL,
                       ANOMALY_SCORE, TOTAL_REQUESTS, ERROR_RATE,
                       PIPELINE_MTTD_MS, E2E_MTTD_MS, WEBHOOK_SENT,
                       INCIDENT_REPORT_PATH, DETECTOR
                FROM ANOMALIES
                {where}
                ORDER BY DETECTED_AT DESC
                """,
                params,
            )
            cols = [d[0].lower() for d in cursor.description]
            return [dict(zip(cols, row, strict=False)) for row in cursor.fetchall()]
        finally:
            cursor.close()

    async def mttd_percentiles(self, hours: int = 24) -> dict[str, Any]:
        """Return ``{p50_ms, p95_ms, sample_count}`` over the last *hours*.

        HANA's ``PERCENTILE_CONT`` is a window function (per-row output),
        not a scalar aggregate, so computing p50/p95 server-side requires
        either subquery + DISTINCT gymnastics or moving the math into
        Python. We reuse :meth:`mttd_samples` (already bounded by the
        time window) and compute in Python — same code path as mock
        mode, no dialect surprises.
        """
        samples = await self.mttd_samples(window_minutes=hours * 60)
        return _percentiles(samples)

    @staticmethod
    def _count_since_sync(conn: Any, hours: int) -> int:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT COUNT(*) FROM ANOMALIES "
                "WHERE DETECTED_AT >= ADD_SECONDS(CURRENT_TIMESTAMP, ?)",
                (-(hours * 3600),),
            )
            row = cursor.fetchone()
            return int(row[0]) if row and row[0] is not None else 0
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

    async def latest(self) -> dict[str, Any] | None:
        """Return the most recently registered model version, or None."""
        if settings.mock_hana:
            return dict(self._memory[-1]) if self._memory else None

        async with self._pool.acquire() as conn:
            if conn is None:
                return None
            return await asyncio.to_thread(self._latest_sync, conn)

    @staticmethod
    def _latest_sync(conn: Any) -> dict[str, Any] | None:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT TOP 1 VERSION_TAG, MODEL_TYPE, TRAINED_AT, CONTAMINATION,
                             TRAINING_SAMPLES, FEATURE_COLUMNS, HYPERPARAMS,
                             CV_SCORES, IS_ACTIVE, NOTES
                FROM MODEL_VERSIONS
                ORDER BY TRAINED_AT DESC
                """,
            )
            row = cursor.fetchone()
            if not row:
                return None
            cols = [d[0].lower() for d in cursor.description]
            return dict(zip(cols, row, strict=False))
        finally:
            cursor.close()

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


def _percentiles(samples: list[int]) -> dict[str, Any]:
    """Compute p50/p95 from a list of ints; mock-mode helper."""
    if not samples:
        return {"p50_ms": None, "p95_ms": None, "sample_count": 0}
    s = sorted(samples)
    n = len(s)

    def _p(q: float) -> int:
        # Linear interpolation between the two nearest ranks.
        idx = q * (n - 1)
        lo = int(idx)
        hi = min(lo + 1, n - 1)
        frac = idx - lo
        return int(round(s[lo] * (1 - frac) + s[hi] * frac))

    return {"p50_ms": _p(0.5), "p95_ms": _p(0.95), "sample_count": n}


# Module-level singletons used by the pipeline + API.
log_repository: LogRepository = LogRepository()
anomaly_repository: AnomalyRepository = AnomalyRepository()
model_version_repository: ModelVersionRepository = ModelVersionRepository()
