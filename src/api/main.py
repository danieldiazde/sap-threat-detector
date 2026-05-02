"""
main.py
-------
FastAPI application — the single ``web`` process on SAP BTP Cloud Foundry.

Endpoints:
- ``GET  /health``   — liveness probe (always 200)
- ``GET  /ready``    — readiness: HANA reachable + model loaded
- ``POST /predict``  — ad-hoc scoring of log batches
- ``GET  /metrics``  — JSON metrics snapshot (MTTD, counters)

The detection pipeline runs as a background ``asyncio.Task`` started in
the :func:`lifespan` context. On shutdown (SIGTERM from CF), the pipeline
is stopped cleanly before the process exits.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException, status
from src.api.agent_routes import router as agent_router
from src.api.schemas import (
    AnomaliesResponse,
    AnomalyRecord,
    AnomalyResult,
    HealthResponse,
    MetricsResponse,
    PredictRequest,
    PredictResponse,
    ReadinessCheck,
    ReadinessResponse,
)
from src.common.config import settings
from src.common.logging import get_logger
from src.common.metrics import metrics
from src.common.time_utils import utcnow
from src.ingestion.sap_log_fetcher import close_client as close_fetcher_client
from src.model.features import extract_features
from src.model.llm_train import llm_registry
from src.model.predict import predict
from src.model.train import train as train_model
from src.model.versioning import ModelNotFoundError, registry
from src.pipeline import Pipeline
from src.storage.migrations import apply_schema
from src.storage.pool import pool
from src.storage.repositories import anomaly_repository

logger = get_logger(__name__)

# ─── Pipeline background task ─────────────────────────────────────────────

_pipeline: Pipeline | None = None
_pipeline_task: asyncio.Task[None] | None = None
_keepalive_task: asyncio.Task[None] | None = None


async def hana_keepalive() -> None:
    """Run SELECT 1 FROM DUMMY every 10 minutes to prevent HANA auto-shutdown."""
    while True:
        await asyncio.sleep(600)
        try:
            ok = await pool.ping()
            if not ok:
                logger.warning("hana_keepalive.ping_failed")
        except Exception as exc:
            logger.warning("hana_keepalive.error", extra={"error": str(exc)})


def _bootstrap_model() -> None:
    """Train an initial model from sample data if no model exists on disk."""
    from pathlib import Path

    import pandas as pd
    from src.ingestion.log_parser import normalize_columns

    sample_path = Path("data/samples/sample_logs.csv")
    if not sample_path.exists():
        logger.warning("api.bootstrap_model.no_sample_data", extra={"path": str(sample_path)})
        return

    logger.info("api.bootstrap_model.start", extra={"path": str(sample_path)})
    df = normalize_columns(pd.read_csv(sample_path))
    features_df = extract_features(df)
    if features_df.empty:
        logger.warning("api.bootstrap_model.no_features")
        return

    report = train_model(features_df)
    logger.info("api.bootstrap_model.done", extra={"version": report.get("version_tag")})


def _bootstrap_llm_model() -> None:
    """Train an initial LLM bundle from HANA if none exists on disk."""
    import pandas as pd
    from hdbcli import dbapi
    from src.model.llm_train import train_llm_ensemble

    _COLUMN_MAP = {
        "DATETIME": "datetime",
        "SOURCE_IP": "source_ip",
        "STATUS": "status",
        "EVENT_DESCRIPTION": "event_description",
        "PORT_SERVICE": "port_service",
        "LOG_TYPE": "log_type",
        "LLM_MODEL_ID": "llm_model_id",
        "LLM_PROMPT_CATEGORY": "llm_prompt_category",
        "LLM_PROMPT_TOKENS": "llm_prompt_tokens",
        "LLM_TOTAL_TOKENS": "llm_total_tokens",
        "LLM_COST_USD": "llm_cost_usd",
        "LLM_RESPONSE_TIME_MS": "llm_response_time_ms",
        "LLM_FINISH_REASON": "llm_finish_reason",
        "LLM_STATUS": "llm_status",
        "LLM_ERROR_MESSAGE": "llm_error_message",
        "INGESTED_AT": "ingested_at",
    }

    logger.info("api.bootstrap_llm_model.start")
    conn = dbapi.connect(
        address=settings.hana_host,
        port=settings.hana_port,
        user=settings.hana_user,
        password=settings.hana_password,
        databaseName=settings.hana_database,
    )
    try:
        cur = conn.cursor()
        cols = ", ".join(_COLUMN_MAP.keys())
        cur.execute(
            f"SELECT {cols} FROM SECURITY_LOGS"
            " WHERE LOG_TYPE LIKE 'LLM\\_%' ESCAPE '\\'"
            " AND LLM_MODEL_ID IS NOT NULL"
        )
        rows = cur.fetchall()
        cur.close()
    finally:
        conn.close()

    if not rows:
        logger.warning("api.bootstrap_llm_model.no_rows")
        return

    df = pd.DataFrame(rows, columns=list(_COLUMN_MAP.keys())).rename(columns=_COLUMN_MAP)
    bundle = train_llm_ensemble(df)
    version_tag = llm_registry.save(bundle, notes="auto-bootstrapped at startup")
    logger.info("api.bootstrap_llm_model.done", extra={"version": version_tag})


async def _llm_bootstrap() -> None:
    """Async wrapper: run the sync LLM bootstrap in a thread; log failures without crashing."""
    try:
        await asyncio.to_thread(_bootstrap_llm_model)
    except Exception as exc:
        logger.error("api.bootstrap_llm_model.failed", extra={"error": str(exc)})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Start the detection pipeline on boot, tear it down on shutdown.

    Also initialises the HANA pool and runs migrations (both are no-ops
    in mock mode).
    """
    global _pipeline, _pipeline_task

    logger.info("api.startup", extra={"environment": settings.environment})

    # Storage — non-fatal: app boots even if HANA is temporarily unreachable
    try:
        await pool.initialize()
        await apply_schema()
    except Exception as exc:
        logger.error("api.startup.hana_failed", extra={"error": str(exc)})

    # Bootstrap model if none exists
    if registry.current_version() is None:
        await asyncio.to_thread(_bootstrap_model)

    # Pipeline
    _pipeline = Pipeline()
    _pipeline_task = asyncio.create_task(
        _pipeline.run_forever(), name="detection-pipeline"
    )
    _keepalive_task = asyncio.create_task(
        hana_keepalive(), name="hana-keepalive"
    )

    # LLM bundle bootstrap — background task so the health check passes immediately.
    # _safe_predict_llm tolerates a missing bundle (returns empty), so the pipeline
    # runs normally while training completes in the background.
    _llm_bootstrap_task: asyncio.Task[None] | None = None
    if not settings.mock_hana and llm_registry.latest_tag() is None:
        _llm_bootstrap_task = asyncio.create_task(_llm_bootstrap(), name="llm-bootstrap")

    yield

    # Shutdown
    logger.info("api.shutdown")
    if _pipeline is not None:
        _pipeline.request_stop()
    if _pipeline_task is not None:
        _pipeline_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _pipeline_task
    if _keepalive_task is not None:
        _keepalive_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _keepalive_task
    if _llm_bootstrap_task is not None and not _llm_bootstrap_task.done():
        _llm_bootstrap_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _llm_bootstrap_task
    await close_fetcher_client()
    await pool.close()


# ─── App ───────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SAP AI Security — Threat Detector",
    version="0.1.0",
    docs_url="/docs",
    lifespan=lifespan,
)
app.include_router(agent_router)


# ─── Endpoints ─────────────────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe — always returns 200."""
    snap = metrics.snapshot()
    task_alive = _pipeline_task is not None and not _pipeline_task.done()
    pipeline_alive = _pipeline is not None and _pipeline.is_running
    return HealthResponse(
        status="ok",
        mock_api=settings.mock_api,
        mock_webhook=settings.mock_webhook,
        mock_hana=settings.mock_hana,
        scheduler_running=pipeline_alive and task_alive,
        pipeline_runs_total=snap["counters"]["pipeline_runs_total"],
        last_run_at=snap["last_run_at"],
    )


@app.get("/ready", response_model=ReadinessResponse)
async def ready() -> ReadinessResponse:
    """
    Readiness probe — checks HANA connectivity and model availability.

    CF will route traffic only when ``ready == true``.
    """
    checks: list[ReadinessCheck] = []

    # HANA
    hana_ok = await pool.ping()
    checks.append(ReadinessCheck(
        name="hana",
        ok=hana_ok,
        detail="mock" if settings.mock_hana else ("connected" if hana_ok else "unreachable"),
    ))

    # Model
    model_version = registry.current_version()
    model_ok = model_version is not None
    checks.append(ReadinessCheck(
        name="model",
        ok=model_ok,
        detail=model_version or "no trained model",
    ))

    # Pipeline
    pipeline_ok = _pipeline is not None and _pipeline.is_running
    checks.append(ReadinessCheck(
        name="pipeline",
        ok=pipeline_ok,
        detail="running" if pipeline_ok else "stopped",
    ))

    all_ok = all(c.ok for c in checks)
    return ReadinessResponse(ready=all_ok, checks=checks)


@app.post("/predict", response_model=PredictResponse)
async def predict_endpoint(request: PredictRequest) -> PredictResponse:
    """Score a batch of log entries and return detected anomalies."""
    records = [entry.model_dump() for entry in request.logs]
    df = pd.DataFrame(records)
    ingested_at = utcnow()

    features_df = extract_features(df)
    if features_df.empty:
        return PredictResponse(anomalies=[], total_ips_scored=0, pipeline_mttd_ms=0)

    try:
        scored = predict(
            features_df,
            ingested_at=ingested_at,
            batch_min_log_time=None,
        )
    except ModelNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    anomalies = scored[scored["is_anomaly"]].copy()
    results = [
        AnomalyResult(
            source_ip=str(row.source_ip),
            anomaly_score=float(row.anomaly_score),
            threat_level=str(row.threat_level),
            is_anomaly=True,
            total_requests=int(row.total_requests),
            pipeline_mttd_ms=int(row.pipeline_mttd_ms),
            e2e_mttd_ms=int(row.e2e_mttd_ms) if row.e2e_mttd_ms is not None else None,
            multi_bucket_count=int(row.multi_bucket_count),
        )
        for row in anomalies.itertuples(index=False)
    ]

    avg_mttd = int(scored["pipeline_mttd_ms"].mean()) if not scored.empty else 0

    return PredictResponse(
        anomalies=results,
        total_ips_scored=len(scored),
        pipeline_mttd_ms=avg_mttd,
    )


@app.get("/metrics", response_model=MetricsResponse)
async def metrics_endpoint() -> dict[str, Any]:
    """Return the current metrics snapshot as JSON."""
    return metrics.snapshot()


@app.get("/anomalies", response_model=AnomaliesResponse)
async def anomalies_endpoint(limit: int = 50) -> AnomaliesResponse:
    """Return the most recent detected anomalies, newest first."""
    limit = min(limit, 200)
    rows = await anomaly_repository.recent_anomalies(limit=limit)
    records = [
        AnomalyRecord(
            detected_at=str(r.get("detected_at") or ""),
            source_ip=str(r.get("source_ip") or ""),
            threat_level=str(r.get("threat_level") or ""),
            anomaly_score=float(r.get("anomaly_score") or 0.0),
            total_requests=int(r.get("total_requests") or 0),
            error_rate=float(r.get("error_rate") or 0.0),
            pipeline_mttd_ms=int(r["pipeline_mttd_ms"]) if r.get("pipeline_mttd_ms") is not None else None,
            e2e_mttd_ms=int(r["e2e_mttd_ms"]) if r.get("e2e_mttd_ms") is not None else None,
            webhook_sent=bool(r.get("webhook_sent", False)),
            incident_report_path=r.get("incident_report_path"),
        )
        for r in rows
    ]
    return AnomaliesResponse(anomalies=records, total=len(records))
