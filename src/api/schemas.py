"""
schemas.py
----------
Pydantic models for the FastAPI request/response contracts.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ─── Health / readiness ──────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    mock_api: bool = False
    mock_webhook: bool = False
    mock_hana: bool = False


class ReadinessCheck(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class ReadinessResponse(BaseModel):
    ready: bool
    checks: list[ReadinessCheck]


# ─── /predict ────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    datetime: str
    source_ip: str
    port_service: str = ""
    event_description: str = ""
    status: str = ""
    log_type: str = "security"


class PredictRequest(BaseModel):
    logs: list[LogEntry] = Field(..., min_length=1)


class AnomalyResult(BaseModel):
    source_ip: str
    anomaly_score: float
    threat_level: str
    is_anomaly: bool
    total_requests: int = 0
    pipeline_mttd_ms: int = 0
    e2e_mttd_ms: int | None = None
    multi_bucket_count: int = 0


class PredictResponse(BaseModel):
    anomalies: list[AnomalyResult]
    total_ips_scored: int
    pipeline_mttd_ms: int


# ─── /anomalies ──────────────────────────────────────────────────────────

class AnomalyRecord(BaseModel):
    detected_at: str | None = None
    source_ip: str = ""
    threat_level: str = ""
    anomaly_score: float = 0.0
    total_requests: int = 0
    error_rate: float = 0.0
    pipeline_mttd_ms: int | None = None
    e2e_mttd_ms: int | None = None
    webhook_sent: bool = False
    incident_report_path: str | None = None


class AnomaliesResponse(BaseModel):
    anomalies: list[AnomalyRecord]
    total: int


# ─── /metrics ────────────────────────────────────────────────────────────

class MetricsResponse(BaseModel):
    """Mirrors the dict returned by ``MetricsRegistry.snapshot()``."""

    started_at: str | None = None
    last_run_at: str | None = None
    counters: dict[str, int] = {}
    pipeline_mttd_ms: dict[str, float] = {}
    e2e_mttd_ms: dict[str, float] = {}
    last_error: str | None = None
