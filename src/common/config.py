"""
config.py
---------
Typed configuration loaded once from environment variables.

Every other module imports ``settings`` from here instead of calling
``os.getenv`` directly. This gives us one place to reason about defaults,
mock-mode detection, and env-var documentation.

Mock mode is *derived*, never configured: each external dependency flips
out of mock mode automatically the moment its URL/host is set, so promoting
from development to staging to production is purely a secrets change.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

# Load .env once at import time. Safe to call repeatedly — dotenv is idempotent.
load_dotenv()


# ─── Defaults (single source of truth) ─────────────────────────────────────

DEFAULT_POLL_INTERVAL_SECONDS: Final[int] = 30
DEFAULT_RETRAIN_EVERY_N_CYCLES: Final[int] = 480  # 480 x 30s = 4 hours
DEFAULT_MODEL_CONTAMINATION: Final[float] = 0.05
DEFAULT_MODEL_N_ESTIMATORS: Final[int] = 200
DEFAULT_MODEL_MAX_SAMPLES: Final[str] = "auto"
DEFAULT_MODEL_RANDOM_STATE: Final[int] = 42
DEFAULT_MODEL_CONTEXT_WINDOW_MINUTES: Final[int] = 60
DEFAULT_TRAINING_WINDOW_MINUTES: Final[int] = 5
DEFAULT_ANOMALY_SCORE_THRESHOLD: Final[float] = -0.1
DEFAULT_ALERT_HIGH_THRESHOLD: Final[float] = -0.3
DEFAULT_ALERT_MEDIUM_THRESHOLD: Final[float] = -0.1
DEFAULT_ANOMALY_DEDUP_TTL_SECONDS: Final[int] = 300
DEFAULT_HANA_POOL_SIZE: Final[int] = 4
DEFAULT_HANA_PORT: Final[int] = 443
DEFAULT_DASHBOARD_REFRESH_SECONDS: Final[int] = 5
DEFAULT_API_BASE_URL: Final[str] = "http://localhost:8000"
DEFAULT_MTTD_HIGH_THRESHOLD_MS: Final[int] = 5000
DEFAULT_MODEL_TYPE: Final[str] = "isolation_forest"
DEFAULT_MODEL_VERSION: Final[str] = "latest"
DEFAULT_TEAM_ID: Final[str] = "team-tec"
DEFAULT_AGENT_MODEL: Final[str] = "claude-sonnet-4-6"
DEFAULT_AGENT_MAX_ITERATIONS: Final[int] = 5


def _parse_vcap_connectivity() -> dict:
    """Extract credentials from VCAP_SERVICES['connectivity'][0]['credentials']."""
    raw = os.getenv("VCAP_SERVICES")
    if not raw:
        return {}
    try:
        vcap = json.loads(raw)
        return vcap.get("connectivity", [{}])[0].get("credentials", {})
    except (json.JSONDecodeError, IndexError, AttributeError, TypeError):
        return {}


def _env_str(key: str, default: str = "") -> str:
    value = os.getenv(key)
    return value if value is not None else default


def _env_int(key: str, default: int) -> int:
    raw = os.getenv(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Env var {key}={raw!r} is not a valid int") from exc


def _env_float(key: str, default: float) -> float:
    raw = os.getenv(key)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Env var {key}={raw!r} is not a valid float") from exc


@dataclass(frozen=True)
class Settings:
    """Immutable, typed snapshot of application configuration."""

    # --- SAP API (available April 13) ---
    # Note: page size is server-controlled (BATCH_SIZE=500). Clients only send `page`.
    sap_api_url: str
    sap_api_key: str

    # --- Alerting (POST /alert lives on the SAP API itself) ---
    sap_team_id: str

    # --- HANA ---
    hana_host: str
    hana_port: int
    hana_user: str
    hana_password: str
    hana_database: str
    hana_pool_size: int

    # --- Model ---
    model_type: str
    model_version: str
    model_contamination: float
    model_n_estimators: int
    model_max_samples: str
    model_random_state: int
    model_context_window_minutes: int
    training_window_minutes: int
    anomaly_score_threshold: float
    alert_high_threshold: float
    alert_medium_threshold: float

    # --- Alerting ---
    anomaly_dedup_ttl_seconds: int

    # --- App runtime ---
    environment: str
    log_level: str
    poll_interval_seconds: int
    retrain_every_n_cycles: int

    # --- Dashboard ---
    dashboard_refresh_seconds: int
    api_base_url: str
    mttd_high_threshold_ms: int

    # --- Conversational agent (Streamlit page 5_Agent.py) ---
    anthropic_api_key: str
    agent_model: str
    agent_max_iterations: int

    # --- CF Connectivity Service (Cloud Connector proxy) ---
    # Populated from VCAP_SERVICES["connectivity"] when the service is bound.
    cf_proxy_host: str
    cf_proxy_port: int
    cf_proxy_client_id: str
    cf_proxy_client_secret: str
    cf_proxy_token_url: str

    # --- Paths ---
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    model_dir: Path = field(default_factory=lambda: Path("models"))
    incident_report_dir: Path = field(default_factory=lambda: Path("reports/incidents"))

    # ── Derived mock flags ──────────────────────────────────────────────

    @property
    def cf_proxy_enabled(self) -> bool:
        """True when the CF Connectivity Service is bound and proxy host/port are available."""
        return bool(self.cf_proxy_host and self.cf_proxy_port)

    @property
    def mock_api(self) -> bool:
        """True when no real SAP API URL is configured — use local CSV instead."""
        return not self.sap_api_url

    @property
    def mock_webhook(self) -> bool:
        """True when the SAP API is not configured — log alerts locally.

        Alerts now POST to ``{SAP_API_URL}/alert`` with the same Bearer token
        used for ingestion, so mock-alert mode is tied to the API URL.
        """
        return not self.sap_api_url

    @property
    def mock_hana(self) -> bool:
        """True when no HANA host is configured — use in-memory repo."""
        return not self.hana_host

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    # ── Factory ─────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> Settings:
        """Build a Settings instance from current process env vars."""
        _conn = _parse_vcap_connectivity()
        return cls(
            sap_api_url=_env_str("SAP_API_URL"),
            sap_api_key=_env_str("SAP_API_KEY"),
            sap_team_id=_env_str("SAP_TEAM_ID", DEFAULT_TEAM_ID),
            hana_host=_env_str("HANA_HOST"),
            hana_port=_env_int("HANA_PORT", DEFAULT_HANA_PORT),
            hana_user=_env_str("HANA_USER"),
            hana_password=_env_str("HANA_PASSWORD"),
            hana_database=_env_str("HANA_DATABASE"),
            hana_pool_size=_env_int("HANA_POOL_SIZE", DEFAULT_HANA_POOL_SIZE),
            model_type=_env_str("MODEL_TYPE", DEFAULT_MODEL_TYPE),
            model_version=_env_str("MODEL_VERSION", DEFAULT_MODEL_VERSION),
            model_contamination=_env_float("MODEL_CONTAMINATION", DEFAULT_MODEL_CONTAMINATION),
            model_n_estimators=_env_int("MODEL_N_ESTIMATORS", DEFAULT_MODEL_N_ESTIMATORS),
            model_max_samples=_env_str("MODEL_MAX_SAMPLES", DEFAULT_MODEL_MAX_SAMPLES),
            model_random_state=_env_int("MODEL_RANDOM_STATE", DEFAULT_MODEL_RANDOM_STATE),
            model_context_window_minutes=_env_int(
                "MODEL_CONTEXT_WINDOW_MINUTES", DEFAULT_MODEL_CONTEXT_WINDOW_MINUTES
            ),
            training_window_minutes=_env_int(
                "TRAINING_WINDOW_MINUTES", DEFAULT_TRAINING_WINDOW_MINUTES
            ),
            anomaly_score_threshold=_env_float(
                "ANOMALY_SCORE_THRESHOLD", DEFAULT_ANOMALY_SCORE_THRESHOLD
            ),
            alert_high_threshold=_env_float(
                "ALERT_HIGH_THRESHOLD", DEFAULT_ALERT_HIGH_THRESHOLD
            ),
            alert_medium_threshold=_env_float(
                "ALERT_MEDIUM_THRESHOLD", DEFAULT_ALERT_MEDIUM_THRESHOLD
            ),
            anomaly_dedup_ttl_seconds=_env_int(
                "ANOMALY_DEDUP_TTL_SECONDS", DEFAULT_ANOMALY_DEDUP_TTL_SECONDS
            ),
            environment=_env_str("ENVIRONMENT", "development"),
            log_level=_env_str("LOG_LEVEL", "INFO"),
            poll_interval_seconds=_env_int(
                "POLL_INTERVAL_SECONDS", DEFAULT_POLL_INTERVAL_SECONDS
            ),
            retrain_every_n_cycles=_env_int(
                "RETRAIN_EVERY_N_CYCLES", DEFAULT_RETRAIN_EVERY_N_CYCLES
            ),
            dashboard_refresh_seconds=_env_int(
                "DASHBOARD_REFRESH_SECONDS", DEFAULT_DASHBOARD_REFRESH_SECONDS
            ),
            api_base_url=_env_str("API_BASE_URL", DEFAULT_API_BASE_URL),
            mttd_high_threshold_ms=_env_int(
                "MTTD_HIGH_THRESHOLD_MS", DEFAULT_MTTD_HIGH_THRESHOLD_MS
            ),
            anthropic_api_key=_env_str("ANTHROPIC_API_KEY"),
            agent_model=_env_str("AGENT_MODEL", DEFAULT_AGENT_MODEL),
            agent_max_iterations=_env_int(
                "AGENT_MAX_ITERATIONS", DEFAULT_AGENT_MAX_ITERATIONS
            ),
            incident_report_dir=Path(
                _env_str("INCIDENT_REPORT_DIR", "reports/incidents")
            ),
            cf_proxy_host=_conn.get("onpremise_proxy_host", ""),
            cf_proxy_port=int(_conn.get("onpremise_proxy_port", 0) or 0),
            cf_proxy_client_id=_conn.get("clientid", ""),
            cf_proxy_client_secret=_conn.get("clientsecret", ""),
            cf_proxy_token_url=_conn.get("token_service_url", ""),
        )


# Module-level singleton. Import as: ``from src.common.config import settings``.
settings: Settings = Settings.from_env()
