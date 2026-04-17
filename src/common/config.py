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
DEFAULT_PAGE_SIZE: Final[int] = 100
DEFAULT_MODEL_CONTAMINATION: Final[float] = 0.05
DEFAULT_MODEL_CONTEXT_WINDOW_MINUTES: Final[int] = 60
DEFAULT_ANOMALY_SCORE_THRESHOLD: Final[float] = -0.1
DEFAULT_ALERT_HIGH_THRESHOLD: Final[float] = -0.3
DEFAULT_ALERT_MEDIUM_THRESHOLD: Final[float] = -0.1
DEFAULT_ANOMALY_DEDUP_TTL_SECONDS: Final[int] = 300
DEFAULT_HANA_POOL_SIZE: Final[int] = 4
DEFAULT_HANA_PORT: Final[int] = 443
DEFAULT_DASHBOARD_REFRESH_SECONDS: Final[int] = 5
DEFAULT_MTTD_HIGH_THRESHOLD_MS: Final[int] = 5000
DEFAULT_MODEL_TYPE: Final[str] = "isolation_forest"
DEFAULT_MODEL_VERSION: Final[str] = "latest"
DEFAULT_TEAM_ID: Final[str] = "team-tec"


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
    sap_api_url: str
    sap_api_key: str
    sap_api_page_size: int

    # --- Webhook (available April 27) ---
    sap_webhook_url: str
    sap_webhook_secret: str
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
    model_context_window_minutes: int
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
    mttd_high_threshold_ms: int

    # --- Paths ---
    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    model_dir: Path = field(default_factory=lambda: Path("models"))
    incident_report_dir: Path = field(default_factory=lambda: Path("reports/incidents"))

    # ── Derived mock flags ──────────────────────────────────────────────

    @property
    def mock_api(self) -> bool:
        """True when no real SAP API URL is configured — use local CSV instead."""
        return not self.sap_api_url

    @property
    def mock_webhook(self) -> bool:
        """True when no real webhook URL is configured — log alerts locally."""
        return not self.sap_webhook_url

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
        return cls(
            sap_api_url=_env_str("SAP_API_URL"),
            sap_api_key=_env_str("SAP_API_KEY"),
            sap_api_page_size=_env_int("SAP_API_PAGE_SIZE", DEFAULT_PAGE_SIZE),
            sap_webhook_url=_env_str("SAP_WEBHOOK_URL"),
            sap_webhook_secret=_env_str("SAP_WEBHOOK_SECRET"),
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
            model_context_window_minutes=_env_int(
                "MODEL_CONTEXT_WINDOW_MINUTES", DEFAULT_MODEL_CONTEXT_WINDOW_MINUTES
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
            mttd_high_threshold_ms=_env_int(
                "MTTD_HIGH_THRESHOLD_MS", DEFAULT_MTTD_HIGH_THRESHOLD_MS
            ),
            incident_report_dir=Path(
                _env_str("INCIDENT_REPORT_DIR", "reports/incidents")
            ),
        )


# Module-level singleton. Import as: ``from src.common.config import settings``.
settings: Settings = Settings.from_env()
