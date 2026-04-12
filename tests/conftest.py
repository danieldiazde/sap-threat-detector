"""
conftest.py
-----------
Shared pytest fixtures for the entire test suite.

Provides:
- Pre-built DataFrames: normal_logs_df, attack_logs_df, mixed_logs_df
- Trained model fixtures: trained_isolation_forest, trained_dbscan
- Infrastructure: tmp_model_registry, mock_settings, in_memory_metrics
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.common.config import Settings
from src.common.metrics import MetricsRegistry
from src.model.dbscan_detector import DBSCANDetector
from src.model.features import extract_features, feature_matrix
from src.model.schema import FEATURE_COLUMNS
from src.model.versioning import ModelRegistry


# ─── Log DataFrames ──────────────────────────────────────────────────────


def _make_normal_logs(n: int = 200, seed: int = 42) -> pd.DataFrame:
    """Simulate normal traffic — many IPs, low volume, 200 status."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        rows.append({
            "datetime": f"2026-04-04 14:{i // 60:02d}:{i % 60:02d}",
            "source_ip": f"10.10.1.{rng.integers(1, 51)}",
            "port_service": "TCP/80",
            "event_description": "GET /index.html HTTP/1.1",
            "status": "200",
            "log_type": "access",
        })
    return pd.DataFrame(rows)


def _make_attack_logs(n: int = 100, ip: str = "203.0.113.99") -> pd.DataFrame:
    """Simulate a brute-force / scanning attack from a single IP."""
    rows = []
    for i in range(n):
        rows.append({
            "datetime": f"2026-04-04 15:00:{i % 60:02d}",
            "source_ip": ip,
            "port_service": "TCP/22",
            "event_description": "Failed login attempt: user 'root'",
            "status": "DENIED",
            "log_type": "security",
        })
    return pd.DataFrame(rows)


@pytest.fixture()
def normal_logs_df() -> pd.DataFrame:
    return _make_normal_logs()


@pytest.fixture()
def attack_logs_df() -> pd.DataFrame:
    return _make_attack_logs()


@pytest.fixture()
def mixed_logs_df() -> pd.DataFrame:
    normal = _make_normal_logs(200)
    attack = _make_attack_logs(50)
    return pd.concat([normal, attack], ignore_index=True)


# ─── Trained models ──────────────────────────────────────────────────────


@pytest.fixture()
def trained_isolation_forest(
    mixed_logs_df: pd.DataFrame,
) -> tuple[IsolationForest, StandardScaler, pd.DataFrame]:
    """Return a fitted (model, scaler, features_df) tuple."""
    features_df = extract_features(mixed_logs_df)
    X = feature_matrix(features_df)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
    model.fit(X_scaled)
    return model, scaler, features_df


@pytest.fixture()
def trained_dbscan(
    mixed_logs_df: pd.DataFrame,
) -> tuple[DBSCANDetector, StandardScaler, pd.DataFrame]:
    """Return a fitted (DBSCANDetector, scaler, features_df) tuple."""
    features_df = extract_features(mixed_logs_df)
    X = feature_matrix(features_df)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    detector = DBSCANDetector(eps=0.8, min_samples=3)
    detector.fit(X_scaled)
    return detector, scaler, features_df


# ─── Infrastructure fixtures ─────────────────────────────────────────────


@pytest.fixture()
def tmp_model_registry(tmp_path: Path) -> ModelRegistry:
    """Return a ModelRegistry backed by a temporary directory."""
    return ModelRegistry(root=tmp_path / "models")


@pytest.fixture()
def mock_settings() -> Settings:
    """Return a Settings instance configured for full mock mode."""
    return Settings(
        sap_api_url="",
        sap_api_key="",
        sap_api_page_size=100,
        sap_webhook_url="",
        sap_webhook_secret="",
        sap_team_id="test-team",
        hana_host="",
        hana_port=443,
        hana_user="",
        hana_password="",
        hana_database="",
        hana_pool_size=1,
        model_type="isolation_forest",
        model_version="latest",
        model_contamination=0.05,
        model_context_window_minutes=60,
        anomaly_score_threshold=-0.1,
        alert_high_threshold=-0.3,
        alert_medium_threshold=-0.1,
        anomaly_dedup_ttl_seconds=300,
        environment="development",
        log_level="DEBUG",
        poll_interval_seconds=5,
        dashboard_refresh_seconds=5,
        mttd_high_threshold_ms=5000,
    )


@pytest.fixture()
def in_memory_metrics() -> MetricsRegistry:
    """Return a fresh MetricsRegistry (not the global singleton)."""
    return MetricsRegistry()


# ─── Helpers available to all tests ──────────────────────────────────────


def make_utc(year: int = 2026, month: int = 4, day: int = 4, hour: int = 14) -> datetime:
    """Convenience for creating a tz-aware UTC datetime."""
    return datetime(year, month, day, hour, tzinfo=timezone.utc)
