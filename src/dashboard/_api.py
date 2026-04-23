"""
dashboard/_api.py
-----------------
Shared helpers for the Streamlit dashboard pages.

The leading underscore keeps this file from being auto-registered as a
Streamlit page (the ``pages/`` discovery only picks up files in that
folder; this file lives alongside ``app.py`` and is imported, not
rendered).

Every page should funnel its API calls through these helpers so caching
semantics stay consistent and we have one place to change when the
backend contract moves.

Owner: Security Analyst & Visualization Lead
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pandas as pd
import streamlit as st
from src.common.config import settings

# ─── Constants ─────────────────────────────────────────────────────────────

TIMEOUT_SECONDS: float = 3.0
FALLBACK_CSV_PATHS: tuple[Path, ...] = (
    Path("data/samples/sample_logs.csv"),
    Path("data/samples/mock_logs.csv"),
)


# ─── HTTP fetchers ─────────────────────────────────────────────────────────


@st.cache_data(ttl=5, show_spinner=False)
def fetch_metrics() -> dict[str, Any]:
    """Return ``/metrics`` JSON or ``{}`` if the API is unreachable."""
    return _safe_get("/metrics") or {}


@st.cache_data(ttl=5, show_spinner=False)
def fetch_health() -> dict[str, Any]:
    return _safe_get("/health") or {}


@st.cache_data(ttl=5, show_spinner=False)
def fetch_readiness() -> dict[str, Any]:
    return _safe_get("/ready") or {}


@st.cache_data(ttl=5, show_spinner=False)
def fetch_anomalies(limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent anomalies, newest first. Empty on failure."""
    payload = _safe_get("/anomalies", params={"limit": limit}) or {}
    return payload.get("anomalies", [])


def _safe_get(path: str, *, params: dict[str, Any] | None = None) -> Any:
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    try:
        resp = httpx.get(url, params=params, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ─── Fallback data ─────────────────────────────────────────────────────────


@st.cache_data(ttl=30, show_spinner=False)
def load_fallback_logs() -> pd.DataFrame:
    """Load local sample logs — used when the API is down or in tests."""
    for path in FALLBACK_CSV_PATHS:
        if path.exists():
            df = pd.read_csv(path)
            if "datetime" in df.columns:
                df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
            return df
    return pd.DataFrame()


# ─── Shared UI bits ────────────────────────────────────────────────────────


def api_status_banner(metrics_data: dict[str, Any]) -> bool:
    """Render a banner when the API is unreachable. Returns True when live."""
    if metrics_data:
        return True
    st.warning(
        f"API not reachable at {settings.api_base_url}. Showing fallback "
        "data where possible. Start the API with `make api`."
    )
    return False


def dashboard_autorefresh(key: str) -> None:
    """Wire the auto-refresh component if installed. Silent no-op otherwise."""
    try:
        from streamlit_autorefresh import st_autorefresh
    except ImportError:
        return
    interval_ms = settings.dashboard_refresh_seconds * 1000
    st_autorefresh(interval=interval_ms, key=key)


def format_number(value: Any, default: str = "—") -> str:
    """Human-friendly numeric formatter for ``st.metric`` and headers."""
    if value is None or value == "":
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if number == int(number):
        return f"{int(number):,}"
    return f"{number:,.2f}"


def threat_level_color(level: str) -> str:
    """Colour code matching the existing dashboard palette."""
    mapping = {
        "high": "#e74c3c",
        "medium": "#f39c12",
        "low": "#2ecc71",
        "suppressed": "#f39c12",
    }
    return mapping.get((level or "").lower(), "#3498db")
