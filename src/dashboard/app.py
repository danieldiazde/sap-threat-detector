"""
app.py
------
Streamlit real-time dashboard for the SAP AI Security SOC.

Pulls live data from:
- FastAPI ``/metrics`` endpoint (KPIs, MTTD, counters)
- In-memory repositories (anomalies, recent logs) in mock mode
- Local CSV/parquet fallback when no pipeline is running

Auto-refreshes via ``streamlit-autorefresh`` at a configurable interval
(default 5 seconds).

Run::

    make dashboard
    # OR
    streamlit run src/dashboard/app.py

Owner: Security Analyst & Visualization Lead
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─── Page config (must be first Streamlit call) ──────────────────────────
st.set_page_config(page_title="SAP AI Security SOC", page_icon="\U0001f6e1\ufe0f", layout="wide")

# ─── Auto-refresh ────────────────────────────────────────────────────────


def _get_refresh_interval() -> int:
    """Read DASHBOARD_REFRESH_SECONDS from env (not importing settings to
    avoid importing heavy ML libs in the Streamlit process)."""
    import os

    try:
        return int(os.getenv("DASHBOARD_REFRESH_SECONDS", "5")) * 1000
    except ValueError:
        return 5000


try:
    from streamlit_autorefresh import st_autorefresh

    _refresh_interval_ms = _get_refresh_interval()
except ImportError:
    st_autorefresh = None
    _refresh_interval_ms = 5000


# ─── Data loading helpers ────────────────────────────────────────────────

import os
API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000")


@st.cache_data(ttl=5)
def _fetch_metrics() -> dict[str, Any]:
    """Fetch the /metrics JSON from the FastAPI backend."""
    import httpx

    try:
        resp = httpx.get(f"{API_BASE}/metrics", timeout=3.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


@st.cache_data(ttl=5)
def _fetch_health() -> dict[str, Any]:
    """Fetch /health from the FastAPI backend."""
    import httpx

    try:
        resp = httpx.get(f"{API_BASE}/health", timeout=3.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


@st.cache_data(ttl=5)
def _fetch_readiness() -> dict[str, Any]:
    import httpx

    try:
        resp = httpx.get(f"{API_BASE}/ready", timeout=3.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


@st.cache_data(ttl=5)
def _fetch_anomalies(limit: int = 50) -> list[dict]:
    """Fetch recent anomalies from GET /anomalies."""
    import httpx

    try:
        resp = httpx.get(f"{API_BASE}/anomalies", params={"limit": limit}, timeout=3.0)
        resp.raise_for_status()
        return resp.json().get("anomalies", [])
    except Exception:
        return []


def _load_fallback_logs() -> pd.DataFrame:
    """Load local CSV as fallback when the API is not running."""
    from pathlib import Path

    for path in [Path("data/samples/sample_logs.csv"), Path("data/samples/mock_logs.csv")]:
        if path.exists():
            return pd.read_csv(path)
    return pd.DataFrame()


# ─── Refresh trigger ─────────────────────────────────────────────────────

if st_autorefresh is not None:
    st_autorefresh(interval=_refresh_interval_ms, key="soc_autorefresh")

# ─── Fetch data ──────────────────────────────────────────────────────────

metrics_data = _fetch_metrics()
health_data = _fetch_health()
readiness_data = _fetch_readiness()
api_available = bool(metrics_data)

counters = metrics_data.get("counters", {})
pipeline_mttd = metrics_data.get("pipeline_mttd_ms", {})
e2e_mttd = metrics_data.get("e2e_mttd_ms", {})

# ─── Header ──────────────────────────────────────────────────────────────

st.title("\U0001f6e1\ufe0f SAP AI Security \u2014 Live SOC Dashboard")
st.markdown("**OBSERVE \u2192 ANALYZE \u2192 DETECT \u2192 RESPOND**")

if not api_available:
    st.warning(
        "API not reachable at localhost:8000. Showing fallback data. "
        "Start the API with `make api`."
    )

st.divider()

# ─── KPI row ─────────────────────────────────────────────────────────────

col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric("Active Threats", counters.get("anomalies_detected_total", "\u2014"))
with col2:
    p50 = pipeline_mttd.get("p50", 0)
    st.metric("MTTD p50 (ms)", f"{p50:.0f}" if p50 else "\u2014")
with col3:
    p95 = pipeline_mttd.get("p95", 0)
    st.metric("MTTD p95 (ms)", f"{p95:.0f}" if p95 else "\u2014")
with col4:
    e2e_p50 = e2e_mttd.get("p50", 0)
    st.metric("E2E MTTD p50", f"{e2e_p50:.0f}" if e2e_p50 else "\u2014")
with col5:
    st.metric("Logs Processed", counters.get("logs_processed_total", "\u2014"))
with col6:
    sent = counters.get("alerts_sent_total", 0)
    failed = counters.get("alerts_failed_total", 0)
    st.metric("Alerts Sent/Failed", f"{sent}/{failed}")

st.divider()

# ─── Charts ──────────────────────────────────────────────────────────────

chart_col1, chart_col2 = st.columns(2)

# Chart 1: Request timeline with anomaly overlay (uses fallback if no API)
with chart_col1:
    st.subheader("Requests/Min Timeline")
    logs_df = _load_fallback_logs()
    if not logs_df.empty and "datetime" in logs_df.columns:
        logs_df["datetime"] = pd.to_datetime(logs_df["datetime"], errors="coerce")
        logs_df = logs_df.dropna(subset=["datetime"])
        timeline = (
            logs_df.set_index("datetime")
            .resample("1min")
            .size()
            .reset_index(name="requests")
        )
        if not timeline.empty:
            fig_timeline = px.area(
                timeline,
                x="datetime",
                y="requests",
                color_discrete_sequence=["#0070f3"],
            )
            fig_timeline.update_layout(height=300, margin=dict(t=10, b=10))
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No timeline data yet.")
    else:
        st.info("No log data available.")

# Chart 2: Threat level donut
with chart_col2:
    st.subheader("Threat Level Distribution")
    anomaly_count = counters.get("anomalies_detected_total", 0)
    if anomaly_count > 0:
        # Approximate distribution from suppressed vs sent
        sent = counters.get("alerts_sent_total", 0)
        suppressed = counters.get("alerts_suppressed_total", 0)
        fig_donut = go.Figure(data=[go.Pie(
            labels=["High (sent)", "Suppressed (deduped)", "Low (no alert)"],
            values=[sent, suppressed, max(0, anomaly_count - sent - suppressed)],
            hole=0.5,
            marker_colors=["#e74c3c", "#f39c12", "#2ecc71"],
        )])
        fig_donut.update_layout(height=300, margin=dict(t=10, b=10))
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        st.info("No anomalies detected yet.")

chart_col3, chart_col4 = st.columns(2)

# Chart 3: Top 10 source IPs
with chart_col3:
    st.subheader("Top 10 Source IPs")
    if not logs_df.empty and "source_ip" in logs_df.columns:
        top_ips = logs_df["source_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["source_ip", "count"]
        fig_ips = px.bar(
            top_ips,
            x="count",
            y="source_ip",
            orientation="h",
            color_discrete_sequence=["#3498db"],
        )
        fig_ips.update_layout(height=300, margin=dict(t=10, b=10), yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig_ips, use_container_width=True)
    else:
        st.info("No IP data available.")

# Chart 4: MTTD distribution histogram
with chart_col4:
    st.subheader("MTTD Distribution")
    mttd_count = pipeline_mttd.get("count", 0)
    if mttd_count > 0:
        st.markdown(
            f"**p50**: {pipeline_mttd.get('p50', 0):.0f} ms | "
            f"**p95**: {pipeline_mttd.get('p95', 0):.0f} ms | "
            f"**max**: {pipeline_mttd.get('max', 0):.0f} ms | "
            f"**samples**: {mttd_count}"
        )
        st.progress(min(1.0, pipeline_mttd.get("p50", 0) / 5000))
    else:
        st.info("No MTTD samples yet. Start the pipeline with `make api`.")

st.divider()

# ─── Active Threats Table ────────────────────────────────────────────────

st.subheader("Active Threats")
anomalies = _fetch_anomalies() if api_available else []
if anomalies:
    threats_df = pd.DataFrame(anomalies)
    display_cols = [c for c in [
        "detected_at", "source_ip", "threat_level", "anomaly_score",
        "pipeline_mttd_ms", "total_requests", "error_rate",
        "webhook_sent", "incident_report_path",
    ] if c in threats_df.columns]
    st.dataframe(
        threats_df[display_cols].sort_values("detected_at", ascending=False)
        if "detected_at" in threats_df.columns else threats_df[display_cols],
        use_container_width=True,
    )
    st.caption(f"{len(anomalies)} anomalies — total lifetime: {anomaly_count}")
else:
    st.info("No active threats. The system is monitoring.")

# ─── Recent Logs ─────────────────────────────────────────────────────────

st.subheader("Recent Log Feed")
if not logs_df.empty:
    st.dataframe(logs_df.tail(20), use_container_width=True)
else:
    st.info("No logs loaded. Run `make mock` to generate sample data.")

# ─── System Health Sidebar ───────────────────────────────────────────────

with st.sidebar:
    st.header("System Health")

    if api_available:
        mock_api = health_data.get("mock_api", True)
        mock_webhook = health_data.get("mock_webhook", True)
        mock_hana = health_data.get("mock_hana", True)

        checks = readiness_data.get("checks", [])
        for check in checks:
            name = check.get("name", "unknown")
            ok = check.get("ok", False)
            detail = check.get("detail", "")
            icon = "\u2705" if ok else "\u274c"
            st.markdown(f"{icon} **{name.upper()}**: {detail}")

        st.divider()
        st.markdown(f"**SAP API**: {'Live' if not mock_api else 'Mock'}")
        st.markdown(f"**Webhook**: {'Live' if not mock_webhook else 'Mock'}")
        st.markdown(f"**HANA**: {'Live' if not mock_hana else 'Mock'}")
    else:
        st.markdown("\u274c **API**: Not reachable")
        st.markdown("\u2753 **HANA**: Unknown")
        st.markdown("\u2753 **Webhook**: Unknown")
        st.markdown("\u2753 **Model**: Unknown")

    st.divider()
    last_run = metrics_data.get("last_run_at")
    st.markdown(f"**Last pipeline run**: {last_run or 'Never'}")
    last_error = metrics_data.get("last_error")
    if last_error:
        st.markdown(f"**Last error**: {last_error}")
    st.markdown(f"**Pipeline runs**: {counters.get('pipeline_runs_total', 0)}")
    st.markdown(f"**Errors**: {counters.get('errors_total', 0)}")
