"""
app.py
------
Streamlit real-time dashboard — landing page (OPERATIONS view).

This is the Security Operations Centre live view. Other pages live under
``src/dashboard/pages/`` and are auto-registered by Streamlit:

- ``1_Model.py``    — model registry, metrics, hyperparameters
- ``2_Explorer.py`` — anomaly drill-down with filters
- ``3_Admin.py``    — readiness checks, settings, threshold preview

Run::

    make dashboard
    # OR
    streamlit run src/dashboard/app.py

Owner: Security Analyst & Visualization Lead
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from src.common.config import settings
from src.dashboard._api import (
    api_status_banner,
    dashboard_autorefresh,
    fetch_anomalies,
    fetch_health,
    fetch_metrics,
    fetch_readiness,
    format_number,
    load_fallback_logs,
)

# ─── Page config (must be first Streamlit call) ──────────────────────────

st.set_page_config(
    page_title="SAP AI Security SOC — Operations",
    page_icon="\U0001f6e1️",
    layout="wide",
)

dashboard_autorefresh(key="operations_autorefresh")

# ─── Fetch data ──────────────────────────────────────────────────────────

metrics_data = fetch_metrics()
health_data = fetch_health()
readiness_data = fetch_readiness()
api_available = bool(metrics_data)

counters = metrics_data.get("counters", {})
pipeline_mttd = metrics_data.get("pipeline_mttd_ms", {})
e2e_mttd = metrics_data.get("e2e_mttd_ms", {})

# ─── Header ──────────────────────────────────────────────────────────────

st.title("\U0001f6e1️ SAP AI Security — Live SOC Dashboard")
st.caption("**OBSERVE → ANALYZE → DETECT → RESPOND** · Operations view")

api_status_banner(metrics_data)
st.divider()

# ─── KPI row ─────────────────────────────────────────────────────────────

mttd_target = settings.mttd_high_threshold_ms
p50_pipeline = pipeline_mttd.get("p50", 0) or 0
p95_pipeline = pipeline_mttd.get("p95", 0) or 0
p50_e2e = e2e_mttd.get("p50", 0) or 0

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("Active Threats", format_number(counters.get("anomalies_detected_total")))
col2.metric(
    "MTTD p50 (ms)",
    format_number(p50_pipeline),
    delta=f"target <{mttd_target:,}" if p50_pipeline else None,
    delta_color="inverse" if p50_pipeline >= mttd_target else "normal",
)
col3.metric("MTTD p95 (ms)", format_number(p95_pipeline))
col4.metric("E2E MTTD p50", format_number(p50_e2e))
col5.metric("Logs Processed", format_number(counters.get("logs_processed_total")))
col6.metric(
    "Alerts Sent / Failed",
    f"{counters.get('alerts_sent_total', 0)} / {counters.get('alerts_failed_total', 0)}",
)

st.divider()

# ─── Charts row 1: timeline + threat donut ───────────────────────────────

logs_df = load_fallback_logs()

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Requests/min timeline")
    if not logs_df.empty and "datetime" in logs_df.columns:
        timeline = (
            logs_df.dropna(subset=["datetime"])
            .set_index("datetime")
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
            fig_timeline.update_layout(
                height=300,
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis_title=None,
                yaxis_title="requests",
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No timeline data yet.")
    else:
        st.info("No log data available. Run `make mock` to generate samples.")

with chart_col2:
    st.subheader("Threat level distribution")
    anomaly_count = counters.get("anomalies_detected_total", 0)
    sent = counters.get("alerts_sent_total", 0)
    suppressed = counters.get("alerts_suppressed_total", 0)
    remainder = max(0, anomaly_count - sent - suppressed)
    if anomaly_count:
        fig_donut = go.Figure(
            data=[
                go.Pie(
                    labels=["High (sent)", "Suppressed (deduped)", "Low (no alert)"],
                    values=[sent, suppressed, remainder],
                    hole=0.55,
                    marker_colors=["#e74c3c", "#f39c12", "#2ecc71"],
                )
            ]
        )
        fig_donut.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        st.info("No anomalies detected yet.")

# ─── Charts row 2: top IPs + MTTD gauge ──────────────────────────────────

chart_col3, chart_col4 = st.columns(2)

with chart_col3:
    st.subheader("Top 10 source IPs")
    if not logs_df.empty and "source_ip" in logs_df.columns:
        top_ips = (
            logs_df["source_ip"].value_counts().head(10).reset_index()
        )
        top_ips.columns = ["source_ip", "count"]
        fig_ips = px.bar(
            top_ips,
            x="count",
            y="source_ip",
            orientation="h",
            color="count",
            color_continuous_scale="Blues",
        )
        fig_ips.update_layout(
            height=300,
            margin=dict(t=10, b=10, l=10, r=10),
            yaxis=dict(autorange="reversed", title=None),
            xaxis_title="requests",
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_ips, use_container_width=True)
    else:
        st.info("No IP data available.")

with chart_col4:
    st.subheader("MTTD headline")
    mttd_count = pipeline_mttd.get("count", 0)
    if mttd_count:
        target = settings.mttd_high_threshold_ms
        fig_gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=p50_pipeline,
                number={"suffix": " ms"},
                gauge={
                    "axis": {"range": [0, max(target * 2, p95_pipeline * 1.2)]},
                    "bar": {"color": "#0070f3"},
                    "steps": [
                        {"range": [0, target], "color": "#d4edda"},
                        {"range": [target, target * 2], "color": "#f8d7da"},
                    ],
                    "threshold": {
                        "line": {"color": "red", "width": 3},
                        "value": p95_pipeline,
                    },
                },
                title={"text": f"Pipeline MTTD p50 (target <{target} ms)"},
            )
        )
        fig_gauge.update_layout(height=300, margin=dict(t=30, b=10, l=10, r=10))
        st.plotly_chart(fig_gauge, use_container_width=True)
        st.caption(
            f"p50 {p50_pipeline:.0f} ms · p95 {p95_pipeline:.0f} ms · "
            f"max {pipeline_mttd.get('max', 0):.0f} ms · {mttd_count} samples"
        )
    else:
        st.info("No MTTD samples yet. Start the pipeline with `make api`.")

st.divider()

# ─── Active Threats ──────────────────────────────────────────────────────

st.subheader("Active threats")
anomalies = fetch_anomalies(limit=50) if api_available else []
if anomalies:
    threats_df = pd.DataFrame(anomalies)
    display_cols = [
        c
        for c in [
            "detected_at",
            "source_ip",
            "threat_level",
            "anomaly_score",
            "pipeline_mttd_ms",
            "total_requests",
            "error_rate",
            "webhook_sent",
            "incident_report_path",
        ]
        if c in threats_df.columns
    ]
    view = threats_df[display_cols]
    if "detected_at" in view.columns:
        view = view.sort_values("detected_at", ascending=False)
    st.dataframe(view, use_container_width=True, hide_index=True)
    st.caption(
        f"{len(anomalies)} shown · lifetime total: "
        f"{counters.get('anomalies_detected_total', 0):,}"
    )
    st.caption(
        "Need to drill into a specific IP or filter by severity? Open the "
        "**Explorer** page in the sidebar."
    )
else:
    st.info(
        "No active threats. System is monitoring. "
        "(If you expect alerts, check the Admin page for readiness state.)"
    )

# ─── Recent Logs ─────────────────────────────────────────────────────────

st.subheader("Recent log feed")
if not logs_df.empty:
    st.dataframe(logs_df.tail(20), use_container_width=True, hide_index=True)
else:
    st.info("No logs loaded. Run `make mock` to generate sample data.")

# ─── Sidebar ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("System health")

    if api_available:
        checks = readiness_data.get("checks", [])
        for check in checks:
            name = check.get("name", "unknown")
            ok = bool(check.get("ok", False))
            detail = check.get("detail", "")
            icon = "✅" if ok else "❌"
            st.markdown(f"{icon} **{name.upper()}** — {detail}")

        st.divider()
        st.markdown(
            f"**SAP API**: {'Live' if not health_data.get('mock_api', True) else 'Mock'}"
        )
        st.markdown(
            f"**Webhook**: {'Live' if not health_data.get('mock_webhook', True) else 'Mock'}"
        )
        st.markdown(
            f"**HANA**: {'Live' if not health_data.get('mock_hana', True) else 'Mock'}"
        )
    else:
        st.markdown("❌ **API** — not reachable")
        st.markdown("❓ **HANA** — unknown")
        st.markdown("❓ **Webhook** — unknown")
        st.markdown("❓ **Model** — unknown")

    st.divider()
    st.markdown(f"**Last pipeline run** · {metrics_data.get('last_run_at') or 'never'}")
    if metrics_data.get("last_error"):
        st.markdown(f"**Last error** · {metrics_data['last_error']}")
    st.markdown(f"**Pipeline runs** · {counters.get('pipeline_runs_total', 0):,}")
    st.markdown(f"**Errors** · {counters.get('errors_total', 0):,}")
    st.caption(f"Refresh · every {settings.dashboard_refresh_seconds}s")
