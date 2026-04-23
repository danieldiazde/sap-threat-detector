"""
pages/2_Explorer.py
-------------------
Interactive anomaly explorer — the analyst's triage surface.

Flow: load recent anomalies, filter, pick a row, drill into that IP's
feature vector and raw logs. Computes features on demand using
``src.model.features.extract_features`` so the per-IP panel shows what
the model actually saw, not a re-summarized approximation.

Owner: Security Analyst & Visualization Lead
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
import plotly.express as px
import streamlit as st
from src.common.time_utils import utcnow
from src.dashboard._api import (
    dashboard_autorefresh,
    fetch_anomalies,
    load_fallback_logs,
)
from src.model.features import extract_features

st.set_page_config(
    page_title="Explorer — SAP AI Security",
    page_icon="\U0001f50d",
    layout="wide",
)

dashboard_autorefresh(key="explorer_autorefresh")

st.title("\U0001f50d Anomaly explorer")
st.caption(
    "Filter · select · drill. All filters are client-side — the API call "
    "fetches the last 200 anomalies and everything below runs on that set."
)

# ─── Data load ───────────────────────────────────────────────────────────

raw_anomalies = fetch_anomalies(limit=200)
logs_df = load_fallback_logs()

if not raw_anomalies:
    st.warning(
        "No anomalies available from the API. Showing sample logs only — "
        "start the pipeline (`make api`) to populate real detections."
    )

anomalies_df = pd.DataFrame(raw_anomalies) if raw_anomalies else pd.DataFrame()
if not anomalies_df.empty and "detected_at" in anomalies_df.columns:
    anomalies_df["detected_at"] = pd.to_datetime(
        anomalies_df["detected_at"], errors="coerce", utc=True
    )

# ─── Filters ─────────────────────────────────────────────────────────────

filter_col1, filter_col2, filter_col3 = st.columns([2, 2, 3])

available_levels = (
    sorted(anomalies_df["threat_level"].dropna().unique().tolist())
    if "threat_level" in anomalies_df.columns and not anomalies_df.empty
    else ["high", "medium", "low"]
)

with filter_col1:
    selected_levels = st.multiselect(
        "Threat level",
        options=available_levels,
        default=available_levels,
        key="explorer_levels",
    )

with filter_col2:
    hours = st.selectbox(
        "Time window",
        options=[1, 6, 24, 72, 168, 0],
        index=2,
        format_func=lambda h: "all" if h == 0 else f"last {h}h",
        key="explorer_hours",
    )

if (
    "anomaly_score" in anomalies_df.columns
    and not anomalies_df.empty
    and anomalies_df["anomaly_score"].notna().any()
):
    score_min = float(anomalies_df["anomaly_score"].min())
    score_max = float(anomalies_df["anomaly_score"].max())
else:
    score_min, score_max = -1.0, 0.0

with filter_col3:
    score_range = st.slider(
        "Anomaly score range",
        min_value=float(min(score_min, -1.0)),
        max_value=float(max(score_max, 0.0)),
        value=(float(min(score_min, -1.0)), float(max(score_max, 0.0))),
        step=0.01,
        key="explorer_score_range",
    )

# Apply filters
filtered = anomalies_df
if not filtered.empty:
    if "threat_level" in filtered.columns:
        filtered = filtered[filtered["threat_level"].isin(selected_levels)]
    if hours and "detected_at" in filtered.columns:
        cutoff = utcnow() - timedelta(hours=hours)
        filtered = filtered[filtered["detected_at"] >= cutoff]
    if "anomaly_score" in filtered.columns:
        lo, hi = score_range
        filtered = filtered[
            (filtered["anomaly_score"] >= lo) & (filtered["anomaly_score"] <= hi)
        ]

st.caption(
    f"{len(filtered)} of {len(anomalies_df)} anomalies match the current filters."
)

# ─── Distribution panel ──────────────────────────────────────────────────

if not filtered.empty and "anomaly_score" in filtered.columns:
    dist_col1, dist_col2 = st.columns(2)
    with dist_col1:
        st.subheader("Score distribution")
        fig_hist = px.histogram(
            filtered,
            x="anomaly_score",
            nbins=30,
            color="threat_level" if "threat_level" in filtered.columns else None,
            color_discrete_map={
                "high": "#e74c3c",
                "medium": "#f39c12",
                "low": "#2ecc71",
            },
        )
        fig_hist.update_layout(height=260, margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig_hist, use_container_width=True)
    with dist_col2:
        st.subheader("Anomalies over time")
        if "detected_at" in filtered.columns:
            timeline = (
                filtered.set_index("detected_at")
                .resample("15min")
                .size()
                .reset_index(name="anomalies")
            )
            fig_time = px.bar(
                timeline,
                x="detected_at",
                y="anomalies",
                color_discrete_sequence=["#e74c3c"],
            )
            fig_time.update_layout(
                height=260, margin=dict(t=10, b=10, l=10, r=10), xaxis_title=None
            )
            st.plotly_chart(fig_time, use_container_width=True)

st.divider()

# ─── Table with row selection ────────────────────────────────────────────

st.subheader("Select a row to drill in")

if filtered.empty:
    st.info(
        "No anomalies match the current filters. Relax the threat-level "
        "multiselect or extend the time window."
    )
    st.stop()

display_cols = [
    c
    for c in [
        "detected_at",
        "source_ip",
        "threat_level",
        "anomaly_score",
        "total_requests",
        "error_rate",
        "pipeline_mttd_ms",
        "webhook_sent",
    ]
    if c in filtered.columns
]
table_view = filtered[display_cols].copy()
if "detected_at" in table_view.columns:
    table_view = table_view.sort_values("detected_at", ascending=False)

selection = st.dataframe(
    table_view.reset_index(drop=True),
    use_container_width=True,
    hide_index=True,
    selection_mode="single-row",
    on_select="rerun",
    key="explorer_table",
)

selected_rows = getattr(selection, "selection", {}).get("rows", [])
if not selected_rows:
    st.caption("Click a row to see the per-IP drill-down.")
    st.stop()

selected_idx = selected_rows[0]
selected = table_view.reset_index(drop=True).iloc[selected_idx]
selected_ip = str(selected.get("source_ip", ""))

# ─── Drill-down panel ────────────────────────────────────────────────────

st.divider()
st.subheader(f"Drill-down · `{selected_ip}`")

detail_col1, detail_col2, detail_col3 = st.columns(3)
detail_col1.metric("Threat level", str(selected.get("threat_level", "—")))
detail_col2.metric(
    "Anomaly score",
    f"{float(selected.get('anomaly_score') or 0):.3f}",
)
detail_col3.metric(
    "Total requests",
    int(selected.get("total_requests") or 0),
)

# Raw anomaly record
with st.expander("Full anomaly record", expanded=False):
    full_row = filtered[filtered["source_ip"] == selected_ip]
    st.dataframe(full_row, use_container_width=True, hide_index=True)

# Per-IP feature vector (computed on demand from sample logs)
st.markdown("**Computed feature vector** (from available log data)")

if logs_df.empty or "source_ip" not in logs_df.columns:
    st.info(
        "No log data available to recompute features. Run `make mock` to "
        "populate `data/samples/sample_logs.csv`."
    )
else:
    ip_logs = logs_df[logs_df["source_ip"] == selected_ip].copy()
    if ip_logs.empty:
        st.info(
            f"No log rows for `{selected_ip}` in the local sample set. "
            "This IP was probably captured from live traffic only."
        )
    else:
        try:
            features_df = extract_features(ip_logs)
        except Exception as exc:
            st.error(f"Feature extraction failed: {exc}")
            features_df = pd.DataFrame()

        if features_df.empty:
            st.info("Feature extractor returned no rows for this IP.")
        else:
            feature_row = features_df.iloc[0].to_dict()
            pretty = pd.DataFrame(
                [{"feature": k, "value": v} for k, v in feature_row.items()]
            )
            st.dataframe(pretty, use_container_width=True, hide_index=True)

    st.markdown("**Recent logs from this IP**")
    if ip_logs.empty:
        st.caption("No matching logs.")
    else:
        show_cols = [
            c
            for c in [
                "datetime",
                "log_type",
                "status",
                "http_method",
                "request_path",
                "event_description",
            ]
            if c in ip_logs.columns
        ]
        st.dataframe(
            ip_logs[show_cols].sort_values(
                show_cols[0] if show_cols else ip_logs.columns[0],
                ascending=False,
            ).head(50),
            use_container_width=True,
            hide_index=True,
        )

# ─── Sidebar ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Explorer tips")
    st.markdown(
        "- Start wide (all threat levels, all time), then narrow.\n"
        "- The score slider snaps to ±0.01; IsolationForest "
        "`decision_function` scores are in roughly `[-0.5, 0.5]`.\n"
        "- The drill-down recomputes features from local sample data, "
        "so NULLs from pre-expansion rows may look different than what "
        "the live API sees. See `MODEL_JOURNAL.md` → *Open questions*."
    )
