"""
pages/4_Dev_Analyst.py
----------------------
Developer / Analyst view — Isolation Forest internals, Legacy/Modern split
evaluation, and raw anomaly investigation.

Audience: ML engineers and security analysts who need to interrogate the
model, compare cohort behaviours, and drill into raw anomaly evidence without
the operational noise of the SOC view.

Design rules enforced here:
- Rule zero: missing data shown as missing — no front-end imputation.
- No 3D charts, no pie charts.
- All bar-chart Y-axes start at 0 (rangemode="tozero").
- Legacy model grouped separately from Modern model (Gestalt: proximity).
- Light theme, high contrast, dark text on white/near-white backgrounds.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from src.common.time_utils import utcnow
from src.dashboard._api import (
    api_status_banner,
    dashboard_autorefresh,
    fetch_anomalies,
    fetch_metrics,
    format_number,
    inject_sidebar_css,
    sb_row,
    sb_section,
    sb_status,
    sidebar_brand,
)
from src.model.versioning import ModelNotFoundError, registry

# ─── Page config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Dev / Analyst — SAP AI Security",
    page_icon="\U0001f52c",
    layout="wide",
)

inject_sidebar_css()

dashboard_autorefresh(key="dev_analyst_autorefresh")

# ─── Palette ─────────────────────────────────────────────────────────────────
# Threat colours match the existing SOC palette in _api.py.

THREAT_COLOURS = {
    "high": "#e74c3c",
    "medium": "#f39c12",
    "low": "#2ecc71",
}
_LEGACY_COLOUR = "#1a73e8"
_MODERN_COLOUR = "#7b2cbf"
_CHART_BG = "#f9f9f9"
_GRID = "#e0e0e0"
_FONT = {"color": "#333333"}
_MISSING = "missing"  # explicit label — never an imputed value

# ─── Remote data ─────────────────────────────────────────────────────────────

_metrics = fetch_metrics()
_raw_anomalies = fetch_anomalies(limit=200)
_api_live = api_status_banner(_metrics)

# ─── On-disk model registry ───────────────────────────────────────────────────


def _load_split(feature_set: str):
    """Return LoadedModel for the given split, or None if unavailable."""
    try:
        return registry.load_for_feature_set(feature_set)
    except (ModelNotFoundError, Exception):
        return None


_legacy = _load_split("legacy")
_modern = _load_split("modern")

# ─── Build anomaly DataFrame ─────────────────────────────────────────────────


def _build_df(raw: list[dict]) -> pd.DataFrame:
    if not raw:
        return pd.DataFrame()
    df = pd.DataFrame(raw)
    df["detected_at"] = pd.to_datetime(df.get("detected_at"), errors="coerce", utc=True)
    for col in ("anomaly_score", "total_requests", "error_rate", "pipeline_mttd_ms", "e2e_mttd_ms"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


_df = _build_df(_raw_anomalies)

# ─── Page header ─────────────────────────────────────────────────────────────

st.title("\U0001f52c Developer / Analyst view")
st.caption(
    "Model internals, Legacy/Modern split evaluation, and raw anomaly investigation. "
    "**Rule zero**: missing data is displayed as missing — no front-end imputation or interpolation."
)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Top-level KPIs
# Most critical information anchored at top-left per layout hierarchy rule.
# ═══════════════════════════════════════════════════════════════════════════════

st.subheader("Detection & model health")

_now = utcnow()
_today_start = _now.replace(hour=0, minute=0, second=0, microsecond=0)

if not _df.empty:
    _critical_today = int(
        _df[(_df["threat_level"] == "high") & (_df["detected_at"] >= _today_start)].shape[0]
    )
    _med_score = _df["anomaly_score"].median()
    _score_display = f"{_med_score:.4f}" if pd.notna(_med_score) else _MISSING
    _missing_score = int(_df["anomaly_score"].isna().sum())
    _missing_e2e = int(_df["e2e_mttd_ms"].isna().sum())
else:
    _critical_today = 0
    _score_display = _MISSING
    _missing_score = 0
    _missing_e2e = 0

_pipe_p50_raw = (_metrics.get("pipeline_mttd_ms") or {}).get("p50")
_pipe_p50 = f"{int(_pipe_p50_raw):,} ms" if _pipe_p50_raw is not None else _MISSING

if _legacy and _modern:
    _health_label, _health_delta = "Both active", "legacy + modern"
elif _legacy or _modern:
    _which = "legacy only" if _legacy else "modern only"
    _health_label, _health_delta = "Partial", _which
else:
    _health_label, _health_delta = "No model", "run make train"

_kpi = st.columns(4)
_kpi[0].metric(
    "Critical anomalies today",
    format_number(_critical_today),
    help="threat_level = 'high', detected_at >= UTC midnight.",
)
_kpi[1].metric(
    "Model health",
    _health_label,
    delta=_health_delta,
    help="Whether both legacy and modern Isolation Forest models are registered on disk.",
)
_kpi[2].metric(
    "Median anomaly score (last 200)",
    _score_display,
    help="IsolationForest decision_function output. More negative = more anomalous. NULL shown as 'missing'.",
)
_kpi[3].metric(
    "Pipeline MTTD p50",
    _pipe_p50,
    help="Median detected_at - ingested_at across all pipeline runs. Sourced from /metrics.",
)

_null_parts: list[str] = []
if _missing_score:
    _null_parts.append(f"{_missing_score} anomaly score(s) NULL")
if _missing_e2e:
    _null_parts.append(f"{_missing_e2e} e2e_mttd_ms NULL")
if _null_parts:
    st.info(
        "Data quality notice: " + ", ".join(_null_parts)
        + " in the last 200 records. Shown as gaps — not filled."
    )

st.divider()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Legacy vs. Modern model cards
# Gestalt grouping: each cohort is a self-contained bordered container.
# ═══════════════════════════════════════════════════════════════════════════════

st.subheader("Legacy vs. Modern model split")
st.caption(
    "Routing logic: a row is sent to the **Modern** model if `app_diversity > 0` or "
    "`region_diversity > 0` (meaning `SAP_APPLICATION` or `REGION_CODE` was present). "
    "Pre-expansion rows always route to **Legacy** (13 features vs. 16 for Modern)."
)

_col_legacy, _col_modern = st.columns(2)


def _model_card(col, model, label: str, colour: str) -> None:
    with col, st.container(border=True):
            st.markdown(
                f"<h4 style='color:{colour};margin-bottom:4px'>{label} model</h4>",
                unsafe_allow_html=True,
            )
            if model is None:
                st.warning("Not found on disk. Run `make train` to produce both splits.")
                return

            m = model.manifest
            cv = m.get("cv_scores") or {}
            score_dist = m.get("score_distribution") or {}
            features: list[str] = m.get("feature_columns") or []

            r1 = st.columns(3)
            r1[0].metric("Version", (m.get("version_tag") or "—")[:18])
            r1[1].metric("Training samples", format_number(m.get("training_samples", 0)))
            r1[2].metric("Contamination", f"{float(m.get('contamination') or 0):.3f}")

            r2 = st.columns(3)
            r2[0].metric("Features", len(features))
            r2[1].metric(
                "CV anomaly-rate mean",
                f"{float(cv.get('mean') or 0):.3f}" if cv else _MISSING,
            )
            r2[2].metric(
                "CV anomaly-rate std",
                f"{float(cv.get('std') or 0):.3f}" if cv else _MISSING,
            )

            st.caption(
                f"Trained `{m.get('trained_at', 'unknown')}` · "
                f"{m.get('model_type', 'unknown')} · "
                f"notes: {m.get('notes') or '—'}"
            )

            # Score distribution bar chart — if manifest has it.
            if score_dist:
                _labels = ["min", "p10", "median", "p90", "max"]
                _vals = [score_dist.get(lbl) for lbl in _labels]
                _texts = [f"{v:.4f}" if v is not None else _MISSING for v in _vals]
                _y = [v if v is not None else 0.0 for v in _vals]
                _has_gap = any(v is None for v in _vals)

                fig_dist = go.Figure()
                fig_dist.add_bar(
                    x=_labels,
                    y=_y,
                    marker_color=colour,
                    text=_texts,
                    textposition="outside",
                )
                fig_dist.update_layout(
                    height=220,
                    margin=dict(t=24, b=8, l=8, r=8),
                    paper_bgcolor="white",
                    plot_bgcolor=_CHART_BG,
                    font=_FONT,
                    yaxis=dict(
                        title="decision_function score",
                        rangemode="tozero",
                        gridcolor=_GRID,
                    ),
                    xaxis_title=None,
                )
                st.plotly_chart(fig_dist, use_container_width=True, key=f"dist_{label}")
                if _has_gap:
                    st.caption("Some score percentiles are NULL in the manifest — shown as 0, labelled 'missing'.")
            else:
                st.caption("Score distribution absent from manifest — retrain to populate.")

            with st.expander("Feature columns", expanded=False):
                if features:
                    st.dataframe(
                        pd.DataFrame({"feature": features}),
                        use_container_width=True,
                        hide_index=True,
                        height=min(35 * (len(features) + 1), 340),
                    )
                else:
                    st.info("No feature columns recorded in manifest.")


_model_card(_col_legacy, _legacy, "Legacy", _LEGACY_COLOUR)
_model_card(_col_modern, _modern, "Modern", _MODERN_COLOUR)

st.caption(
    "There is a risk of **model staleness on the legacy cohort** as pre-expansion rows "
    "accumulate without the three diversity features, which could represent a risk of "
    "**lower detection sensitivity for legacy-origin traffic**, requiring us to enrich "
    "the data by **backfilling `SAP_APPLICATION` and `REGION_CODE` for pre-expansion "
    "rows so they graduate to the modern feature set**."
)

st.divider()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Anomaly score time series
# Heavy time-series focus per project design rule.
# ═══════════════════════════════════════════════════════════════════════════════

st.subheader("Anomaly score evolution")

if _df.empty:
    st.info("No anomaly data available from the API. Start the pipeline with `make run`.")
else:
    _f1, _f2 = st.columns([2, 2])
    with _f1:
        _window_choice = st.selectbox(
            "Time window",
            ["1 h", "6 h", "24 h", "72 h", "All"],
            index=2,
            key="ts_window",
        )
    with _f2:
        _levels_choice = st.multiselect(
            "Threat levels",
            ["high", "medium", "low"],
            default=["high", "medium", "low"],
            key="ts_levels",
        )

    _wmap = {"1 h": 1, "6 h": 6, "24 h": 24, "72 h": 72, "All": None}
    _ts = _df.copy()
    _wh = _wmap[_window_choice]
    if _wh:
        _ts = _ts[_ts["detected_at"] >= _now - timedelta(hours=_wh)]
    if _levels_choice:
        _ts = _ts[_ts["threat_level"].isin(_levels_choice)]

    if _ts.empty:
        st.info("No records match the selected window / levels.")
    else:
        # Scatter: score per event over time.
        # Rows with NULL detected_at are already dropped; NULL anomaly_score becomes a gap.
        _score_df = _ts.dropna(subset=["detected_at"])
        _n_missing_score = int(_score_df["anomaly_score"].isna().sum())

        fig_scatter = px.scatter(
            _score_df,
            x="detected_at",
            y="anomaly_score",
            color="threat_level",
            color_discrete_map=THREAT_COLOURS,
            hover_data=["source_ip", "total_requests", "error_rate"],
            labels={
                "detected_at": "Detected at (UTC)",
                "anomaly_score": "Anomaly score",
            },
            title=f"Anomaly score per event — {len(_score_df)} records",
        )
        # Decision thresholds as reference lines.
        fig_scatter.add_hline(
            y=-0.3,
            line_dash="dash",
            line_color="#e74c3c",
            annotation_text="High threshold (-0.3)",
            annotation_position="bottom right",
        )
        fig_scatter.add_hline(
            y=-0.1,
            line_dash="dot",
            line_color="#f39c12",
            annotation_text="Medium threshold (-0.1)",
            annotation_position="top right",
        )
        fig_scatter.update_layout(
            height=400,
            paper_bgcolor="white",
            plot_bgcolor=_CHART_BG,
            font=_FONT,
            legend_title_text="Threat level",
            margin=dict(t=44, b=20),
            yaxis=dict(gridcolor=_GRID),
            xaxis=dict(gridcolor=_GRID),
        )
        st.plotly_chart(fig_scatter, use_container_width=True, key="score_scatter")

        if _n_missing_score:
            st.caption(
                f"Data gap: {_n_missing_score} record(s) have a NULL anomaly_score "
                "and appear as gaps above — not interpolated."
            )

        # Bar chart: anomalies per hour, stacked by threat level. Y-axis from 0.
        st.markdown("**Anomaly count by hour**")
        _hourly = (
            _ts.dropna(subset=["detected_at"])
            .assign(hour_bucket=lambda d: d["detected_at"].dt.floor("1h"))
            .groupby(["hour_bucket", "threat_level"])
            .size()
            .reset_index(name="count")
        )
        fig_bar = px.bar(
            _hourly,
            x="hour_bucket",
            y="count",
            color="threat_level",
            color_discrete_map=THREAT_COLOURS,
            barmode="stack",
            labels={"hour_bucket": "Hour (UTC)", "count": "Anomaly count"},
        )
        fig_bar.update_yaxes(rangemode="tozero", gridcolor=_GRID)  # strict: Y starts at 0
        fig_bar.update_xaxes(gridcolor=_GRID)
        fig_bar.update_layout(
            height=300,
            paper_bgcolor="white",
            plot_bgcolor=_CHART_BG,
            font=_FONT,
            margin=dict(t=20, b=20),
        )
        st.plotly_chart(fig_bar, use_container_width=True, key="hourly_bar")

        st.caption(
            "There is a risk of **anomaly score clustering near the medium threshold** "
            "(-0.1), which could represent a risk of **threshold miscalibration causing "
            "high-severity events to be suppressed as medium**, requiring us to enrich "
            "the data by **running threshold sensitivity analysis in `3_Admin.py` and "
            "tracking the score distribution across consecutive retraining cycles**."
        )

st.divider()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Feature distributions from stored anomaly records
# Only total_requests and error_rate are persisted; full vectors need Explorer.
# ═══════════════════════════════════════════════════════════════════════════════

st.subheader("Feature distributions by threat level")
st.caption(
    "Only `total_requests` and `error_rate` are stored in the `ANOMALIES` table. "
    "For the full 13- or 16-feature vector of a specific IP, use `2_Explorer.py`."
)

if _df.empty:
    st.info("No anomaly data to plot.")
else:
    _feat = _df.dropna(subset=["threat_level"]).copy()

    _bl, _br = st.columns(2)

    with _bl:
        st.markdown("**Total requests per anomaly (box)**")
        fig_req = px.box(
            _feat,
            x="threat_level",
            y="total_requests",
            color="threat_level",
            color_discrete_map=THREAT_COLOURS,
            points="all",
            labels={"total_requests": "Total requests", "threat_level": "Threat level"},
            category_orders={"threat_level": ["high", "medium", "low"]},
        )
        fig_req.update_yaxes(rangemode="tozero", gridcolor=_GRID)
        fig_req.update_layout(
            height=340,
            showlegend=False,
            paper_bgcolor="white",
            plot_bgcolor=_CHART_BG,
            font=_FONT,
            margin=dict(t=20, b=20),
        )
        st.plotly_chart(fig_req, use_container_width=True, key="box_requests")

    with _br:
        st.markdown("**Error rate per anomaly (box)**")
        fig_err = px.box(
            _feat,
            x="threat_level",
            y="error_rate",
            color="threat_level",
            color_discrete_map=THREAT_COLOURS,
            points="all",
            labels={"error_rate": "Error rate", "threat_level": "Threat level"},
            category_orders={"threat_level": ["high", "medium", "low"]},
        )
        fig_err.update_yaxes(rangemode="tozero", gridcolor=_GRID)
        fig_err.update_layout(
            height=340,
            showlegend=False,
            paper_bgcolor="white",
            plot_bgcolor=_CHART_BG,
            font=_FONT,
            margin=dict(t=20, b=20),
        )
        st.plotly_chart(fig_err, use_container_width=True, key="box_errors")

    # Scatter: request volume vs. error rate coloured by threat level.
    st.markdown("**Request volume vs. error rate**")
    _scatter_src = _feat.dropna(subset=["total_requests", "error_rate"])
    _n_dropped = len(_feat) - len(_scatter_src)

    fig_fscatter = px.scatter(
        _scatter_src,
        x="total_requests",
        y="error_rate",
        color="threat_level",
        color_discrete_map=THREAT_COLOURS,
        opacity=0.72,
        hover_data=["source_ip", "anomaly_score", "detected_at"],
        labels={"total_requests": "Total requests", "error_rate": "Error rate"},
    )
    fig_fscatter.update_xaxes(rangemode="tozero", gridcolor=_GRID)
    fig_fscatter.update_yaxes(rangemode="tozero", gridcolor=_GRID)
    fig_fscatter.update_layout(
        height=380,
        paper_bgcolor="white",
        plot_bgcolor=_CHART_BG,
        font=_FONT,
        margin=dict(t=20, b=20),
    )
    st.plotly_chart(fig_fscatter, use_container_width=True, key="feat_scatter")

    if _n_dropped:
        st.caption(
            f"Data gap: {_n_dropped} record(s) excluded from scatter — NULL in "
            "`total_requests` or `error_rate`. Not imputed."
        )

    st.caption(
        "There is a risk of **high-volume, low-error-rate IPs evading detection** "
        "(top-left cluster: many requests, near-zero error rate), which could represent "
        "a risk of **slow-burn enumeration or data exfiltration going unscored**, "
        "requiring us to enrich the data by **persisting `request_rate_zscore` and "
        "`interarrival_std` into the `ANOMALIES` table for retrospective analysis**."
    )

st.divider()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — MTTD evolution
# Both pipeline (internal) and end-to-end MTTD tracked as time series.
# NULL e2e values shown as chart gaps — not interpolated.
# ═══════════════════════════════════════════════════════════════════════════════

st.subheader("MTTD evolution")
st.caption(
    "`pipeline_mttd_ms` = detected_at - ingested_at (internal pipeline latency). "
    "`e2e_mttd_ms` = detected_at - earliest log event time (real-world detection "
    "latency). NULL e2e values appear as gaps in the chart — never filled."
)

_pipe_p95_raw = (_metrics.get("pipeline_mttd_ms") or {}).get("p95")
_e2e_p50_raw = (_metrics.get("e2e_mttd_ms") or {}).get("p50")
_e2e_p95_raw = (_metrics.get("e2e_mttd_ms") or {}).get("p95")

_mttd_kpi = st.columns(4)
_mttd_kpi[0].metric("Pipeline MTTD p50", _pipe_p50)
_mttd_kpi[1].metric(
    "Pipeline MTTD p95",
    f"{int(_pipe_p95_raw):,} ms" if _pipe_p95_raw is not None else _MISSING,
)
_mttd_kpi[2].metric(
    "E2E MTTD p50",
    f"{int(_e2e_p50_raw):,} ms" if _e2e_p50_raw is not None else _MISSING,
)
_mttd_kpi[3].metric(
    "E2E MTTD p95",
    f"{int(_e2e_p95_raw):,} ms" if _e2e_p95_raw is not None else _MISSING,
)

if not _df.empty:
    _mttd_df = _df.dropna(subset=["detected_at"]).sort_values("detected_at")

    fig_mttd = go.Figure()
    fig_mttd.add_scatter(
        x=_mttd_df["detected_at"],
        y=_mttd_df["pipeline_mttd_ms"],
        mode="markers+lines",
        name="Pipeline MTTD",
        line=dict(color=_LEGACY_COLOUR, width=1.5),
        marker=dict(size=5),
        connectgaps=False,  # NaN renders as a visible gap — not interpolated
    )
    fig_mttd.add_scatter(
        x=_mttd_df["detected_at"],
        y=_mttd_df["e2e_mttd_ms"],
        mode="markers+lines",
        name="E2E MTTD",
        line=dict(color=_MODERN_COLOUR, width=1.5, dash="dot"),
        marker=dict(size=5),
        connectgaps=False,
    )
    fig_mttd.update_layout(
        height=380,
        xaxis_title="Detected at (UTC)",
        yaxis_title="MTTD (ms)",
        paper_bgcolor="white",
        plot_bgcolor=_CHART_BG,
        font=_FONT,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(t=44, b=20),
        yaxis=dict(rangemode="tozero", gridcolor=_GRID),
        xaxis=dict(gridcolor=_GRID),
    )
    st.plotly_chart(fig_mttd, use_container_width=True, key="mttd_line")

    _gap_pipe = int(_mttd_df["pipeline_mttd_ms"].isna().sum())
    _gap_e2e = int(_mttd_df["e2e_mttd_ms"].isna().sum())
    _gap_parts: list[str] = []
    if _gap_pipe:
        _gap_parts.append(f"{_gap_pipe} pipeline_mttd_ms NULL")
    if _gap_e2e:
        _gap_parts.append(f"{_gap_e2e} e2e_mttd_ms NULL")
    if _gap_parts:
        st.caption("Gaps in chart: " + ", ".join(_gap_parts) + ". Not interpolated.")

    st.caption(
        "There is a risk of **e2e_mttd_ms spiking during background retrain windows** "
        "(retrain blocks feature extraction for ~30 s each cycle), which could represent "
        "a risk of **detection blind spots every ~4 hours**, requiring us to enrich the "
        "data by **logging retrain start/end timestamps and overlaying them as vertical "
        "bands on this chart**."
    )

st.divider()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Raw anomaly investigation table
# Full records, NULL cells displayed as blank. No imputation.
# ═══════════════════════════════════════════════════════════════════════════════

st.subheader("Raw anomaly records")
st.caption(
    "Values shown exactly as received from `/anomalies`. NULL cells are blank — "
    "never filled or inferred. Use column headers to sort."
)

if _df.empty:
    st.info("No anomaly records available from the API.")
else:
    _show_cols = [
        "detected_at",
        "source_ip",
        "threat_level",
        "anomaly_score",
        "total_requests",
        "error_rate",
        "pipeline_mttd_ms",
        "e2e_mttd_ms",
        "webhook_sent",
        "incident_report_path",
    ]
    _avail = [c for c in _show_cols if c in _df.columns]
    _table_df = _df[_avail].copy()

    def _colour_threat(val: object) -> str:
        _map = {
            "high": "background-color:#fde8e8;font-weight:bold",
            "medium": "background-color:#fef3cd;font-weight:bold",
            "low": "background-color:#d4edda;font-weight:bold",
        }
        return _map.get(str(val).lower(), "")

    _styled = _table_df.style.map(_colour_threat, subset=["threat_level"])

    st.dataframe(_styled, use_container_width=True, hide_index=True, height=440)

    _null_counts = _table_df.isna().sum()
    _null_cols = _null_counts[_null_counts > 0]
    if not _null_cols.empty:
        st.caption(
            "NULL counts: "
            + ", ".join(f"`{col}`: {n}" for col, n in _null_cols.items())
        )

# ─── Sidebar ─────────────────────────────────────────────────────────────────

with st.sidebar:
    sidebar_brand("DEV / ANALYST")

    # ── Model cohort status ──────────────────────────────────────────────
    st.markdown(sb_section("Model cohorts"), unsafe_allow_html=True)
    st.markdown(sb_status("Legacy model", _legacy is not None, "13 features"), unsafe_allow_html=True)
    st.markdown(sb_status("Modern model", _modern is not None, "16 features"), unsafe_allow_html=True)

    # ── Routing logic ────────────────────────────────────────────────────
    st.markdown(sb_section("Routing rules"), unsafe_allow_html=True)
    st.markdown(
        sb_row("Legacy", "diversity = 0 (both)")
        + sb_row("Modern", "either diversity > 0"),
        unsafe_allow_html=True,
    )

    # ── Score thresholds ─────────────────────────────────────────────────
    st.markdown(sb_section("Score thresholds"), unsafe_allow_html=True)
    st.markdown(
        sb_row("High", "-0.3  (ALERT_HIGH_THRESHOLD)")
        + sb_row("Medium", "-0.1  (ALERT_MEDIUM_THRESHOLD)")
        + sb_row("Gate", "-0.1  (ANOMALY_SCORE_THRESHOLD)"),
        unsafe_allow_html=True,
    )

    # ── Related pages ────────────────────────────────────────────────────
    st.markdown(sb_section("Related pages"), unsafe_allow_html=True)
    st.markdown(
        "- `1_Model` — registry & training metrics\n"
        "- `2_Explorer` — per-IP drill-down\n"
        "- `3_Admin` — threshold tuning"
    )

    st.divider()
    with st.expander("Connectivity", expanded=False):
        st.json({
            "api_live": _api_live,
            "anomalies_loaded": len(_raw_anomalies),
            "metrics_live": bool(_metrics),
            "legacy_on_disk": _legacy is not None,
            "modern_on_disk": _modern is not None,
        })
