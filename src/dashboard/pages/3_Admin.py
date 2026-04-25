"""
pages/3_Admin.py
----------------
Ops-and-config surface for the dashboard.

Three sections:

1. Readiness checks (HANA, model, pipeline) — live probe to `/ready`.
2. Settings inspector — what the process loaded from env, with secrets
   redacted. Useful when debugging "why is this in mock mode?".
3. Threshold preview — slide candidate high/medium thresholds and see
   how the last 200 anomalies *would have* been classified. Preview
   only: no setting is mutated.

Owner: Security Viz Lead / Cloud Engineer
"""

from __future__ import annotations

from dataclasses import fields
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from src.common.config import settings
from src.dashboard._api import (
    dashboard_autorefresh,
    fetch_anomalies,
    fetch_health,
    fetch_metrics,
    fetch_readiness,
    format_number,
    inject_sidebar_css,
    sb_row,
    sb_section,
    sidebar_brand,
)

st.set_page_config(
    page_title="Admin — SAP AI Security",
    page_icon="⚙️",
    layout="wide",
)

inject_sidebar_css()

dashboard_autorefresh(key="admin_autorefresh")

st.title("⚙️ Admin · readiness, config, threshold preview")

metrics_data = fetch_metrics()
health_data = fetch_health()
readiness_data = fetch_readiness()

# ─── Readiness ───────────────────────────────────────────────────────────

st.subheader("Readiness")

if not readiness_data:
    st.error(
        f"API unreachable at {settings.api_base_url}. Start it with `make api` "
        "and this panel will populate."
    )
else:
    ready = readiness_data.get("ready", False)
    st.markdown(f"**Overall** · {'✅ ready' if ready else '❌ not ready'}")
    checks = readiness_data.get("checks", [])
    if checks:
        ready_rows = [
            {
                "check": c.get("name", ""),
                "ok": "✅" if c.get("ok") else "❌",
                "detail": c.get("detail", ""),
            }
            for c in checks
        ]
        st.dataframe(
            pd.DataFrame(ready_rows),
            use_container_width=True,
            hide_index=True,
        )

st.caption(
    "`pipeline`, `hana`, `model` are probed live. Mock-mode components "
    "report `ok=True` with `detail='mock'` so CF readiness passes "
    "pre-integration."
)

# Pipeline counters
counters = metrics_data.get("counters", {}) if metrics_data else {}
st.markdown("**Pipeline counters**")
counter_cols = st.columns(5)
counter_cols[0].metric("Pipeline runs", format_number(counters.get("pipeline_runs_total")))
counter_cols[1].metric("Logs processed", format_number(counters.get("logs_processed_total")))
counter_cols[2].metric("Anomalies", format_number(counters.get("anomalies_detected_total")))
counter_cols[3].metric("Alerts sent", format_number(counters.get("alerts_sent_total")))
counter_cols[4].metric("Errors", format_number(counters.get("errors_total")))

st.divider()

# ─── Settings inspector ──────────────────────────────────────────────────

st.subheader("Settings inspector")

SECRET_FIELDS = {
    "sap_api_key",
    "hana_password",
    "sap_webhook_secret",
}


def _redact(name: str, value: Any) -> str:
    if name in SECRET_FIELDS:
        return "***set***" if value else "***not set***"
    if value is None:
        return "—"
    return str(value)


settings_rows: list[dict[str, str]] = []
for field in fields(settings):
    settings_rows.append(
        {
            "setting": field.name,
            "value": _redact(field.name, getattr(settings, field.name)),
        }
    )

# Derived mock flags
for flag in ("mock_api", "mock_webhook", "mock_hana", "is_production"):
    settings_rows.append(
        {
            "setting": f"{flag} (derived)",
            "value": str(getattr(settings, flag)),
        }
    )

st.dataframe(
    pd.DataFrame(settings_rows),
    use_container_width=True,
    hide_index=True,
    height=min(38 * (len(settings_rows) + 1), 520),
)

st.caption(
    "All values come from `src/common/config.py`. Secrets are shown as "
    "`***set***` or `***not set***`. Mutation happens only through env vars + "
    "process restart — there is no live-reload."
)

st.divider()

# ─── Threshold preview ───────────────────────────────────────────────────

st.subheader("Threshold preview")
st.caption(
    "What *would* have fired at different thresholds? This panel is "
    "preview-only — it does not change `ALERT_HIGH_THRESHOLD` or "
    "`ALERT_MEDIUM_THRESHOLD`. Update `.env` and restart to apply."
)

anomalies = fetch_anomalies(limit=200)
if not anomalies:
    st.info("No anomalies available to preview against. Run the pipeline to seed.")
else:
    anomalies_df = pd.DataFrame(anomalies)
    if "anomaly_score" not in anomalies_df.columns:
        st.info("Anomalies payload does not include `anomaly_score`.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            candidate_high = st.slider(
                "Candidate HIGH threshold (score < this ⇒ high)",
                min_value=-1.0,
                max_value=0.0,
                value=float(settings.alert_high_threshold),
                step=0.01,
                key="admin_high",
            )
        with col_b:
            candidate_medium = st.slider(
                "Candidate MEDIUM threshold (score < this ⇒ medium)",
                min_value=-1.0,
                max_value=0.0,
                value=float(settings.alert_medium_threshold),
                step=0.01,
                key="admin_medium",
            )

        if candidate_medium < candidate_high:
            st.warning(
                "Medium threshold is more restrictive than high. Normally "
                "medium > high (less negative). The preview still runs."
            )

        def _classify(score: float, high: float, medium: float) -> str:
            if score < high:
                return "high"
            if score < medium:
                return "medium"
            return "low"

        scores = anomalies_df["anomaly_score"].astype(float)
        anomalies_df["candidate_level"] = [
            _classify(s, candidate_high, candidate_medium) for s in scores
        ]

        current_counts = (
            anomalies_df["threat_level"].value_counts()
            if "threat_level" in anomalies_df.columns
            else pd.Series(dtype=int)
        )
        candidate_counts = anomalies_df["candidate_level"].value_counts()
        levels = ["high", "medium", "low"]

        fig = go.Figure()
        fig.add_bar(
            name="current settings",
            x=levels,
            y=[int(current_counts.get(level, 0)) for level in levels],
            marker_color="#3498db",
        )
        fig.add_bar(
            name="candidate thresholds",
            x=levels,
            y=[int(candidate_counts.get(level, 0)) for level in levels],
            marker_color="#e74c3c",
        )
        fig.update_layout(
            barmode="group",
            height=320,
            margin=dict(t=20, b=10, l=10, r=10),
            yaxis_title="anomalies",
        )
        st.plotly_chart(fig, use_container_width=True)

        changed = anomalies_df[
            anomalies_df.get("threat_level", "") != anomalies_df["candidate_level"]
        ]
        st.caption(
            f"{len(changed)} of {len(anomalies_df)} anomalies would be "
            f"reclassified at the candidate thresholds."
        )

        if not changed.empty:
            with st.expander("Show the reclassified rows"):
                cols = [
                    c
                    for c in [
                        "detected_at",
                        "source_ip",
                        "anomaly_score",
                        "threat_level",
                        "candidate_level",
                    ]
                    if c in changed.columns
                ]
                st.dataframe(changed[cols], use_container_width=True, hide_index=True)

st.divider()

# ─── HANA retention watchdog ─────────────────────────────────────────────

st.subheader("HANA retention watchdog")

st.markdown(
    """
Implementation trigger (from **ADR-0001**): archival must land by
**2026-06-15** *or* when `SECURITY_LOGS` row count exceeds **5,000,000**
*or* when HANA reports **>60% storage used** — whichever comes first.
"""
)

st.info(
    "This panel will show live row count + storage usage once the "
    "`/admin/hana-usage` endpoint is wired (tracked in ADR-0001 → "
    "*Implementation sketch*). For now, run "
    "`python -m scripts.hana_summary` manually and paste the headline "
    "into `docs/MODEL_JOURNAL.md` → *Dataset versions*."
)

# ─── Sidebar ─────────────────────────────────────────────────────────────

with st.sidebar:
    sidebar_brand("ADMIN")

    st.markdown(sb_section("Reference"), unsafe_allow_html=True)
    st.markdown(
        sb_row("Settings", "src/common/config.py")
        + sb_row("Training", "scripts/train_model.py")
        + sb_row("Schema", "src/storage/schema.sql")
        + sb_row("Branch rules", "CONTRIBUTING.md")
        + sb_row("Journal", "docs/MODEL_JOURNAL.md")
        + sb_row("ADRs", "docs/adr/"),
        unsafe_allow_html=True,
    )

    st.markdown(sb_section("Environment"), unsafe_allow_html=True)
    st.markdown(
        sb_row("Env", str(settings.environment))
        + sb_row("Mock API", str(settings.mock_api))
        + sb_row("Mock HANA", str(settings.mock_hana)),
        unsafe_allow_html=True,
    )
