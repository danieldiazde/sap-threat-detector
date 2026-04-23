"""
pages/1_Model.py
----------------
Model registry + training metrics view for the SOC dashboard.

Reads directly from the on-disk model registry (``models/``) — no API
round-trip required. Read-only: activating a different version is a
production decision that happens through ``registry.activate()`` in a
deliberate script, not a dashboard button.

Owner: AI & Data Science Specialist / Security Viz Lead
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from src.dashboard._api import dashboard_autorefresh, format_number
from src.model.versioning import ModelNotFoundError, registry

st.set_page_config(
    page_title="Model — SAP AI Security",
    page_icon="\U0001f9e0",
    layout="wide",
)

dashboard_autorefresh(key="model_autorefresh")

st.title("\U0001f9e0 Model registry & training metrics")
st.caption(
    "What model is live, what it was trained on, how well it holds together "
    "across folds. Training happens in `scripts/train_model.py`; this page "
    "observes the result."
)

# ─── Active model ────────────────────────────────────────────────────────

current = registry.current_version()
if current is None:
    st.warning(
        "No trained model yet. Run `make train` (or "
        "`python -m scripts.train_model`) to bootstrap one, then refresh."
    )
    st.stop()

try:
    active = registry.load(current)
except ModelNotFoundError as exc:
    st.error(f"Active version `{current}` is broken on disk: {exc}")
    st.stop()

manifest = active.manifest
metrics = manifest.get("cv_scores", {}) or {}
hyperparams = manifest.get("hyperparams", {}) or {}
features = manifest.get("feature_columns", []) or []

st.subheader("Active version")

headline_cols = st.columns(4)
headline_cols[0].metric("Version", manifest.get("version_tag", "unknown"))
headline_cols[1].metric("Algorithm", manifest.get("model_type", "unknown"))
headline_cols[2].metric("Training samples", format_number(manifest.get("training_samples", 0)))
headline_cols[3].metric(
    "Contamination",
    f"{float(manifest.get('contamination') or 0.0):.3f}",
)

st.caption(
    f"Trained at `{manifest.get('trained_at', 'unknown')}` · "
    f"{len(features)} features · notes: {manifest.get('notes') or '—'}"
)

st.divider()

# ─── Metrics ─────────────────────────────────────────────────────────────

st.subheader("Training metrics")

if not metrics:
    st.info(
        "No CV metrics recorded for this version. Older checkpoints may pre-date "
        "the metrics-in-manifest convention; retrain to pick them up."
    )

metric_cols = st.columns(3)
metric_cols[0].metric(
    "CV anomaly-rate mean",
    f"{float(metrics.get('mean', 0) or 0):.3f}" if metrics else "—",
)
metric_cols[1].metric(
    "CV anomaly-rate std",
    f"{float(metrics.get('std', 0) or 0):.3f}" if metrics else "—",
)
metric_cols[2].metric(
    "Folds",
    format_number(metrics.get("folds")) if metrics else "—",
)

# Score-distribution visual if the manifest carries it (newer training runs do).
score_dist = manifest.get("score_distribution", {}) or {}
if score_dist:
    st.markdown("**Score distribution** (from training-time evaluation)")
    fig_dist = go.Figure()
    labels = ["min", "p10", "median", "p90", "max"]
    values = [score_dist.get(label, 0) for label in labels]
    fig_dist.add_bar(x=labels, y=values, marker_color="#0070f3")
    fig_dist.update_layout(
        height=260,
        margin=dict(t=10, b=10, l=10, r=10),
        yaxis_title="decision_function score",
        xaxis_title=None,
    )
    st.plotly_chart(fig_dist, use_container_width=True)
else:
    st.caption(
        "Score distribution not present in manifest — it's written by "
        "`src/model/evaluate.py` at training time. Retrain to populate."
    )

st.divider()

# ─── Hyperparameters + feature list side by side ─────────────────────────

left, right = st.columns(2)

with left:
    st.subheader("Hyperparameters")
    if hyperparams:
        hp_df = pd.DataFrame(
            [{"parameter": k, "value": str(v)} for k, v in hyperparams.items()]
        )
        st.dataframe(hp_df, use_container_width=True, hide_index=True)
    else:
        st.info("No hyperparameters recorded.")
    st.caption(
        "Defaults live in `src/common/config.py` (`MODEL_N_ESTIMATORS`, "
        "`MODEL_MAX_SAMPLES`, `MODEL_CONTAMINATION`, `MODEL_RANDOM_STATE`)."
    )

with right:
    st.subheader("Feature columns")
    if features:
        st.dataframe(
            pd.DataFrame({"feature": features}),
            use_container_width=True,
            hide_index=True,
            height=min(38 * (len(features) + 1), 430),
        )
    else:
        st.info("No feature columns recorded.")
    st.caption(
        "The canonical list is in `src/model/schema.py::FEATURE_COLUMNS`. "
        "When adding features, expand there and retrain."
    )

st.divider()

# ─── Version history ─────────────────────────────────────────────────────

st.subheader("Version history")

versions = registry.list_versions()
rows: list[dict[str, object]] = []
for tag in versions:
    try:
        loaded = registry.load(tag)
    except ModelNotFoundError:
        continue
    m = loaded.manifest
    rows.append(
        {
            "version": tag,
            "active": tag == current,
            "model_type": m.get("model_type"),
            "trained_at": m.get("trained_at"),
            "samples": m.get("training_samples"),
            "contamination": m.get("contamination"),
            "notes": (m.get("notes") or "")[:60],
        }
    )

if rows:
    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )
    st.caption(
        "Activating a different version is a production decision — do it "
        "via `registry.activate('<version>')` in a deliberate script, not "
        "from the dashboard."
    )
else:
    st.info("No version manifests found on disk.")

# ─── Sidebar pointers ────────────────────────────────────────────────────

with st.sidebar:
    st.header("Training journal")
    st.markdown(
        "Every experiment should land in `docs/MODEL_JOURNAL.md`. "
        "Before opening a hyperparameter sweep or swapping algorithms, "
        "add a row describing the hypothesis and *why*."
    )
    st.divider()
    st.markdown(
        "**Retrain locally:**\n"
        "```\nmake train\n```"
    )
    st.markdown(
        "**Sweep idea queue** is in the *Open questions* section of "
        "`MODEL_JOURNAL.md`."
    )
