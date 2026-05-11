"""
llm_predict.py
--------------
DETECT phase — score a batch of LLM rows and emit per-cohort anomaly records.

Shape contract: returns a DataFrame with the same column shape the SAP
detector produces (``src/model/predict.py::predict``), so ``src/pipeline.py``
can ``pd.concat`` the two and run the existing alert / dedup / incident-report
loop unchanged. LLM-specific columns (``detector``, ``llm_model_id``,
``llm_prompt_category``, ``rule_ids``, ``if_global_score``, ``if_category_score``)
are added; SAP-only columns (e.g. ``source_ip``, ``total_requests``,
``error_rate``) are emitted as None / 0 so downstream code that reads them
still works.

Scoring strategy:
  - For each row in the batch, score with the global IF (always) and with
    the per-category IF (when one exists for that category).
  - Aggregate to (model_id, prompt_category) cohorts: count of anomaly
    predictions, mean decision_function on each model.
  - Run the rule layer (src/model/llm_rules.py) on each cohort.
  - Emit one anomaly record per cohort that *either* fires a rule or has
    enough rows flagged by the IF ensemble.
  - Severity = max(rule severity, IF-derived severity). When both global and
    per-category IFs agree on a cohort being anomalous, escalate one tier.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd
from src.common.logging import get_logger
from src.common.metrics import metrics
from src.common.time_utils import elapsed_ms, utcnow
from src.model.llm_features import (
    build_llm_feature_matrix,
    is_scorable_llm_row,
    llm_feature_matrix,
)
from src.model.llm_rules import (
    SEVERITY_RANK,
    FiredRule,
    Severity,
    evaluate_cohort,
    max_severity,
)
from src.model.llm_train import LLMModelBundle, llm_registry

logger = get_logger(__name__)


# ─── Tunables ──────────────────────────────────────────────────────────────
# Cohort is anomalous when either:
#   - any rule fires, OR
#   - more than this fraction of cohort rows are predicted -1 by the global IF.
# Calibrated 2026-04-28 from the preview run on 5,000 real HANA rows: average
# cohort size in production batches is ~15 rows, so a 0.05 floor only requires
# 1 anomalous row — within sampling noise. Raised to 0.15 (≈15x the
# contamination rate of 0.01) so an IF-only emit needs at least 2-3 rows in a
# 15-row cohort to depart meaningfully from the background.
COHORT_ANOMALY_FRACTION_THRESHOLD: float = 0.15

# IF-derived severity thresholds, applied to the cohort's anomaly fraction
# on the global model. The rule severity is computed independently and the
# final severity is max() of the two (with one-tier escalation on ensemble
# agreement, see _combine_severity). Tightened 2026-04-28 — old 0.20/0.50
# admitted too many IF-only "medium" emissions on small cohorts.
IF_SEVERITY_THRESHOLDS: dict[Severity, float] = {
    "high":   0.60,
    "medium": 0.35,
    "low":    COHORT_ANOMALY_FRACTION_THRESHOLD,
}

# Ensemble agreement (one-tier severity escalation) requires meaningful
# anomaly fractions on BOTH the global and per-category IF, not just both
# above the emit floor. Without this, a low-severity cohort got promoted to
# medium whenever both models flagged a single row.
ENSEMBLE_AGREEMENT_FRACTION: float = 0.20


# ─── Public API ────────────────────────────────────────────────────────────


def predict_llm(
    raw_df: pd.DataFrame,
    *,
    ingested_at: datetime,
    batch_min_log_time: datetime | None = None,
    bundle: LLMModelBundle | None = None,
) -> pd.DataFrame:
    """
    Score LLM rows in *raw_df* and return per-cohort anomaly records.

    Args:
        raw_df: Raw log DataFrame from the poll. Non-LLM rows are filtered
            out internally — caller doesn't need to pre-split.
        ingested_at: When the batch was ingested. Used for pipeline_mttd_ms.
        batch_min_log_time: Earliest ``datetime`` across the batch's logs;
            used for e2e_mttd_ms. Pass None to skip e2e tracking.
        bundle: Optional pre-loaded bundle (for tests). When None, loads from
            the registry.

    Returns:
        DataFrame with one row per anomalous (model_id, prompt_category)
        cohort. Empty if nothing flagged. Column shape matches
        :func:`src.model.predict.predict` plus LLM-specific columns; see
        :func:`_empty_output`.
    """
    detected_at = utcnow()

    if raw_df is None or raw_df.empty:
        return _empty_output()

    mask = is_scorable_llm_row(raw_df)
    df = raw_df[mask].copy()
    if df.empty:
        return _empty_output()

    if bundle is None:
        bundle = llm_registry.load("latest")

    profiles = bundle.profiles
    baselines = bundle.metadata.get("category_baselines", {})

    features = build_llm_feature_matrix(df, profiles)
    if features.empty:
        return _empty_output()

    # Score with the global model on every scorable row.
    X = llm_feature_matrix(features)
    Xs_global = bundle.global_scaler.transform(X)
    global_scores = bundle.global_model.decision_function(Xs_global)
    global_predict = bundle.global_model.predict(Xs_global)  # -1 / 1
    features = features.copy()
    features["__global_score"] = global_scores
    features["__global_anomaly"] = (global_predict == -1).astype(int)

    # Score with per-category model where available; else borrow the global score.
    category_scores = np.full(len(features), np.nan)
    category_predict = np.zeros(len(features), dtype=int)
    for category, group_idx in features.groupby("llm_prompt_category", sort=False).groups.items():
        cat_model = bundle.category_models.get(str(category))
        cat_scaler = bundle.category_scalers.get(str(category))
        if cat_model is None or cat_scaler is None:
            continue
        Xs_cat = cat_scaler.transform(X[features.index.get_indexer(group_idx)])
        category_scores[features.index.get_indexer(group_idx)] = cat_model.decision_function(Xs_cat)
        category_predict[features.index.get_indexer(group_idx)] = (cat_model.predict(Xs_cat) == -1).astype(int)
    features["__category_score"] = category_scores
    features["__category_anomaly"] = category_predict

    # Pull a few raw fields onto the features frame for the rule layer (rules
    # need them; features matrix doesn't include them by design).
    for col in (
        "log_type",
        "llm_prompt_tokens",
        "llm_total_tokens",
        "llm_cost_usd",
        "llm_response_time_ms",
        "llm_finish_reason",
        "llm_status",
    ):
        if col in df.columns:
            features[col] = df.loc[features.index, col].values

    # Cohort aggregation + rule evaluation.
    pipeline_mttd = elapsed_ms(ingested_at, detected_at)
    # Per-cohort earliest event time → per-cohort e2e MTTD. Fallback to the
    # batch-wide scalar only when datetime isn't available.
    if "datetime" in df.columns:
        cohort_min_dt = (
            df.dropna(subset=["datetime"])
            .groupby(["llm_model_id", "llm_prompt_category"], sort=False)["datetime"]
            .min()
            .to_dict()
        )
    else:
        cohort_min_dt = {}
    batch_fallback_e2e = (
        elapsed_ms(batch_min_log_time, detected_at) if batch_min_log_time else None
    )

    anomaly_rows: list[dict[str, Any]] = []
    e2e_observations: list[int] = []
    grouped = features.groupby(["llm_model_id", "llm_prompt_category"], sort=False)
    for (model_id, category), cohort_rows in grouped:
        fired = evaluate_cohort(
            cohort_rows,
            model_id=str(model_id),
            category=str(category),
            profiles=profiles,
            baselines=baselines,
        )
        cohort_start = cohort_min_dt.get((model_id, category))
        cohort_e2e_mttd: int | None
        if cohort_start is not None:
            cohort_e2e_mttd = elapsed_ms(cohort_start, detected_at)
        else:
            cohort_e2e_mttd = batch_fallback_e2e
        anomaly = _maybe_emit_cohort_anomaly(
            cohort_rows=cohort_rows,
            model_id=str(model_id),
            category=str(category),
            fired=fired,
            detected_at=detected_at,
            ingested_at=ingested_at,
            pipeline_mttd=pipeline_mttd,
            e2e_mttd=cohort_e2e_mttd,
            bundle_version=bundle.metadata.get("version_tag", "unknown"),
        )
        if anomaly is not None:
            anomaly_rows.append(anomaly)
            if cohort_e2e_mttd is not None:
                e2e_observations.append(cohort_e2e_mttd)

    metrics.observe_pipeline_mttd(pipeline_mttd)
    if e2e_observations:
        metrics.observe_e2e_mttd(int(sum(e2e_observations) / len(e2e_observations)))

    out = pd.DataFrame(anomaly_rows) if anomaly_rows else _empty_output()

    logger.info(
        "llm_predict.done",
        extra={
            "rows_scored": len(features),
            "cohorts_examined": int(grouped.ngroups),
            "anomalies_emitted": len(out),
            "pipeline_mttd_ms": pipeline_mttd,
            "e2e_mttd_ms_mean": (
                int(sum(e2e_observations) / len(e2e_observations))
                if e2e_observations
                else None
            ),
        },
    )
    return out


# ─── Cohort anomaly synthesis ──────────────────────────────────────────────


def _maybe_emit_cohort_anomaly(
    *,
    cohort_rows: pd.DataFrame,
    model_id: str,
    category: str,
    fired: list[FiredRule],
    detected_at: datetime,
    ingested_at: datetime,
    pipeline_mttd: int,
    e2e_mttd: int | None,
    bundle_version: str,
) -> dict[str, Any] | None:
    """Synthesize a single anomaly record for a cohort, or None if benign."""
    n = len(cohort_rows)
    if n == 0:
        return None

    global_anomaly_fraction = float(cohort_rows["__global_anomaly"].mean())
    category_anomaly_fraction = float(cohort_rows["__category_anomaly"].mean())
    global_score = float(cohort_rows["__global_score"].mean())
    category_score_mean = cohort_rows["__category_score"].mean()
    category_score = float(category_score_mean) if pd.notna(category_score_mean) else None

    # Skip when neither rules nor IF say much.
    if not fired and global_anomaly_fraction < COHORT_ANOMALY_FRACTION_THRESHOLD:
        return None

    rule_severity = max_severity(fired)
    if_severity = _severity_from_fraction(global_anomaly_fraction)
    severity = _combine_severity(
        rule_severity=rule_severity,
        if_severity=if_severity,
        global_anomaly_fraction=global_anomaly_fraction,
        category_anomaly_fraction=category_anomaly_fraction,
    )

    rule_ids = sorted({f.rule_id for f in fired})
    rule_context = {f.rule_id: f.context for f in fired}

    return {
        # Detector identity
        "detector": "llm",
        # Cohort key
        "llm_model_id": model_id,
        "llm_prompt_category": category,
        "source_ip": None,
        # Severity / scores
        "threat_level": severity,
        "is_anomaly": True,
        "anomaly_score": global_score,
        "if_global_score": global_score,
        "if_category_score": category_score,
        # Rule attribution
        "rule_ids": json.dumps(rule_ids),
        "rule_context": json.dumps(rule_context, default=str),
        # Timing — same fields as the SAP detector
        "detected_at": detected_at,
        "ingested_at": ingested_at,
        "pipeline_mttd_ms": int(pipeline_mttd),
        "e2e_mttd_ms": e2e_mttd,
        # Cohort summary
        "total_requests": int(n),
        "global_anomaly_fraction": global_anomaly_fraction,
        "category_anomaly_fraction": category_anomaly_fraction,
        "rules_fired_count": len(fired),
        "model_version": bundle_version,
        "model_type": "llm_isolation_forest_ensemble",
        # Compatibility shims for the existing alerting path
        "error_rate": global_anomaly_fraction,
        "multi_bucket_count": 0,
    }


def _severity_from_fraction(fraction: float) -> Severity:
    if fraction >= IF_SEVERITY_THRESHOLDS["high"]:
        return "high"
    if fraction >= IF_SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    if fraction >= IF_SEVERITY_THRESHOLDS["low"]:
        return "low"
    return "low"


def _combine_severity(
    *,
    rule_severity: Severity,
    if_severity: Severity,
    global_anomaly_fraction: float,
    category_anomaly_fraction: float,
) -> Severity:
    """
    Final severity = max(rule, IF) with a one-tier escalation when global and
    category IFs agree the cohort is anomalous (both above the low threshold).
    """
    base_rank = max(SEVERITY_RANK[rule_severity], SEVERITY_RANK[if_severity])
    ensemble_agreement = (
        global_anomaly_fraction >= ENSEMBLE_AGREEMENT_FRACTION
        and category_anomaly_fraction >= ENSEMBLE_AGREEMENT_FRACTION
    )
    if ensemble_agreement:
        base_rank = min(3, base_rank + 1)
    inverse = {v: k for k, v in SEVERITY_RANK.items()}
    return inverse[base_rank]


# ─── Empty-output shape ────────────────────────────────────────────────────


_OUTPUT_COLUMNS: tuple[str, ...] = (
    "detector",
    "llm_model_id",
    "llm_prompt_category",
    "source_ip",
    "threat_level",
    "is_anomaly",
    "anomaly_score",
    "if_global_score",
    "if_category_score",
    "rule_ids",
    "rule_context",
    "detected_at",
    "ingested_at",
    "pipeline_mttd_ms",
    "e2e_mttd_ms",
    "total_requests",
    "global_anomaly_fraction",
    "category_anomaly_fraction",
    "rules_fired_count",
    "model_version",
    "model_type",
    "error_rate",
    "multi_bucket_count",
)


def _empty_output() -> pd.DataFrame:
    return pd.DataFrame({col: pd.Series(dtype="object") for col in _OUTPUT_COLUMNS})
