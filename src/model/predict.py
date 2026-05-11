"""
predict.py
----------
DETECT phase — run a trained model on incoming log batches.

Core responsibilities:
- Load the active model via :class:`ModelRegistry` (cached).
- Score features with the fitted scaler + decision_function.
- Assign threat levels with explicit, settings-driven thresholds.
- **Stamp MTTD**: compute ``pipeline_mttd_ms`` (detected_at - ingested_at)
  and ``e2e_mttd_ms`` (detected_at - min log datetime in the batch) on
  every row, and publish the samples to :class:`MetricsRegistry`.
- Maintain a **sliding context window** of recent batches per IP so we
  can detect "multi-bucket" anomalies — IPs that stay elevated across
  several consecutive windows.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from collections import deque
from datetime import datetime

import numpy as np
import pandas as pd
from src.common.config import settings
from src.common.logging import get_logger
from src.common.metrics import metrics
from src.common.time_utils import elapsed_ms, utcnow
from src.model.features import feature_matrix
from src.model.schema import FEATURE_COLUMNS, FEATURE_COLUMNS_LEGACY
from src.model.versioning import LoadedModel, ModelNotFoundError, registry

logger = get_logger(__name__)


# ─── Sliding context window ────────────────────────────────────────────────

_CONTEXT_WINDOW: deque[tuple[datetime, dict[str, float]]] = deque()


def _update_context(detected_at: datetime, features_df: pd.DataFrame) -> dict[str, int]:
    """
    Push per-IP total_requests from this batch into the sliding window
    and return per-IP consecutive-elevated-bucket counts.
    """
    snapshot = {
        str(row.source_ip): float(row.total_requests)
        for row in features_df.itertuples(index=False)
    }
    _CONTEXT_WINDOW.append((detected_at, snapshot))

    cutoff = detected_at.timestamp() - settings.model_context_window_minutes * 60
    while _CONTEXT_WINDOW and _CONTEXT_WINDOW[0][0].timestamp() < cutoff:
        _CONTEXT_WINDOW.popleft()

    # Per-IP count of consecutive buckets where the IP's request volume was
    # above the batch mean — cheap proxy for multi-bucket anomaly.
    consecutive: dict[str, int] = {}
    for _, hist_snapshot in _CONTEXT_WINDOW:
        if not hist_snapshot:
            continue
        mean_req = sum(hist_snapshot.values()) / len(hist_snapshot)
        for ip, total in hist_snapshot.items():
            if total > mean_req:
                consecutive[ip] = consecutive.get(ip, 0) + 1
    return consecutive


def clear_context_window() -> None:
    """Empty the sliding context window — used by tests."""
    _CONTEXT_WINDOW.clear()


# ─── Prediction ────────────────────────────────────────────────────────────


# Features that distinguish post-expansion rows from pre-expansion rows.
# app_diversity and region_diversity use nunique() which returns 0 when
# all values in the group are NaN — the reliable legacy signal.
_EXPANSION_DISCRIMINATORS: tuple[str, ...] = ("app_diversity", "region_diversity")


def _modern_mask(features_df: pd.DataFrame) -> pd.Series:
    """True for rows with any non-zero expansion discriminator."""
    cols = [c for c in _EXPANSION_DISCRIMINATORS if c in features_df.columns]
    if not cols:
        return pd.Series(False, index=features_df.index)
    return features_df[cols].gt(0).any(axis=1)


def predict(
    features_df: pd.DataFrame,
    *,
    ingested_at: datetime,
    batch_min_log_time: datetime | None = None,
    raw_log_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """
    Score *features_df* and return a DataFrame with detection columns added.

    Rows are routed to the legacy model (13-feature, FEATURE_COLUMNS_LEGACY)
    or the modern model (16-feature, FEATURE_COLUMNS) based on whether any
    expansion-only features are non-zero.  Both models are loaded from the
    registry; the modern model falls back to the legacy model (and vice versa)
    when only one is available on disk.

    MTTD attribution:
        - ``pipeline_mttd_ms`` = ``detected_at - ingested_at`` (scalar, same on
          every row).
        - ``e2e_mttd_ms``: when ``raw_log_df`` is provided, computed per source_ip
          as ``detected_at - min(log.datetime per source_ip)``. Otherwise falls
          back to ``batch_min_log_time`` as a single scalar (legacy callers).

    Added columns:
        anomaly_score (float), is_anomaly (bool), threat_level (str),
        detected_at (datetime), pipeline_mttd_ms (int), e2e_mttd_ms (int|None),
        multi_bucket_count (int), model_version (str), model_type (str).
    """
    if features_df.empty:
        return _empty_output()

    detected_at = utcnow()
    pipeline_mttd = elapsed_ms(ingested_at, detected_at)
    # Per-IP earliest event time → per-anomaly e2e MTTD. Falls back to the
    # batch-wide minimum only when callers don't supply ``raw_log_df``.
    min_dt_by_ip: dict[str, datetime] = {}
    if raw_log_df is not None and not raw_log_df.empty and {"source_ip", "datetime"}.issubset(raw_log_df.columns):
        valid = raw_log_df[["source_ip", "datetime"]].dropna()
        if not valid.empty:
            min_dt_by_ip = (
                valid.groupby("source_ip")["datetime"].min().to_dict()
            )

    legacy_model, modern_model = _load_models()
    mask = _modern_mask(features_df)

    # Use each model's own feature_columns from the manifest — this handles
    # the fallback case where load_for_feature_set returns the same model for
    # both slots (e.g. first boot before any split retrain has occurred).
    legacy_cols = tuple(legacy_model.manifest.get("feature_columns") or list(FEATURE_COLUMNS_LEGACY))
    modern_cols = tuple(modern_model.manifest.get("feature_columns") or list(FEATURE_COLUMNS))

    parts: list[pd.DataFrame] = []
    for subset_mask, loaded, feat_cols in (
        (~mask, legacy_model, legacy_cols),
        (mask, modern_model, modern_cols),
    ):
        subset = features_df[subset_mask]
        if subset.empty:
            continue
        X = feature_matrix(subset, columns=feat_cols)
        X_scaled = loaded.scaler.transform(X)
        scores = loaded.model.decision_function(X_scaled)

        part = subset.copy()
        part["anomaly_score"] = scores
        part["is_anomaly"] = scores < settings.anomaly_score_threshold
        part["threat_level"] = _assign_threat_levels(scores)
        part["model_version"] = loaded.version_tag
        part["model_type"] = loaded.model_type
        parts.append(part)

    if not parts:
        return _empty_output()

    out = pd.concat(parts, ignore_index=True)
    multi_bucket = _update_context(detected_at, features_df)

    out["detected_at"] = detected_at
    out["ingested_at"] = ingested_at
    out["pipeline_mttd_ms"] = int(pipeline_mttd)

    if min_dt_by_ip:
        def _e2e_for_ip(ip: str) -> int | None:
            start = min_dt_by_ip.get(ip)
            return elapsed_ms(start, detected_at) if start is not None else None
        out["e2e_mttd_ms"] = out["source_ip"].map(_e2e_for_ip)
    elif batch_min_log_time is not None:
        out["e2e_mttd_ms"] = elapsed_ms(batch_min_log_time, detected_at)
    else:
        out["e2e_mttd_ms"] = None

    out["multi_bucket_count"] = out["source_ip"].map(multi_bucket).fillna(0).astype(int)

    metrics.observe_pipeline_mttd(pipeline_mttd)
    e2e_observed = out["e2e_mttd_ms"].dropna()
    if not e2e_observed.empty:
        metrics.observe_e2e_mttd(int(e2e_observed.mean()))

    anomaly_count = int(out["is_anomaly"].sum())
    logger.info(
        "predict.done",
        extra={
            "ips_scored": len(out),
            "anomalies": anomaly_count,
            "pipeline_mttd_ms": pipeline_mttd,
            "e2e_mttd_ms_mean": int(e2e_observed.mean()) if not e2e_observed.empty else None,
            "legacy_rows": int((~mask).sum()),
            "modern_rows": int(mask.sum()),
        },
    )
    return out


# ─── Threat level assignment ───────────────────────────────────────────────


def _assign_threat_levels(scores: np.ndarray) -> np.ndarray:
    """
    Bucket anomaly scores into 'high' | 'medium' | 'low' using vectorized
    ``np.select``. Thresholds come from settings and are tunable without
    code changes.
    """
    conditions = [
        scores < settings.alert_high_threshold,
        scores < settings.alert_medium_threshold,
    ]
    return np.select(conditions, ["high", "medium"], default="low")


# ─── Model loading ─────────────────────────────────────────────────────────

_active_legacy: LoadedModel | None = None
_active_modern: LoadedModel | None = None


def _load_models() -> tuple[LoadedModel, LoadedModel]:
    """
    Return (legacy_model, modern_model), loading from disk on first call or
    after ``reset_active_model()``.

    When only one model exists on disk (single-model deployment or first
    boot before a split retrain), both slots resolve to the same bundle via
    the ``load_for_feature_set`` fallback.
    """
    global _active_legacy, _active_modern
    if _active_legacy is None:
        try:
            _active_legacy = registry.load_for_feature_set("legacy")
        except ModelNotFoundError:
            logger.error("predict.no_legacy_model")
            raise
    if _active_modern is None:
        try:
            _active_modern = registry.load_for_feature_set("modern")
        except ModelNotFoundError:
            logger.error("predict.no_modern_model")
            raise
    return _active_legacy, _active_modern


def reset_active_model() -> None:
    """Force the next ``predict()`` call to reload both models from disk."""
    global _active_legacy, _active_modern
    _active_legacy = None
    _active_modern = None
    registry.invalidate_cache()


# ─── Helpers ───────────────────────────────────────────────────────────────


def _empty_output() -> pd.DataFrame:
    columns = [
        "source_ip",
        *FEATURE_COLUMNS,
        "anomaly_score",
        "is_anomaly",
        "threat_level",
        "detected_at",
        "ingested_at",
        "pipeline_mttd_ms",
        "e2e_mttd_ms",
        "multi_bucket_count",
        "model_version",
        "model_type",
    ]
    return pd.DataFrame({col: pd.Series(dtype="object") for col in columns})


def anomalies_only(scored_df: pd.DataFrame) -> pd.DataFrame:
    """Convenience: return only the rows flagged as anomalous."""
    if scored_df.empty:
        return scored_df
    return scored_df[scored_df["is_anomaly"]].copy()
