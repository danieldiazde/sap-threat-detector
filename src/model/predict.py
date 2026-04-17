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
from src.model.schema import FEATURE_COLUMNS
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


def predict(
    features_df: pd.DataFrame,
    *,
    ingested_at: datetime,
    batch_min_log_time: datetime | None = None,
) -> pd.DataFrame:
    """
    Score *features_df* and return a DataFrame with detection columns added.

    Args:
        features_df: Per-IP feature matrix from :func:`extract_features`.
        ingested_at: When the pipeline received this batch (used for
            pipeline MTTD).
        batch_min_log_time: The earliest log event time in the batch (used
            for end-to-end MTTD). If omitted, e2e_mttd is set to None.

    Added columns:
        anomaly_score (float), is_anomaly (bool), threat_level (str),
        detected_at (datetime), pipeline_mttd_ms (int), e2e_mttd_ms (int|None),
        multi_bucket_count (int).
    """
    if features_df.empty:
        return _empty_output()

    loaded = _load_active_model()
    X = feature_matrix(features_df)
    X_scaled = loaded.scaler.transform(X)
    scores = loaded.model.decision_function(X_scaled)

    detected_at = utcnow()
    pipeline_mttd = elapsed_ms(ingested_at, detected_at)
    e2e_mttd = elapsed_ms(batch_min_log_time, detected_at) if batch_min_log_time else None

    multi_bucket = _update_context(detected_at, features_df)

    out = features_df.copy()
    out["anomaly_score"] = scores
    out["is_anomaly"] = scores < settings.anomaly_score_threshold
    out["threat_level"] = _assign_threat_levels(scores)
    out["detected_at"] = detected_at
    out["ingested_at"] = ingested_at
    out["pipeline_mttd_ms"] = int(pipeline_mttd)
    out["e2e_mttd_ms"] = e2e_mttd
    out["multi_bucket_count"] = out["source_ip"].map(multi_bucket).fillna(0).astype(int)
    out["model_version"] = loaded.version_tag
    out["model_type"] = loaded.model_type

    metrics.observe_pipeline_mttd(pipeline_mttd)
    if e2e_mttd is not None:
        metrics.observe_e2e_mttd(e2e_mttd)

    anomaly_count = int(out["is_anomaly"].sum())
    logger.info(
        "predict.done",
        extra={
            "ips_scored": len(out),
            "anomalies": anomaly_count,
            "pipeline_mttd_ms": pipeline_mttd,
            "e2e_mttd_ms": e2e_mttd,
            "model_version": loaded.version_tag,
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

_active_model: LoadedModel | None = None


def _load_active_model() -> LoadedModel:
    """Cache the active model bundle at module level to avoid disk hits."""
    global _active_model
    if _active_model is None or _active_model.version_tag != _requested_version():
        try:
            _active_model = registry.load(settings.model_version)
        except ModelNotFoundError:
            logger.error("predict.no_model_available")
            raise
    return _active_model


def _requested_version() -> str:
    if settings.model_version == "latest":
        return registry.current_version() or "latest"
    return settings.model_version


def reset_active_model() -> None:
    """Force the next ``predict()`` call to reload from disk."""
    global _active_model
    _active_model = None
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
