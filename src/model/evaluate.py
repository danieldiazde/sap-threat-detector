"""
evaluate.py
-----------
Model quality metrics.

For the unsupervised regime we're in until April 13, "evaluation" means:
- score distribution stats (so we can tune thresholds before real data arrives)
- silhouette score when it applies (DBSCAN)
- cross-validated anomaly-rate stability (is the contamination hyperparam
  finding a consistent fraction of outliers across folds?)

When real labeled incidents exist (post April 13), the same entrypoint
gains precision/recall via the ``y_true`` argument.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_fscore_support, silhouette_score
from sklearn.model_selection import KFold

from src.common.logging import get_logger

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

CV_FOLDS: int = 5
MIN_SAMPLES_FOR_CV: int = 25


def evaluate(
    *,
    model: Any,
    X_scaled: np.ndarray,
    model_type: str,
    y_true: np.ndarray | None = None,
) -> dict[str, Any]:
    """
    Compute proxy metrics for an unsupervised detector.

    Args:
        model: A fitted estimator exposing ``decision_function``.
        X_scaled: The scaled feature matrix the model was trained on.
        model_type: "isolation_forest" or "dbscan" — affects which
            auxiliary metrics are computed.
        y_true: Optional binary labels (1 = anomaly, 0 = normal) when
            real labeled data becomes available. Enables precision/recall.

    Returns:
        A JSON-serializable dict of metrics. Keys vary by model type but
        always include ``score_distribution``, ``anomaly_rate``, and
        ``sample_count``.
    """
    if len(X_scaled) == 0:
        return {"sample_count": 0, "score_distribution": {}, "anomaly_rate": 0.0}

    scores = model.decision_function(X_scaled)
    flagged = scores < 0
    anomaly_rate = float(flagged.mean())

    metrics: dict[str, Any] = {
        "sample_count": int(len(X_scaled)),
        "anomaly_rate": anomaly_rate,
        "score_distribution": _describe(scores),
        "score_decile_gap": _decile_gap(scores),
        "model_type": model_type,
    }

    if model_type == "dbscan":
        try:
            metrics["silhouette"] = _safe_silhouette(X_scaled, model)
        except Exception as exc:  # noqa: BLE001
            logger.warning("evaluate.silhouette_failed", extra={"error": str(exc)})
            metrics["silhouette"] = None

    if model_type == "isolation_forest" and len(X_scaled) >= MIN_SAMPLES_FOR_CV:
        metrics["cv_anomaly_rate_stability"] = _cv_stability(X_scaled, model)

    if y_true is not None and len(y_true) == len(X_scaled):
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, flagged.astype(int), average="binary", zero_division=0
        )
        metrics["precision"] = float(precision)
        metrics["recall"] = float(recall)
        metrics["f1"] = float(f1)

    logger.info(
        "evaluate.done",
        extra={
            "model_type": model_type,
            "anomaly_rate": round(anomaly_rate, 4),
            "sample_count": metrics["sample_count"],
        },
    )
    return metrics


# ─── Helpers ───────────────────────────────────────────────────────────────


def _describe(scores: np.ndarray) -> dict[str, float]:
    return {
        "min": float(scores.min()),
        "p10": float(np.percentile(scores, 10)),
        "median": float(np.median(scores)),
        "p90": float(np.percentile(scores, 90)),
        "max": float(scores.max()),
        "mean": float(scores.mean()),
        "std": float(scores.std(ddof=0)),
    }


def _decile_gap(scores: np.ndarray) -> float:
    """
    Gap between the 90th and 10th percentile scores.

    A bigger gap means the model is confidently separating its most-normal
    from most-anomalous points. A small gap suggests the model is indecisive
    and thresholds will be noisy.
    """
    if len(scores) < 2:
        return 0.0
    return float(np.percentile(scores, 90) - np.percentile(scores, 10))


def _safe_silhouette(X: np.ndarray, model: Any) -> float | None:
    """Compute silhouette score when there are ≥2 clusters."""
    labels = model.predict(X) if hasattr(model, "predict") else None
    if labels is None:
        return None
    unique = set(labels.tolist())
    unique.discard(-1)
    if len(unique) < 2:
        return None
    mask = np.array([label != -1 for label in labels])
    if mask.sum() < 2:
        return None
    return float(silhouette_score(X[mask], labels[mask]))


def _cv_stability(X: np.ndarray, reference_model: Any) -> dict[str, float]:
    """
    Cross-validate the anomaly rate of an IsolationForest to check stability.

    Re-trains on each fold with the same hyperparams and reports the mean
    and std of flagged fractions. A stable model has low std.
    """
    params = reference_model.get_params()
    relevant = {
        k: params[k]
        for k in ("contamination", "n_estimators", "max_samples", "random_state")
        if k in params
    }

    kf = KFold(n_splits=CV_FOLDS, shuffle=True, random_state=42)
    rates: list[float] = []
    for train_idx, _ in kf.split(X):
        fold_model = IsolationForest(**relevant)
        fold_model.fit(X[train_idx])
        fold_scores = fold_model.decision_function(X[train_idx])
        rates.append(float((fold_scores < 0).mean()))

    return {
        "mean": float(np.mean(rates)),
        "std": float(np.std(rates, ddof=0)),
        "folds": CV_FOLDS,
    }
