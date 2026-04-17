"""
train.py
--------
ANALYZE phase — unsupervised model training.

Primary: ``sklearn.ensemble.IsolationForest`` — recommended by the SAP
presentation for security log anomaly detection.

Secondary: ``src.model.dbscan_detector.DBSCANDetector`` — selectable via
``MODEL_TYPE=dbscan`` in the environment.

Training entrypoint is ``scripts/train_model.py``; this module exposes
callable functions only.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow
from src.model.dbscan_detector import DBSCANDetector
from src.model.evaluate import evaluate
from src.model.features import feature_matrix
from src.model.schema import FEATURE_COLUMNS
from src.model.versioning import registry

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

DEFAULT_N_ESTIMATORS: int = 200
DEFAULT_MAX_SAMPLES: int | str = "auto"
RANDOM_STATE: int = 42


def train(features_df: pd.DataFrame, *, model_type: str | None = None) -> dict[str, Any]:
    """
    Train an anomaly detector on *features_df*.

    Dispatches on *model_type* (defaults to ``settings.model_type``),
    evaluates the model, writes a new registry version, and returns the
    training report::

        {
            "version_tag": "...",
            "model_type": "...",
            "training_samples": int,
            "hyperparams": {...},
            "metrics": {...},
            "elapsed_seconds": float,
        }
    """
    model_type = (model_type or settings.model_type).lower()
    if features_df.empty:
        raise ValueError("Cannot train on empty feature DataFrame")

    X = feature_matrix(features_df)
    logger.info(
        "train.start",
        extra={
            "model_type": model_type,
            "samples": len(X),
            "features": list(FEATURE_COLUMNS),
        },
    )

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    started = time.perf_counter()
    if model_type == "dbscan":
        model, hyperparams = _train_dbscan(X_scaled)
    else:
        model, hyperparams = _train_isolation_forest(X_scaled)
    elapsed = time.perf_counter() - started

    metrics = evaluate(model=model, X_scaled=X_scaled, model_type=model_type)

    trained_at = utcnow()
    version_tag = registry.save(
        model=model,
        scaler=scaler,
        model_type=model_type,
        feature_columns=list(FEATURE_COLUMNS),
        hyperparams=hyperparams,
        training_samples=len(X),
        cv_scores=metrics.get("cv_anomaly_rate_stability", {}),
        notes=f"Trained from features_df rows={len(X)}",
    )

    report = {
        "version_tag": version_tag,
        "model_type": model_type,
        "trained_at": trained_at.isoformat(),
        "training_samples": int(len(X)),
        "feature_columns": list(FEATURE_COLUMNS),
        "hyperparams": hyperparams,
        "contamination": hyperparams.get("contamination", settings.model_contamination),
        "cv_scores": metrics.get("cv_anomaly_rate_stability", {}),
        "metrics": metrics,
        "elapsed_seconds": round(elapsed, 3),
    }
    logger.info(
        "train.done",
        extra={
            "version_tag": version_tag,
            "elapsed_seconds": round(elapsed, 3),
            "anomaly_rate": metrics.get("anomaly_rate"),
        },
    )
    return report


# ─── Model-specific trainers ───────────────────────────────────────────────


def _train_isolation_forest(X_scaled: np.ndarray) -> tuple[IsolationForest, dict[str, Any]]:
    hyperparams = {
        "contamination": settings.model_contamination,
        "n_estimators": DEFAULT_N_ESTIMATORS,
        "max_samples": DEFAULT_MAX_SAMPLES,
        "random_state": RANDOM_STATE,
    }
    model = IsolationForest(**hyperparams)
    model.fit(X_scaled)
    return model, hyperparams


def _train_dbscan(X_scaled: np.ndarray) -> tuple[DBSCANDetector, dict[str, Any]]:
    hyperparams = {
        "eps": 0.8,
        "min_samples": max(3, int(0.01 * len(X_scaled))),
    }
    detector = DBSCANDetector(**hyperparams)
    detector.fit(X_scaled)
    return detector, hyperparams
