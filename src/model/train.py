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
from src.model.features import extract_features, feature_matrix
from src.model.schema import FEATURE_COLUMNS, FEATURE_COLUMNS_LEGACY
from src.model.versioning import registry

logger = get_logger(__name__)


def _coerce_max_samples(raw: str) -> int | float | str:
    """IsolationForest accepts int, float, or the sentinel string 'auto'."""
    if raw == "auto":
        return "auto"
    try:
        return int(raw)
    except ValueError:
        return float(raw)


# Expansion-only features: non-zero only on rows ingested after schema expansion
# (commit 5b5d777, 2026-04-21).  app_diversity and region_diversity use nunique()
# which returns 0 when all values are NaN — that's the legacy signal.
_EXPANSION_DISCRIMINATORS: tuple[str, ...] = ("app_diversity", "region_diversity")


def _modern_mask(features_df: pd.DataFrame) -> pd.Series:
    """True for rows with any non-zero expansion discriminator (post-expansion data)."""
    cols = [c for c in _EXPANSION_DISCRIMINATORS if c in features_df.columns]
    if not cols:
        return pd.Series(False, index=features_df.index)
    return features_df[cols].gt(0).any(axis=1)


def train_split(raw_df: pd.DataFrame, *, model_type: str | None = None) -> dict[str, Any]:
    """
    Extract features from *raw_df*, split into legacy/modern subsets, and
    train one model per subset.  Returns::

        {
            "legacy": <single-model report>,   # present if legacy rows exist
            "modern": <single-model report>,   # present if modern rows exist
        }

    Either key may be absent when no rows fall into that split.  The pipeline
    should register both reports with :class:`ModelVersionRepository`.

    Use this as the training entry point instead of calling
    :func:`extract_features` + :func:`train` manually.
    """
    features_df = extract_features(raw_df)
    if features_df.empty:
        raise ValueError("Cannot train on empty feature DataFrame")

    model_type = (model_type or settings.model_type).lower()
    mask = _modern_mask(features_df)

    results: dict[str, Any] = {}

    legacy_df = features_df[~mask]
    if not legacy_df.empty:
        results["legacy"] = _train_one(
            legacy_df.reset_index(drop=True),
            feature_cols=FEATURE_COLUMNS_LEGACY,
            feature_set="legacy",
            model_type=model_type,
        )
        logger.info(
            "train_split.legacy_done",
            extra={"samples": len(legacy_df), "version": results["legacy"]["version_tag"]},
        )

    modern_df = features_df[mask]
    if not modern_df.empty:
        results["modern"] = _train_one(
            modern_df.reset_index(drop=True),
            feature_cols=FEATURE_COLUMNS,
            feature_set="modern",
            model_type=model_type,
        )
        logger.info(
            "train_split.modern_done",
            extra={"samples": len(modern_df), "version": results["modern"]["version_tag"]},
        )

    if not results:
        raise ValueError("train_split: both legacy and modern subsets are empty")

    logger.info(
        "train_split.done",
        extra={
            "legacy_samples": len(legacy_df),
            "modern_samples": len(modern_df),
            "splits": list(results.keys()),
        },
    )
    return results


def _train_one(
    features_df: pd.DataFrame,
    *,
    feature_cols: tuple[str, ...],
    feature_set: str,
    model_type: str,
) -> dict[str, Any]:
    """Train a single model on *features_df* using *feature_cols*."""
    X = feature_matrix(features_df, columns=feature_cols)
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
        feature_columns=list(feature_cols),
        hyperparams=hyperparams,
        training_samples=len(X),
        cv_scores=metrics.get("cv_anomaly_rate_stability", {}),
        feature_set=feature_set,
        notes=f"Trained from split={feature_set}, rows={len(X)}",
    )

    return {
        "version_tag": version_tag,
        "feature_set": feature_set,
        "model_type": model_type,
        "trained_at": trained_at.isoformat(),
        "training_samples": int(len(X)),
        "feature_columns": list(feature_cols),
        "hyperparams": hyperparams,
        "contamination": hyperparams.get("contamination", settings.model_contamination),
        "cv_scores": metrics.get("cv_anomaly_rate_stability", {}),
        "metrics": metrics,
        "elapsed_seconds": round(elapsed, 3),
    }


def train(features_df: pd.DataFrame, *, model_type: str | None = None) -> dict[str, Any]:
    """
    Train a single ``"modern"`` model on an already-extracted *features_df*.

    Kept for backward compatibility with :mod:`scripts.train_model`.  New
    callers that have raw log data should use :func:`train_split` instead,
    which handles feature extraction and the legacy/modern split automatically.
    """
    if features_df.empty:
        raise ValueError("Cannot train on empty feature DataFrame")
    model_type = (model_type or settings.model_type).lower()
    logger.info(
        "train.start",
        extra={"model_type": model_type, "samples": len(features_df), "features": list(FEATURE_COLUMNS)},
    )
    report = _train_one(
        features_df,
        feature_cols=FEATURE_COLUMNS,
        feature_set="modern",
        model_type=model_type,
    )
    logger.info(
        "train.done",
        extra={
            "version_tag": report["version_tag"],
            "elapsed_seconds": report["elapsed_seconds"],
            "anomaly_rate": report["metrics"].get("anomaly_rate"),
        },
    )
    return report


# ─── Model-specific trainers ───────────────────────────────────────────────


def _train_isolation_forest(X_scaled: np.ndarray) -> tuple[IsolationForest, dict[str, Any]]:
    hyperparams = {
        "contamination": settings.model_contamination,
        "n_estimators": settings.model_n_estimators,
        "max_samples": _coerce_max_samples(settings.model_max_samples),
        "random_state": settings.model_random_state,
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
