"""
features.py
-----------
ANALYZE phase — feature engineering from raw log DataFrames.

The feature matrix this module produces is the single input to every model
in ``src/model/``. The column set is authoritative in
:mod:`src.model.schema` — do not hardcode column lists anywhere else.

Rich per-IP features include request volume, error/denied ratios, path
suspiciousness, SQL-injection hits, port diversity, brute-force density,
and interarrival time stats. Brute-force and SQLi detection are keyword
matches against ``event_description`` — they're heuristics, not content
inspection.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.common.logging import get_logger
from src.ingestion.log_parser import validate_schema
from src.model.schema import (
    BRUTE_FORCE_KEYWORDS,
    DENIED_STATUSES,
    FEATURE_COLUMNS,
    SQL_INJECTION_KEYWORDS,
    SUSPICIOUS_PATH_FRAGMENTS,
    TEXT_STATUS_TO_CODE,
)

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

STATUS_4XX_LOWER: int = 400
STATUS_4XX_UPPER: int = 499
STATUS_5XX_LOWER: int = 500


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transform a raw log DataFrame into a per-IP feature matrix.

    Args:
        df: Raw logs with columns from :data:`REQUIRED_LOG_COLUMNS`.

    Returns:
        A DataFrame with one row per ``source_ip`` and columns matching
        :data:`FEATURE_COLUMNS`, plus the ``source_ip`` index column.
        Empty input yields an empty DataFrame with the correct columns.
    """
    if df.empty:
        return _empty_feature_frame()

    df = validate_schema(df)
    df = _enrich_raw(df)

    grouped = df.groupby("source_ip", sort=False)
    features = grouped.apply(_ip_features, include_groups=False).reset_index()

    features = _add_global_features(features)
    features = _ensure_all_columns(features)

    logger.debug(
        "features.extract",
        extra={"input_rows": len(df), "output_ips": len(features)},
    )
    return features


# ─── Enrichment (vectorized, runs once on the full frame) ──────────────────


def _enrich_raw(df: pd.DataFrame) -> pd.DataFrame:
    """Attach derived columns used by :func:`_ip_features`."""
    df = df.copy()

    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", utc=True)

    status_str = df["status"].astype(str).str.strip().str.upper()
    df["status_text"] = status_str
    # Map text statuses → synthetic HTTP codes, then fall back to numeric parse.
    numeric = pd.to_numeric(status_str, errors="coerce")
    mapped = status_str.map(TEXT_STATUS_TO_CODE)
    df["status_code"] = mapped.fillna(numeric)

    desc_upper = df["event_description"].fillna("").astype(str).str.upper()
    df["_desc_upper"] = desc_upper
    df["is_post"] = desc_upper.str.contains("POST", regex=False, na=False)

    df["is_suspicious_path"] = desc_upper.apply(
        lambda d: any(frag.upper() in d for frag in SUSPICIOUS_PATH_FRAGMENTS)
    )
    df["is_sql_injection"] = desc_upper.apply(
        lambda d: any(kw.upper() in d for kw in SQL_INJECTION_KEYWORDS)
    )
    df["is_brute_force"] = desc_upper.apply(
        lambda d: any(kw.upper() in d for kw in BRUTE_FORCE_KEYWORDS)
    )
    df["is_denied"] = df["status_text"].isin(DENIED_STATUSES)
    return df


# ─── Per-IP aggregation ────────────────────────────────────────────────────


def _ip_features(group: pd.DataFrame) -> pd.Series:
    total = len(group)
    status_code = group["status_code"]
    is_4xx = status_code.between(STATUS_4XX_LOWER, STATUS_4XX_UPPER, inclusive="both")
    is_5xx = status_code >= STATUS_5XX_LOWER
    error_count = int((is_4xx | is_5xx).sum())

    post_count = int(group["is_post"].sum())
    denied_count = int(group["is_denied"].sum())
    suspicious_count = int(group["is_suspicious_path"].sum())
    sql_hits = int(group["is_sql_injection"].sum())
    brute_hits = int(group["is_brute_force"].sum())

    unique_paths = int(group["event_description"].nunique())
    port_diversity = (
        int(group["port_service"].nunique()) if "port_service" in group.columns else 0
    )

    interarrival_std = _interarrival_std(group["datetime"])
    brute_force_score = brute_hits / total if total else 0.0

    return pd.Series(
        {
            "total_requests": total,
            "error_rate": error_count / total if total else 0.0,
            "post_ratio": post_count / total if total else 0.0,
            "unique_paths": unique_paths,
            "status_4xx_count": int(is_4xx.sum()),
            "status_5xx_count": int(is_5xx.sum()),
            "denied_ratio": denied_count / total if total else 0.0,
            "suspicious_path_ratio": suspicious_count / total if total else 0.0,
            "sql_injection_hits": sql_hits,
            "port_diversity": port_diversity,
            "brute_force_score": brute_force_score,
            "interarrival_std": interarrival_std,
        }
    )


def _interarrival_std(times: pd.Series) -> float:
    """
    Return the standard deviation of request interarrival times in seconds.

    Bots tend to have very regular spacing (low std) — this feature lets
    the model learn "too regular" as anomalous. Returns 0 for fewer than
    two samples.
    """
    clean = times.dropna().sort_values()
    if len(clean) < 2:
        return 0.0
    deltas = clean.diff().dropna().dt.total_seconds()
    if deltas.empty:
        return 0.0
    return float(deltas.std(ddof=0))


# ─── Global / cross-IP features ────────────────────────────────────────────


def _add_global_features(features: pd.DataFrame) -> pd.DataFrame:
    """Compute z-scores and other features that depend on the full batch."""
    if features.empty:
        features["request_rate_zscore"] = pd.Series(dtype="float64")
        return features

    totals = features["total_requests"].astype("float64")
    mean = float(totals.mean())
    std = float(totals.std(ddof=0))

    if std > 0:
        features["request_rate_zscore"] = (totals - mean) / std
    else:
        features["request_rate_zscore"] = 0.0

    return features


# ─── Helpers ───────────────────────────────────────────────────────────────


def _empty_feature_frame() -> pd.DataFrame:
    """Return an empty DataFrame with the expected columns + dtypes."""
    empty: dict[str, pd.Series] = {"source_ip": pd.Series(dtype="object")}
    for col in FEATURE_COLUMNS:
        empty[col] = pd.Series(dtype="float64")
    return pd.DataFrame(empty)


def _ensure_all_columns(features: pd.DataFrame) -> pd.DataFrame:
    """Make sure every column in :data:`FEATURE_COLUMNS` is present."""
    for col in FEATURE_COLUMNS:
        if col not in features.columns:
            features[col] = 0.0
    ordered = ["source_ip", *FEATURE_COLUMNS]
    existing = [c for c in ordered if c in features.columns]
    remaining = [c for c in features.columns if c not in existing]
    return features[existing + remaining]


def feature_matrix(features_df: pd.DataFrame) -> np.ndarray:
    """
    Select :data:`FEATURE_COLUMNS` from *features_df* and return a NumPy
    matrix ready for scaler/model input. Missing columns are filled with 0
    so callers can mix partial input; logged as a warning.
    """
    missing = [c for c in FEATURE_COLUMNS if c not in features_df.columns]
    if missing:
        logger.warning("features.missing_columns", extra={"missing": missing})
        for col in missing:
            features_df[col] = 0.0
    return features_df[list(FEATURE_COLUMNS)].fillna(0).to_numpy(dtype="float64")
