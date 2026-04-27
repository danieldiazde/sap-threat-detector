"""
llm_features.py
---------------
ANALYZE phase — feature engineering for the LLM threat detector.

The LLM detector runs in parallel with the SAP detector (``src/model/features.py``)
and consumes the rows the SAP detector excludes (``LOG_TYPE`` in
:data:`LLM_LOG_TYPES`). It keys on ``(LLM_MODEL_ID, LLM_PROMPT_CATEGORY)``
and scores each row against per-cohort z-score profiles built from a
training corpus.

Public surface:

    is_scorable_llm_row(df)        -> boolean mask of LLM rows with payload
    compute_cohort_profiles(df)    -> CohortProfiles for a training corpus
    build_llm_feature_matrix(df, profiles)
                                   -> per-row DataFrame in LLM_FEATURE_COLUMNS order
    llm_feature_matrix(features_df) -> NumPy array ready for IsolationForest

The motivation for per-cohort z-scores instead of global thresholds:
``Productivity`` p99 cost on ``gpt-5.4-pro`` is $0.13; on ``gpt-4o-mini``
the same percentile is $0.0002 — a 650× spread. A single global threshold
either misses cheap-model anomalies or false-flags expensive-model normals.
A z-score against the cohort means "3 standard deviations above your peer
group" carries the same signal in both cases.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

import numpy as np
import pandas as pd
from src.common.logging import get_logger
from src.model.schema import (
    LLM_FEATURE_COLUMNS,
    LLM_LOG_TYPES,
    LLM_NEAR_TIMEOUT_THRESHOLD_MS,
    LLM_NUMERIC_PROFILE_COLS,
)

logger = get_logger(__name__)


# Profile is built off five distributions: the four raw numeric columns plus
# the derived output/input token ratio. Listed once here, used everywhere.
_PROFILED_COLS: tuple[str, ...] = LLM_NUMERIC_PROFILE_COLS + ("output_input_ratio",)


@dataclass(frozen=True)
class ColumnStats:
    """Distribution summary used both for z-scoring and for percentile rules."""

    mean: float
    std: float
    p10: float
    p99: float

    def to_dict(self) -> dict[str, float]:
        return {"mean": self.mean, "std": self.std, "p10": self.p10, "p99": self.p99}

    @classmethod
    def from_dict(cls, d: Mapping[str, float]) -> ColumnStats:
        return cls(mean=d["mean"], std=d["std"], p10=d["p10"], p99=d["p99"])


@dataclass(frozen=True)
class CohortProfiles:
    """
    Per-cohort and global distribution statistics over the LLM numeric columns.

    ``cohorts`` maps ``(model_id, prompt_category)`` -> {col -> ColumnStats}.
    ``global_`` is the fallback profile used when a row's cohort is missing
    (a model/category combination unseen at training time). The detector
    must score every row, so a fallback is mandatory.
    """

    cohorts: dict[tuple[str, str], dict[str, ColumnStats]]
    global_: dict[str, ColumnStats]
    n_rows: int = 0
    n_cohorts: int = 0
    columns: tuple[str, ...] = field(default_factory=lambda: tuple(_PROFILED_COLS))

    def lookup(self, model_id: str | None, category: str | None, col: str) -> ColumnStats:
        """Return cohort stats for *col*, falling back to global on miss."""
        key = (str(model_id), str(category))
        cohort = self.cohorts.get(key)
        if cohort is not None and col in cohort:
            return cohort[col]
        return self.global_[col]

    # Serialization used by the trainer when persisting the bundle to disk.

    def to_dict(self) -> dict:
        return {
            "cohorts": {
                f"{m}\x00{c}": {k: v.to_dict() for k, v in stats.items()}
                for (m, c), stats in self.cohorts.items()
            },
            "global": {k: v.to_dict() for k, v in self.global_.items()},
            "n_rows": self.n_rows,
            "n_cohorts": self.n_cohorts,
            "columns": list(self.columns),
        }

    @classmethod
    def from_dict(cls, d: Mapping) -> CohortProfiles:
        cohorts: dict[tuple[str, str], dict[str, ColumnStats]] = {}
        for raw_key, stats in d["cohorts"].items():
            m, _, c = raw_key.partition("\x00")
            cohorts[(m, c)] = {k: ColumnStats.from_dict(v) for k, v in stats.items()}
        return cls(
            cohorts=cohorts,
            global_={k: ColumnStats.from_dict(v) for k, v in d["global"].items()},
            n_rows=int(d.get("n_rows", 0)),
            n_cohorts=int(d.get("n_cohorts", 0)),
            columns=tuple(d.get("columns", _PROFILED_COLS)),
        )


# ─── Scorability filter ────────────────────────────────────────────────────


def is_scorable_llm_row(df: pd.DataFrame) -> pd.Series:
    """
    Boolean mask marking rows the LLM detector can score.

    A row is scorable iff:
      - ``log_type`` is one of :data:`LLM_LOG_TYPES`, AND
      - ``llm_model_id`` is non-null (proxy for "post-expansion payload populated").

    The audit on 2026-04-27 found 38.8% of LLM-typed rows in HANA have NULL
    across every LLM_* field; all of them were ingested before the schema
    expansion (commit 5b5d777, 2026-04-21). The detector cannot meaningfully
    score them, so they're filtered upstream rather than imputed (a
    ``fillna(0)`` here would silently bias z-scores toward zero).
    """
    if df.empty:
        return pd.Series([], dtype=bool)
    log_type = df.get("log_type")
    model_id = df.get("llm_model_id")
    if log_type is None or model_id is None:
        return pd.Series(False, index=df.index)
    is_llm = log_type.astype(str).str.upper().isin(LLM_LOG_TYPES)
    has_payload = model_id.notna() & (model_id.astype(str).str.strip() != "")
    return is_llm & has_payload


# ─── Profile construction ──────────────────────────────────────────────────


def compute_cohort_profiles(
    df: pd.DataFrame,
    *,
    min_cohort_size: int = 200,
) -> CohortProfiles:
    """
    Build per-cohort distribution statistics from a training corpus.

    Cohorts with fewer than ``min_cohort_size`` rows are rolled into the
    global profile only — they can still be *scored* at predict time (via
    fallback) but won't have their own cohort entry. The default of 200
    matches the audit's ``cohort_percentiles`` threshold and keeps z-scores
    statistically meaningful.

    Args:
        df: Scorable rows only. Caller is expected to apply
            :func:`is_scorable_llm_row` first.
        min_cohort_size: Minimum row count for a cohort to be profiled.

    Returns:
        CohortProfiles. ``columns`` matches :data:`_PROFILED_COLS`.
    """
    if df.empty:
        empty_global = {col: ColumnStats(0.0, 0.0, 0.0, 0.0) for col in _PROFILED_COLS}
        return CohortProfiles(cohorts={}, global_=empty_global)

    df = df.copy()
    df["output_input_ratio"] = _safe_ratio(df["llm_total_tokens"], df["llm_prompt_tokens"])

    global_stats = {col: _column_stats(df[col]) for col in _PROFILED_COLS}

    cohorts: dict[tuple[str, str], dict[str, ColumnStats]] = {}
    grouped = df.groupby(
        [df["llm_model_id"].astype(str), df["llm_prompt_category"].astype(str)],
        sort=False,
    )
    for (model_id, category), group in grouped:
        if len(group) < min_cohort_size:
            continue
        cohorts[(model_id, category)] = {
            col: _column_stats(group[col]) for col in _PROFILED_COLS
        }

    logger.info(
        "llm_features.profiles_built",
        extra={
            "n_rows": len(df),
            "n_cohorts": len(cohorts),
            "min_cohort_size": min_cohort_size,
        },
    )

    return CohortProfiles(
        cohorts=cohorts,
        global_=global_stats,
        n_rows=len(df),
        n_cohorts=len(cohorts),
    )


def _column_stats(s: pd.Series) -> ColumnStats:
    """Mean, stddev, p10, p99 — NaNs dropped, std uses population (ddof=0)."""
    clean = pd.to_numeric(s, errors="coerce").dropna()
    if clean.empty:
        return ColumnStats(0.0, 0.0, 0.0, 0.0)
    return ColumnStats(
        mean=float(clean.mean()),
        std=float(clean.std(ddof=0)),
        p10=float(clean.quantile(0.10)),
        p99=float(clean.quantile(0.99)),
    )


def _safe_ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """numerator / max(denominator, 1) elementwise — guards divide-by-zero."""
    n = pd.to_numeric(numerator, errors="coerce").fillna(0.0)
    d = pd.to_numeric(denominator, errors="coerce").fillna(0.0)
    safe_d = d.where(d > 0, 1.0)
    return n / safe_d


# ─── Feature matrix ────────────────────────────────────────────────────────


def build_llm_feature_matrix(
    df: pd.DataFrame,
    profiles: CohortProfiles,
) -> pd.DataFrame:
    """
    Per-row LLM feature DataFrame, in :data:`LLM_FEATURE_COLUMNS` order.

    Joins each row to its cohort profile (or the global fallback) and
    computes:
      - 5 z-scored numeric features (cohort-normalized)
      - 3 binary signals (near-timeout, content_filter, length)

    Args:
        df: Rows that passed :func:`is_scorable_llm_row`. Other rows produce
            NaN z-scores; the caller is responsible for filtering first.
        profiles: From :func:`compute_cohort_profiles`. Provides per-row
            (mean, std) lookups via cohort key with global fallback.

    Returns:
        DataFrame with one row per input row, columns in LLM_FEATURE_COLUMNS
        order plus pass-through identifier columns ``llm_model_id`` and
        ``llm_prompt_category`` for downstream rule-layer joins.
    """
    if df.empty:
        return _empty_llm_feature_frame()

    df = df.copy()
    df["output_input_ratio"] = _safe_ratio(df["llm_total_tokens"], df["llm_prompt_tokens"])

    z_pairs: list[tuple[str, str]] = [
        ("llm_prompt_tokens",    "prompt_tokens_z"),
        ("llm_total_tokens",     "total_tokens_z"),
        ("llm_cost_usd",         "cost_z"),
        ("llm_response_time_ms", "response_time_z"),
        ("output_input_ratio",   "output_input_ratio_z"),
    ]

    model_ids = df["llm_model_id"].astype(str)
    categories = df["llm_prompt_category"].astype(str)

    # Vectorized cohort lookup via a merge against a profile DataFrame. The
    # profile carries one row per known cohort with (mean, std) per profiled
    # column; rows whose cohort is missing get NaN after the merge and are
    # filled from the global profile. A row-by-row Python loop here would
    # be O(rows × cols) and dominate batch latency on 50k+ row windows.
    profile_df = _profiles_to_dataframe(profiles)

    keyed = pd.DataFrame({
        "_model_id": model_ids.values,
        "_category": categories.values,
    }, index=df.index)
    joined = keyed.merge(profile_df, on=["_model_id", "_category"], how="left")
    joined.index = df.index  # merge resets the index

    out = pd.DataFrame(index=df.index)
    for raw_col, feat_col in z_pairs:
        mean_col = f"{raw_col}__mean"
        std_col = f"{raw_col}__std"
        means = joined[mean_col].fillna(profiles.global_[raw_col].mean)
        stds = joined[std_col].fillna(profiles.global_[raw_col].std)

        values = pd.to_numeric(df[raw_col], errors="coerce").fillna(0.0)
        # std == 0 ⇒ no spread in cohort ⇒ z is undefined; we emit 0
        # (interpreted as "exactly average") rather than NaN/inf so IF stays sane.
        out[feat_col] = np.where(stds > 0, (values - means) / stds.replace(0, 1), 0.0)

    # Binary signals — independent of cohort.
    out["near_timeout_cap"] = (
        pd.to_numeric(df["llm_response_time_ms"], errors="coerce")
        .fillna(0.0)
        .ge(LLM_NEAR_TIMEOUT_THRESHOLD_MS)
        .astype("float64")
    )

    finish_reason = df.get("llm_finish_reason", pd.Series("", index=df.index))
    finish_reason = finish_reason.fillna("").astype(str).str.lower()
    out["finish_reason_content_filter"] = (finish_reason == "content_filter").astype("float64")
    out["finish_reason_length"] = (finish_reason == "length").astype("float64")

    # Pass-through identifiers for downstream joins (rule layer, anomaly emission).
    out["llm_model_id"] = model_ids.values
    out["llm_prompt_category"] = categories.values

    # Reorder so feature columns come first in the documented order.
    ordered = list(LLM_FEATURE_COLUMNS) + ["llm_model_id", "llm_prompt_category"]
    return out[[c for c in ordered if c in out.columns]]


def llm_feature_matrix(features_df: pd.DataFrame) -> np.ndarray:
    """Select :data:`LLM_FEATURE_COLUMNS` from *features_df* as a NumPy array."""
    missing = [c for c in LLM_FEATURE_COLUMNS if c not in features_df.columns]
    if missing:
        logger.warning("llm_features.missing_columns", extra={"missing": missing})
        for col in missing:
            features_df[col] = 0.0
    return features_df[list(LLM_FEATURE_COLUMNS)].fillna(0).to_numpy(dtype="float64")


def _profiles_to_dataframe(profiles: CohortProfiles) -> pd.DataFrame:
    """
    Flatten ``profiles.cohorts`` into a DataFrame keyed on (model, category)
    with one column per (raw_col, statistic). Used for vectorized merge in
    :func:`build_llm_feature_matrix`. Empty-cohort case returns a frame with
    just the join keys so the merge remains valid.
    """
    rows: list[dict] = []
    for (model_id, category), stats in profiles.cohorts.items():
        row: dict = {"_model_id": model_id, "_category": category}
        for col, s in stats.items():
            row[f"{col}__mean"] = s.mean
            row[f"{col}__std"] = s.std
        rows.append(row)
    if not rows:
        return pd.DataFrame(columns=["_model_id", "_category"])
    return pd.DataFrame(rows)


def _empty_llm_feature_frame() -> pd.DataFrame:
    cols: dict[str, pd.Series] = {}
    for col in LLM_FEATURE_COLUMNS:
        cols[col] = pd.Series(dtype="float64")
    cols["llm_model_id"] = pd.Series(dtype="object")
    cols["llm_prompt_category"] = pd.Series(dtype="object")
    return pd.DataFrame(cols)
