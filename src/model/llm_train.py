"""
llm_train.py
------------
Trains the LLM threat-detection ensemble.

Architecture (per design 2026-04-27):
  - 1 global IsolationForest fit on every scorable row
  - N per-category IsolationForests (one per LLM_PROMPT_CATEGORY)
  - 1 CohortProfiles artifact (per-(model, category) z-score stats)

The audit on 2026-04-27 found:
  - 11 prompt categories, smallest = 27,804 rows post-expansion (>> IF needs)
  - 320 distinct (model, category) cohorts, smallest >= 500 rows
  - cost p99 varies up to 650x across models in the same category — single
    global model would compromise on cost thresholds; per-category fixes that
  - global + per-category ensemble disagreement is itself an anomaly signal

The ensemble produces two scores per row at predict time:
  - global score: how unusual *across all LLM traffic*
  - category score: how unusual *for this category*
The disagreement between them (one anomalous, the other not) escalates
severity. Implemented in src/model/llm_predict.py.

Persistence: a single joblib bundle per training run, stored under
``settings.model_dir / "llm" / <version_tag>/``. Mirrors the directory
shape of :class:`src.model.versioning.ModelRegistry` but is a separate
namespace because the SAP and LLM detectors have incompatible artifact
shapes.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow
from src.model.llm_features import (
    CohortProfiles,
    build_llm_feature_matrix,
    compute_cohort_profiles,
    is_scorable_llm_row,
    llm_feature_matrix,
)
from src.model.schema import LLM_FEATURE_COLUMNS

logger = get_logger(__name__)


# ─── Bundle ────────────────────────────────────────────────────────────────


@dataclass
class LLMModelBundle:
    """
    Everything the LLM detector needs at predict time, in one artifact.

    Attributes:
        global_model: IF fit on every scorable training row.
        global_scaler: StandardScaler fit on the same training rows.
        category_models: ``{prompt_category -> IsolationForest}``.
        category_scalers: ``{prompt_category -> StandardScaler}``.
        profiles: per-cohort z-score stats used to build features at
            predict time.
        feature_columns: persisted for drift detection — fail fast at load
            time if features.py adds/renames a column without a retrain.
        metadata: training params, sample counts, contamination, timestamps.
    """

    global_model: IsolationForest
    global_scaler: StandardScaler
    category_models: dict[str, IsolationForest]
    category_scalers: dict[str, StandardScaler]
    profiles: CohortProfiles
    feature_columns: tuple[str, ...] = field(default_factory=lambda: tuple(LLM_FEATURE_COLUMNS))
    metadata: dict[str, Any] = field(default_factory=dict)


# ─── Hyperparameters ───────────────────────────────────────────────────────
#
# Reuses the SAP detector's IF defaults from src/common/config.py for parity.
# Per-category models use a smaller n_estimators because the per-cohort
# normalization done by z-scoring already amplifies signal — we don't need
# as many trees to pick it up, and fitting 11 forests adds up otherwise.


def _coerce_max_samples(raw: str) -> int | float | str:
    if raw == "auto":
        return "auto"
    try:
        return int(raw)
    except ValueError:
        return float(raw)


def _global_hyperparams() -> dict[str, Any]:
    return {
        "contamination": settings.model_contamination,
        "n_estimators": settings.model_n_estimators,
        "max_samples": _coerce_max_samples(settings.model_max_samples),
        "random_state": settings.model_random_state,
    }


def _category_hyperparams() -> dict[str, Any]:
    return {
        "contamination": settings.model_contamination,
        # Smaller forests per category — z-scored input is already normalized,
        # so the trees don't need as much depth/breadth to separate outliers.
        "n_estimators": max(50, settings.model_n_estimators // 2),
        "max_samples": _coerce_max_samples(settings.model_max_samples),
        "random_state": settings.model_random_state,
    }


# ─── Training ──────────────────────────────────────────────────────────────


def train_llm_ensemble(
    raw_df: pd.DataFrame,
    *,
    min_cohort_size: int = 200,
    min_category_size: int = 500,
) -> LLMModelBundle:
    """
    Train the global IF + per-category IFs + cohort profiles from raw logs.

    Args:
        raw_df: Raw log DataFrame straight from HANA / the parser. Filtering
            to scorable rows is done internally so callers don't have to know
            which rows count.
        min_cohort_size: Minimum (model, category) row count to get its own
            profile entry (smaller cohorts fall back to global at predict time).
        min_category_size: Minimum row count for a category to get its own IF.
            Categories below this size are not ensemble-modeled but are still
            scored by the global model.

    Raises:
        ValueError: if no scorable rows remain after filtering.
    """
    started = time.perf_counter()

    mask = is_scorable_llm_row(raw_df)
    df_all = raw_df[mask].copy()
    if df_all.empty:
        raise ValueError("train_llm_ensemble: no scorable LLM rows in input")

    # Per-category baselines computed from the FULL scorable corpus (errors,
    # timeouts, and content_filter responses included). Used by the spike
    # rules in llm_rules.py — at predict time we compare a batch's per-row
    # rates against these baselines and fire when the ratio exceeds threshold.
    category_baselines = _compute_category_baselines(df_all)

    # Train only on successful requests — errors / timeouts are signals to
    # the rule layer, not "normal" examples for the IF to learn from.
    before = len(df_all)
    df = df_all[df_all["llm_status"].astype(str).str.lower() == "success"].copy()
    logger.info(
        "llm_train.filtered_to_success",
        extra={"before": before, "after": len(df)},
    )
    if df.empty:
        raise ValueError("train_llm_ensemble: no LLM_STATUS='success' rows after filter")

    profiles = compute_cohort_profiles(df, min_cohort_size=min_cohort_size)
    features = build_llm_feature_matrix(df, profiles)

    # Global model — fit on everything.
    X_global = llm_feature_matrix(features)
    global_scaler = StandardScaler()
    X_global_scaled = global_scaler.fit_transform(X_global)
    global_model = IsolationForest(**_global_hyperparams())
    global_model.fit(X_global_scaled)
    global_anomaly_rate = float((global_model.predict(X_global_scaled) == -1).mean())

    # Per-category models — one per category with enough rows.
    category_models: dict[str, IsolationForest] = {}
    category_scalers: dict[str, StandardScaler] = {}
    category_anomaly_rates: dict[str, float] = {}
    skipped_categories: dict[str, int] = {}

    # The category column exists on `features` (passed through from build_llm_feature_matrix).
    grouped = features.groupby("llm_prompt_category", sort=False)
    for category, group in grouped:
        if len(group) < min_category_size:
            skipped_categories[str(category)] = int(len(group))
            continue
        X_cat = llm_feature_matrix(group)
        scaler = StandardScaler()
        X_cat_scaled = scaler.fit_transform(X_cat)
        model = IsolationForest(**_category_hyperparams())
        model.fit(X_cat_scaled)
        rate = float((model.predict(X_cat_scaled) == -1).mean())

        category_models[str(category)] = model
        category_scalers[str(category)] = scaler
        category_anomaly_rates[str(category)] = rate

    elapsed = time.perf_counter() - started

    metadata = {
        "trained_at": utcnow().isoformat(),
        "training_samples": int(len(features)),
        "training_corpus_total": int(before),
        "global_anomaly_rate": global_anomaly_rate,
        "category_anomaly_rates": category_anomaly_rates,
        "category_baselines": category_baselines,
        "skipped_small_categories": skipped_categories,
        "n_cohorts_profiled": profiles.n_cohorts,
        "min_cohort_size": min_cohort_size,
        "min_category_size": min_category_size,
        "global_hyperparams": _global_hyperparams(),
        "category_hyperparams": _category_hyperparams(),
        "elapsed_seconds": round(elapsed, 3),
        "feature_columns": list(LLM_FEATURE_COLUMNS),
    }

    logger.info(
        "llm_train.done",
        extra={
            "samples": metadata["training_samples"],
            "categories_modeled": len(category_models),
            "categories_skipped": len(skipped_categories),
            "global_anomaly_rate": round(global_anomaly_rate, 4),
            "elapsed_seconds": metadata["elapsed_seconds"],
        },
    )

    return LLMModelBundle(
        global_model=global_model,
        global_scaler=global_scaler,
        category_models=category_models,
        category_scalers=category_scalers,
        profiles=profiles,
        metadata=metadata,
    )


# ─── Baselines ─────────────────────────────────────────────────────────────


def _compute_category_baselines(df_all: pd.DataFrame) -> dict[str, dict[str, float]]:
    """
    Per-category fraction-rates over the *full* scorable corpus.

    Used by the spike rules in llm_rules.py: a batch's observed fraction is
    compared to the baseline; the rule fires when ratio > threshold (and the
    batch is large enough to make the fraction meaningful).

    Returns ``{category: {error_rate, timeout_rate, content_filter_rate, n}}``.
    Fractions are over the per-category total (``n``). LOG_TYPE drives the
    error/timeout split because LLM_STATUS doesn't always discriminate
    timeouts from generic errors.
    """
    if df_all.empty or "llm_prompt_category" not in df_all.columns:
        return {}

    out: dict[str, dict[str, float]] = {}
    grouped = df_all.groupby(df_all["llm_prompt_category"].astype(str), sort=False)
    for category, group in grouped:
        total = len(group)
        if total == 0:
            continue
        log_type = group["log_type"].astype(str).str.upper()
        finish_reason = (
            group["llm_finish_reason"].fillna("").astype(str).str.lower()
            if "llm_finish_reason" in group.columns
            else pd.Series("", index=group.index)
        )
        out[str(category)] = {
            "n": int(total),
            "error_rate": float((log_type == "LLM_ERROR").sum() / total),
            "timeout_rate": float((log_type == "LLM_TIMEOUT").sum() / total),
            "content_filter_rate": float((finish_reason == "content_filter").sum() / total),
        }
    return out


# ─── Registry ──────────────────────────────────────────────────────────────


LLM_REGISTRY_SUBDIR = "llm"
BUNDLE_FILE = "bundle.joblib"
PROFILES_FILE = "profiles.json"
MANIFEST_FILE = "manifest.json"
LATEST_POINTER = "latest_llm.txt"


class LLMModelNotFoundError(FileNotFoundError):
    """Raised when no trained LLM bundle is available on disk."""


class LLMModelRegistry:
    """
    File-system registry for LLM ensemble bundles.

    Layout::

        <model_dir>/llm/
            latest_llm.txt              -> "<version_tag>"
            <version_tag>/
                bundle.joblib           -> joblib(LLMModelBundle)
                profiles.json           -> profiles.to_dict() (human-readable)
                manifest.json           -> training metadata

    Bundle is the source of truth at load time; profiles.json is duplicated
    out as JSON so an operator can read cohort stats without unpickling.
    """

    def __init__(self, root: Path | None = None) -> None:
        self._root: Path = (root or settings.model_dir) / LLM_REGISTRY_SUBDIR

    @property
    def root(self) -> Path:
        return self._root

    def _version_dir(self, version_tag: str) -> Path:
        return self._root / version_tag

    def _latest_pointer(self) -> Path:
        return self._root / LATEST_POINTER

    def save(self, bundle: LLMModelBundle, *, notes: str = "") -> str:
        """Persist *bundle* to disk and update the latest pointer."""
        version_tag = "llm-" + utcnow().strftime("%Y%m%d-%H%M%S")
        version_dir = self._version_dir(version_tag)
        version_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(bundle, version_dir / BUNDLE_FILE)
        (version_dir / PROFILES_FILE).write_text(
            json.dumps(bundle.profiles.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

        manifest = {
            "version_tag": version_tag,
            **bundle.metadata,
            "categories_modeled": sorted(bundle.category_models.keys()),
            "n_categories_modeled": len(bundle.category_models),
            "notes": notes,
        }
        (version_dir / MANIFEST_FILE).write_text(
            json.dumps(manifest, indent=2, default=str),
            encoding="utf-8",
        )
        self._latest_pointer().write_text(version_tag, encoding="utf-8")

        logger.info(
            "llm_registry.save",
            extra={
                "version_tag": version_tag,
                "categories_modeled": len(bundle.category_models),
                "samples": bundle.metadata.get("training_samples"),
            },
        )
        return version_tag

    def load(self, version_tag: str = "latest") -> LLMModelBundle:
        resolved = self._resolve(version_tag)
        bundle_path = self._version_dir(resolved) / BUNDLE_FILE
        if not bundle_path.exists():
            raise LLMModelNotFoundError(
                f"LLM bundle {resolved!r} missing at {bundle_path}. "
                f"Run: python -m scripts.train_llm_model"
            )
        bundle = joblib.load(bundle_path)
        # Drift guard: feature columns must match what's currently expected.
        if tuple(bundle.feature_columns) != tuple(LLM_FEATURE_COLUMNS):
            raise LLMModelNotFoundError(
                f"LLM bundle {resolved!r} has feature columns "
                f"{bundle.feature_columns} but current LLM_FEATURE_COLUMNS is "
                f"{LLM_FEATURE_COLUMNS} — retrain via scripts.train_llm_model"
            )
        return bundle

    def latest_tag(self) -> str | None:
        ptr = self._latest_pointer()
        if not ptr.exists():
            return None
        tag = ptr.read_text(encoding="utf-8").strip()
        return tag or None

    def _resolve(self, version_tag: str) -> str:
        if version_tag == "latest":
            tag = self.latest_tag()
            if tag is None:
                raise LLMModelNotFoundError(
                    "No LLM bundle has been trained yet. "
                    "Run: python -m scripts.train_llm_model"
                )
            return tag
        return version_tag


llm_registry = LLMModelRegistry()
