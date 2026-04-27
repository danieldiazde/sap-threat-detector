"""Unit tests for src.model.llm_features."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from src.model.llm_features import (
    CohortProfiles,
    ColumnStats,
    build_llm_feature_matrix,
    compute_cohort_profiles,
    is_scorable_llm_row,
    llm_feature_matrix,
)
from src.model.schema import LLM_FEATURE_COLUMNS

# ─── Fixtures ──────────────────────────────────────────────────────────────


def _llm_row(**overrides) -> dict:
    base = {
        "log_type": "LLM_REQUEST",
        "llm_model_id": "gpt-4",
        "llm_prompt_category": "Productivity",
        "llm_prompt_tokens": 1000,
        "llm_total_tokens": 1500,
        "llm_cost_usd": 0.01,
        "llm_response_time_ms": 5000,
        "llm_finish_reason": "stop",
        "llm_status": "success",
    }
    base.update(overrides)
    return base


def _make_cohort(model: str, category: str, n: int, **value_fns) -> list[dict]:
    """value_fns = {col: callable(i)->value} to vary fields across n rows."""
    rows = []
    for i in range(n):
        row = _llm_row(llm_model_id=model, llm_prompt_category=category)
        for col, fn in value_fns.items():
            row[col] = fn(i)
        rows.append(row)
    return rows


# ─── is_scorable_llm_row ───────────────────────────────────────────────────


class TestScorabilityFilter:
    def test_drops_non_llm_rows(self):
        df = pd.DataFrame([
            _llm_row(),
            _llm_row(log_type="INFO"),
            _llm_row(log_type="ERROR"),
        ])
        mask = is_scorable_llm_row(df)
        assert mask.tolist() == [True, False, False]

    def test_drops_pre_expansion_llm_rows(self):
        """Rows ingested before 2026-04-21 have NULL across every LLM_* field."""
        df = pd.DataFrame([
            _llm_row(),
            _llm_row(llm_model_id=None),
            _llm_row(llm_model_id=""),
            _llm_row(llm_model_id="   "),
        ])
        mask = is_scorable_llm_row(df)
        assert mask.tolist() == [True, False, False, False]

    def test_keeps_all_three_llm_log_types(self):
        df = pd.DataFrame([
            _llm_row(log_type="LLM_REQUEST"),
            _llm_row(log_type="LLM_ERROR"),
            _llm_row(log_type="LLM_TIMEOUT"),
        ])
        assert is_scorable_llm_row(df).all()

    def test_handles_lowercase_log_type(self):
        """Tolerant to case — LLM_LOG_TYPES is normalized to upper."""
        df = pd.DataFrame([_llm_row(log_type="llm_request")])
        assert is_scorable_llm_row(df).iloc[0]

    def test_empty_input_returns_empty_mask(self):
        mask = is_scorable_llm_row(pd.DataFrame())
        assert mask.empty
        assert mask.dtype == bool

    def test_missing_columns_returns_all_false(self):
        df = pd.DataFrame([{"some_other_col": 1}])
        assert not is_scorable_llm_row(df).any()


# ─── compute_cohort_profiles ───────────────────────────────────────────────


class TestComputeProfiles:
    def test_basic_stats_match_pandas(self):
        rows = _make_cohort(
            "gpt-4",
            "Productivity",
            n=200,
            llm_prompt_tokens=lambda i: 100 + i,
        )
        df = pd.DataFrame(rows)
        profiles = compute_cohort_profiles(df, min_cohort_size=100)

        cohort = profiles.cohorts[("gpt-4", "Productivity")]
        col = "llm_prompt_tokens"
        s = pd.Series([100 + i for i in range(200)])

        assert cohort[col].mean == pytest.approx(float(s.mean()))
        assert cohort[col].std == pytest.approx(float(s.std(ddof=0)))
        assert cohort[col].p10 == pytest.approx(float(s.quantile(0.10)))
        assert cohort[col].p99 == pytest.approx(float(s.quantile(0.99)))

    def test_min_cohort_size_excludes_small_groups(self):
        small = _make_cohort("rare-model", "Niche", n=50)
        large = _make_cohort("common", "Productivity", n=500)
        df = pd.DataFrame(small + large)
        profiles = compute_cohort_profiles(df, min_cohort_size=200)

        assert ("rare-model", "Niche") not in profiles.cohorts
        assert ("common", "Productivity") in profiles.cohorts

    def test_global_profile_includes_all_rows(self):
        small = _make_cohort("a", "X", n=50, llm_cost_usd=lambda i: 1.0)
        large = _make_cohort("b", "X", n=500, llm_cost_usd=lambda i: 2.0)
        df = pd.DataFrame(small + large)
        profiles = compute_cohort_profiles(df, min_cohort_size=100)

        # Global mean is the weighted mean of both cohorts even though "a"
        # was excluded as a cohort.
        expected = (50 * 1.0 + 500 * 2.0) / 550
        assert profiles.global_["llm_cost_usd"].mean == pytest.approx(expected)

    def test_serialization_roundtrip(self):
        rows = _make_cohort("gpt-4", "Productivity", n=300)
        profiles = compute_cohort_profiles(pd.DataFrame(rows), min_cohort_size=100)
        restored = CohortProfiles.from_dict(profiles.to_dict())

        assert restored.n_cohorts == profiles.n_cohorts
        assert restored.n_rows == profiles.n_rows
        for key in profiles.cohorts:
            for col in profiles.cohorts[key]:
                assert (
                    restored.cohorts[key][col].mean
                    == pytest.approx(profiles.cohorts[key][col].mean)
                )

    def test_empty_input_yields_zeroed_global(self):
        profiles = compute_cohort_profiles(pd.DataFrame())
        assert profiles.cohorts == {}
        assert all(s.mean == 0.0 and s.std == 0.0 for s in profiles.global_.values())


# ─── build_llm_feature_matrix ──────────────────────────────────────────────


class TestFeatureMatrix:
    def _profiles_with_known_stats(self) -> CohortProfiles:
        # Hand-built profiles so we can verify z-score arithmetic exactly.
        cohort_stats = {
            "llm_prompt_tokens":     ColumnStats(mean=1000, std=100, p10=850, p99=1200),
            "llm_total_tokens":      ColumnStats(mean=1500, std=200, p10=1200, p99=1800),
            "llm_cost_usd":          ColumnStats(mean=0.01, std=0.005, p10=0.005, p99=0.05),
            "llm_response_time_ms":  ColumnStats(mean=5000, std=1000, p10=3000, p99=10000),
            "output_input_ratio":    ColumnStats(mean=1.5, std=0.3, p10=1.2, p99=2.0),
        }
        # Global has *different* stats so we can detect fallback bugs.
        global_stats = {
            col: ColumnStats(mean=s.mean * 2, std=s.std * 2, p10=s.p10, p99=s.p99)
            for col, s in cohort_stats.items()
        }
        return CohortProfiles(
            cohorts={("gpt-4", "Productivity"): cohort_stats},
            global_=global_stats,
        )

    def test_z_score_arithmetic_correct(self):
        profiles = self._profiles_with_known_stats()
        df = pd.DataFrame([
            _llm_row(
                llm_model_id="gpt-4",
                llm_prompt_category="Productivity",
                llm_prompt_tokens=1200,    # mean 1000, std 100 -> z=2
                llm_total_tokens=1500,     # mean 1500, std 200 -> z=0
                llm_cost_usd=0.025,        # mean 0.01, std 0.005 -> z=3
                llm_response_time_ms=2000, # mean 5000, std 1000 -> z=-3
            )
        ])
        feats = build_llm_feature_matrix(df, profiles)
        row = feats.iloc[0]
        assert row["prompt_tokens_z"] == pytest.approx(2.0)
        assert row["total_tokens_z"] == pytest.approx(0.0)
        assert row["cost_z"] == pytest.approx(3.0)
        assert row["response_time_z"] == pytest.approx(-3.0)

    def test_zero_std_emits_zero_z_not_inf(self):
        profiles = CohortProfiles(
            cohorts={("flat", "Productivity"): {
                col: ColumnStats(mean=10.0, std=0.0, p10=10, p99=10)
                for col in ("llm_prompt_tokens", "llm_total_tokens", "llm_cost_usd",
                            "llm_response_time_ms", "output_input_ratio")
            }},
            global_={col: ColumnStats(0.0, 0.0, 0.0, 0.0)
                     for col in ("llm_prompt_tokens", "llm_total_tokens", "llm_cost_usd",
                                 "llm_response_time_ms", "output_input_ratio")},
        )
        df = pd.DataFrame([_llm_row(llm_model_id="flat", llm_prompt_tokens=999)])
        feats = build_llm_feature_matrix(df, profiles)
        # Exact value is irrelevant — what matters is finite & not NaN.
        assert np.isfinite(feats.iloc[0]["prompt_tokens_z"])

    def test_unknown_cohort_falls_back_to_global(self):
        profiles = self._profiles_with_known_stats()
        # Cohort ("brand-new", "Productivity") not in profiles.cohorts.
        df = pd.DataFrame([
            _llm_row(
                llm_model_id="brand-new",
                llm_prompt_category="Productivity",
                # global mean=2000, std=200 (cohort mean*2, std*2) -> z = (2200-2000)/200 = 1
                llm_prompt_tokens=2200,
            )
        ])
        feats = build_llm_feature_matrix(df, profiles)
        assert feats.iloc[0]["prompt_tokens_z"] == pytest.approx(1.0)

    def test_near_timeout_cap_threshold(self):
        profiles = self._profiles_with_known_stats()
        df = pd.DataFrame([
            _llm_row(llm_response_time_ms=29_999),
            _llm_row(llm_response_time_ms=30_000),
            _llm_row(llm_response_time_ms=34_000),
        ])
        feats = build_llm_feature_matrix(df, profiles)
        assert feats["near_timeout_cap"].tolist() == [0.0, 1.0, 1.0]

    def test_finish_reason_binary_signals(self):
        profiles = self._profiles_with_known_stats()
        df = pd.DataFrame([
            _llm_row(llm_finish_reason="stop"),
            _llm_row(llm_finish_reason="length"),
            _llm_row(llm_finish_reason="content_filter"),
            _llm_row(llm_finish_reason="CONTENT_FILTER"),  # case-insensitive
            _llm_row(llm_finish_reason=None),
        ])
        feats = build_llm_feature_matrix(df, profiles)
        assert feats["finish_reason_content_filter"].tolist() == [0, 0, 1, 1, 0]
        assert feats["finish_reason_length"].tolist() == [0, 1, 0, 0, 0]

    def test_output_input_ratio_handles_zero_prompt(self):
        """A zero-token prompt would divide by zero — must not produce inf/nan."""
        profiles = self._profiles_with_known_stats()
        df = pd.DataFrame([
            _llm_row(llm_prompt_tokens=0, llm_total_tokens=2000),
        ])
        feats = build_llm_feature_matrix(df, profiles)
        assert np.isfinite(feats.iloc[0]["output_input_ratio_z"])

    def test_empty_input_returns_correct_columns(self):
        feats = build_llm_feature_matrix(pd.DataFrame(), CohortProfiles({}, {}))
        for col in LLM_FEATURE_COLUMNS:
            assert col in feats.columns
        assert len(feats) == 0

    def test_numpy_export_shape_and_dtype(self):
        profiles = self._profiles_with_known_stats()
        df = pd.DataFrame([_llm_row() for _ in range(5)])
        feats = build_llm_feature_matrix(df, profiles)
        arr = llm_feature_matrix(feats)
        assert arr.shape == (5, len(LLM_FEATURE_COLUMNS))
        assert arr.dtype == np.float64
        assert np.isfinite(arr).all()

    def test_preserves_input_row_order(self):
        """merge(how='left') should keep left-side ordering."""
        profiles = self._profiles_with_known_stats()
        df = pd.DataFrame([
            _llm_row(llm_model_id="gpt-4", llm_prompt_tokens=1200),     # cohort
            _llm_row(llm_model_id="brand-new", llm_prompt_tokens=2200), # global fallback
            _llm_row(llm_model_id="gpt-4", llm_prompt_tokens=1000),     # cohort
        ])
        feats = build_llm_feature_matrix(df, profiles)
        # cohort row 0: z = (1200-1000)/100 = 2; global row 1: z = (2200-2000)/200 = 1; cohort row 2: z=0
        assert feats["prompt_tokens_z"].tolist() == pytest.approx([2.0, 1.0, 0.0])
