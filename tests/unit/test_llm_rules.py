"""Unit tests for src.model.llm_rules."""

from __future__ import annotations

import pandas as pd
from src.model.llm_features import CohortProfiles, ColumnStats
from src.model.llm_rules import (
    CONTENT_FILTER_SPIKE_RATIO,
    ERROR_STORM_RATIO,
    HIGH_COST_Z_THRESHOLD,
    SPIKE_MIN_BATCH_SIZE,
    TOKEN_HIGH_FLOOR,
    evaluate_cohort,
    max_severity,
)

# ─── Fixtures ──────────────────────────────────────────────────────────────


def _row(**overrides) -> dict:
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


def _profiles() -> CohortProfiles:
    cohort = {
        "llm_prompt_tokens":     ColumnStats(mean=1000, std=200, p10=600, p99=1900),
        "llm_total_tokens":      ColumnStats(mean=1500, std=300, p10=900, p99=2800),
        "llm_cost_usd":          ColumnStats(mean=0.01, std=0.005, p10=0.005, p99=0.05),
        "llm_response_time_ms":  ColumnStats(mean=5000, std=2000, p10=2000, p99=10000),
        "output_input_ratio":    ColumnStats(mean=1.5, std=0.3, p10=1.2, p99=2.5),
    }
    return CohortProfiles(
        cohorts={("gpt-4", "Productivity"): cohort},
        global_={k: ColumnStats(v.mean * 2, v.std, v.p10, v.p99) for k, v in cohort.items()},
    )


def _baselines() -> dict:
    return {
        "Productivity": {
            "n": 70_000,
            "error_rate": 0.20,
            "timeout_rate": 0.10,
            "content_filter_rate": 0.14,
        }
    }


def _eval(rows, profiles=None, baselines=None):
    return evaluate_cohort(
        pd.DataFrame(rows),
        model_id="gpt-4",
        category="Productivity",
        profiles=profiles if profiles is not None else _profiles(),
        baselines=baselines if baselines is not None else _baselines(),
    )


def _ids(fired) -> set[str]:
    return {f.rule_id for f in fired}


# ─── LLM_TOKEN_HIGH ─────────────────────────────────────────────────────────


class TestTokenHigh:
    def test_fires_above_floor(self):
        fired = _eval([_row(llm_prompt_tokens=TOKEN_HIGH_FLOOR), _row(llm_prompt_tokens=TOKEN_HIGH_FLOOR + 5)])
        token_rule = next(f for f in fired if f.rule_id == "LLM_TOKEN_HIGH")
        assert token_rule.rows_affected == 2

    def test_silent_below_floor(self):
        fired = _eval([_row(llm_prompt_tokens=TOKEN_HIGH_FLOOR - 1) for _ in range(5)])
        assert "LLM_TOKEN_HIGH" not in _ids(fired)


# ─── LLM_NEAR_TIMEOUT ───────────────────────────────────────────────────────


class TestNearTimeout:
    def test_fires_at_or_above_threshold(self):
        fired = _eval([_row(llm_response_time_ms=29_999), _row(llm_response_time_ms=30_000)])
        rule = next(f for f in fired if f.rule_id == "LLM_NEAR_TIMEOUT")
        assert rule.rows_affected == 1


# ─── LLM_HIGH_COST_OUTLIER ──────────────────────────────────────────────────


class TestHighCostOutlier:
    def test_requires_both_z_and_floor(self):
        # cohort cost: mean 0.01, std 0.005 → z=4 ⇒ cost = 0.03 (below floor 0.10) — should NOT fire
        fired = _eval([_row(llm_cost_usd=0.03)])
        assert "LLM_HIGH_COST_OUTLIER" not in _ids(fired)

    def test_fires_when_both_conditions_met(self):
        # cost=0.15, z = (0.15-0.01)/0.005 = 28; absolute floor 0.10 cleared.
        fired = _eval([_row(llm_cost_usd=0.15)])
        rule = next(f for f in fired if f.rule_id == "LLM_HIGH_COST_OUTLIER")
        assert rule.rows_affected == 1
        assert rule.context["max_cost_usd"] == 0.15
        assert rule.context["max_z"] > HIGH_COST_Z_THRESHOLD


# ─── LLM_EXFIL_SHAPE ────────────────────────────────────────────────────────


class TestExfilShape:
    def test_fires_on_small_input_huge_output(self):
        # cohort p10 prompt = 600, p99 total = 2800
        fired = _eval([_row(llm_prompt_tokens=300, llm_total_tokens=3000)])
        rule = next(f for f in fired if f.rule_id == "LLM_EXFIL_SHAPE")
        assert rule.rows_affected == 1

    def test_silent_when_only_one_condition_met(self):
        fired = _eval([_row(llm_prompt_tokens=300, llm_total_tokens=1000)])  # small in, normal out
        assert "LLM_EXFIL_SHAPE" not in _ids(fired)


# ─── LLM_CONTENT_FILTER_SPIKE ───────────────────────────────────────────────


class TestContentFilterSpike:
    def test_fires_when_ratio_exceeds_threshold(self):
        # baseline 0.14; threshold ratio 3 → fire when fraction > 0.42
        rows = [_row(llm_finish_reason="content_filter") for _ in range(15)] + [_row() for _ in range(15)]
        # batch size 30 (>=20), 15/30 = 0.5 / 0.14 ≈ 3.57x — fires
        fired = _eval(rows)
        rule = next(f for f in fired if f.rule_id == "LLM_CONTENT_FILTER_SPIKE")
        assert rule.context["ratio"] >= CONTENT_FILTER_SPIKE_RATIO

    def test_silent_below_min_batch_size(self):
        rows = [_row(llm_finish_reason="content_filter") for _ in range(SPIKE_MIN_BATCH_SIZE - 1)]
        fired = _eval(rows)
        assert "LLM_CONTENT_FILTER_SPIKE" not in _ids(fired)

    def test_silent_with_no_baseline(self):
        rows = [_row(llm_finish_reason="content_filter") for _ in range(50)]
        fired = _eval(rows, baselines={})
        assert "LLM_CONTENT_FILTER_SPIKE" not in _ids(fired)


# ─── LLM_ERROR_STORM ────────────────────────────────────────────────────────


class TestErrorStorm:
    def test_fires_on_extreme_error_rate(self):
        # baseline error+timeout 0.30; threshold ratio 10 → need rate > 3.0 (impossible),
        # so error_storm in practice only fires under degenerate conditions.
        # Use a more reasonable baseline for this test.
        baselines = {"Productivity": {"error_rate": 0.05, "timeout_rate": 0.02, "content_filter_rate": 0.14, "n": 1000}}
        # baseline 0.07; need observed_rate > 0.7. 25/30 ≈ 0.83 → fires
        rows = [_row(log_type="LLM_ERROR") for _ in range(25)] + [_row() for _ in range(5)]
        fired = _eval(rows, baselines=baselines)
        rule = next(f for f in fired if f.rule_id == "LLM_ERROR_STORM")
        assert rule.context["ratio"] >= ERROR_STORM_RATIO

    def test_silent_below_threshold(self):
        baselines = {"Productivity": {"error_rate": 0.05, "timeout_rate": 0.02, "content_filter_rate": 0.14, "n": 1000}}
        rows = [_row(log_type="LLM_ERROR") for _ in range(5)] + [_row() for _ in range(95)]
        fired = _eval(rows, baselines=baselines)
        assert "LLM_ERROR_STORM" not in _ids(fired)


# ─── max_severity ───────────────────────────────────────────────────────────


class TestMaxSeverity:
    def test_high_dominates_low(self):
        fired = _eval([
            _row(llm_response_time_ms=31_000),  # low
            _row(llm_cost_usd=0.20),            # high
        ])
        assert max_severity(fired) == "high"

    def test_empty_returns_low(self):
        assert max_severity([]) == "low"


# ─── Empty / edge cases ─────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_dataframe_returns_empty(self):
        fired = _eval([])
        assert fired == []

    def test_zero_std_cost_skips_high_cost_rule(self):
        """Cohort with zero cost variance — division by std would be zero."""
        # Override the cost stats to std=0
        profiles = _profiles()
        profiles.cohorts[("gpt-4", "Productivity")]["llm_cost_usd"] = ColumnStats(
            mean=0.01, std=0.0, p10=0.01, p99=0.01
        )
        fired = _eval([_row(llm_cost_usd=0.20)], profiles=profiles)
        assert "LLM_HIGH_COST_OUTLIER" not in _ids(fired)
