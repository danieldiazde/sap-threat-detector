"""
llm_rules.py
------------
Rule layer for the LLM threat detector.

Each rule is an explainable, data-driven heuristic that complements the
Isolation Forest ensemble. Rules attach to ``(model_id, prompt_category)``
cohorts within a batch, returning :class:`FiredRule` records that carry a
``rule_id``, a severity, and a ``context`` payload used both for alerting
and for the recommendation engine in the next PR.

Why both rules and ML: rules are explainable to judges ("we flagged it
because the content_filter rate was 4x baseline"). ML covers multivariate
patterns rules can't enumerate. Together we get high recall plus demo
clarity.

Rule catalog (all thresholds derived from data/reports/llm_audit_2026-04-27.md):

    LLM_TOKEN_HIGH            row, medium    prompt_tokens >= 1990 (top 0.5%)
    LLM_NEAR_TIMEOUT          row, low       response_time_ms >= 30s (5s buffer to 35s cap)
    LLM_HIGH_COST_OUTLIER     row, high      cost_z > 4 AND cost_usd > 0.10
    LLM_EXFIL_SHAPE           row, high      prompt < cohort_p10 AND total > cohort_p99
    LLM_CONTENT_FILTER_SPIKE  cohort, high   batch CF-rate > 2.5x baseline AND > 30% absolute
    LLM_ERROR_STORM           cohort, high   batch error+timeout rate > 2x baseline AND > 50% absolute

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import pandas as pd
from src.common.logging import get_logger
from src.model.llm_features import CohortProfiles
from src.model.schema import LLM_NEAR_TIMEOUT_THRESHOLD_MS

logger = get_logger(__name__)


Severity = Literal["low", "medium", "high"]
SEVERITY_RANK: dict[Severity, int] = {"low": 1, "medium": 2, "high": 3}


# ─── Thresholds ────────────────────────────────────────────────────────────
# All values derive from the audit on 2026-04-27. If you change a threshold,
# write down the new percentile / ratio it corresponds to in the docstring
# above and add a regression test in tests/unit/test_llm_rules.py.

TOKEN_HIGH_FLOOR: int = 1990              # p99.5 of LLM_PROMPT_TOKENS across all rows
HIGH_COST_Z_THRESHOLD: float = 4.0        # 4sigma above cohort mean
HIGH_COST_FLOOR_USD: float = 0.10         # absolute floor (suppresses small-cohort z-noise)

# Spike rules use BOTH a ratio (elevated relative to baseline) AND an absolute
# floor (the rate is high in absolute terms). Ratio-only thresholds are
# unreachable when baselines are already elevated — the audit shows
# per-category baseline error rates around 30% in our corpus, which makes
# any "10x baseline" rule mathematically impossible to trigger.
CONTENT_FILTER_SPIKE_RATIO: float = 2.5   # ratio of observed/baseline content_filter rate
CONTENT_FILTER_SPIKE_FLOOR: float = 0.30  # observed fraction must also exceed this
ERROR_STORM_RATIO: float = 2.0            # ratio of observed/baseline error+timeout rate
ERROR_STORM_FLOOR: float = 0.50           # observed fraction must also exceed this
SPIKE_MIN_BATCH_SIZE: int = 20            # below this, fractions are too noisy

# Rule severity registry — single source of truth for severity assignment.
RULE_SEVERITY: dict[str, Severity] = {
    "LLM_TOKEN_HIGH": "medium",
    "LLM_NEAR_TIMEOUT": "low",
    "LLM_HIGH_COST_OUTLIER": "high",
    "LLM_EXFIL_SHAPE": "high",
    "LLM_CONTENT_FILTER_SPIKE": "high",
    "LLM_ERROR_STORM": "high",
}


# ─── Result type ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FiredRule:
    """
    A single rule firing on a cohort.

    ``rows_affected`` is the count of rows in the cohort that contributed to
    the rule. For per-row rules it's the number of matching rows; for
    cohort-level rules (spikes) it's the cohort's batch size.

    ``context`` is rule-specific metadata that flows into the alert payload
    and the recommendation engine. Keep it JSON-serializable.
    """

    rule_id: str
    severity: Severity
    rows_affected: int
    context: dict[str, Any]


def max_severity(rules: list[FiredRule]) -> Severity:
    """Return the highest severity among *rules*; 'low' if empty."""
    if not rules:
        return "low"
    return max(rules, key=lambda r: SEVERITY_RANK[r.severity]).severity


# ─── Rule evaluation ───────────────────────────────────────────────────────


def evaluate_cohort(
    cohort_rows: pd.DataFrame,
    *,
    model_id: str,
    category: str,
    profiles: CohortProfiles,
    baselines: dict[str, dict[str, float]],
) -> list[FiredRule]:
    """
    Run every rule on a single cohort's batch and return the fired rules.

    Args:
        cohort_rows: rows in the current batch for one (model_id, category).
            Must include the LLM_* columns plus any z-scored features the
            cost-outlier rule needs.
        model_id: cohort key, used for profile lookup.
        category: cohort key, used for baseline lookup.
        profiles: trained cohort profiles for p10/p99 lookups.
        baselines: per-category baselines from the trained bundle's metadata.

    Returns:
        List of FiredRules. Empty if nothing tripped.
    """
    if cohort_rows.empty:
        return []

    fired: list[FiredRule] = []

    fired.extend(_rule_token_high(cohort_rows))
    fired.extend(_rule_near_timeout(cohort_rows))
    fired.extend(_rule_high_cost_outlier(cohort_rows, model_id, category, profiles))
    fired.extend(_rule_exfil_shape(cohort_rows, model_id, category, profiles))
    fired.extend(_rule_content_filter_spike(cohort_rows, category, baselines))
    fired.extend(_rule_error_storm(cohort_rows, category, baselines))

    return fired


# ── Per-row rules ──────────────────────────────────────────────────────────


def _rule_token_high(rows: pd.DataFrame) -> list[FiredRule]:
    pt = pd.to_numeric(rows.get("llm_prompt_tokens"), errors="coerce").fillna(0)
    mask = pt >= TOKEN_HIGH_FLOOR
    n = int(mask.sum())
    if n == 0:
        return []
    return [FiredRule(
        rule_id="LLM_TOKEN_HIGH",
        severity=RULE_SEVERITY["LLM_TOKEN_HIGH"],
        rows_affected=n,
        context={
            "threshold_tokens": TOKEN_HIGH_FLOOR,
            "max_observed": int(pt[mask].max()),
            "fraction": round(n / len(rows), 4),
        },
    )]


def _rule_near_timeout(rows: pd.DataFrame) -> list[FiredRule]:
    rt = pd.to_numeric(rows.get("llm_response_time_ms"), errors="coerce").fillna(0)
    mask = rt >= LLM_NEAR_TIMEOUT_THRESHOLD_MS
    n = int(mask.sum())
    if n == 0:
        return []
    return [FiredRule(
        rule_id="LLM_NEAR_TIMEOUT",
        severity=RULE_SEVERITY["LLM_NEAR_TIMEOUT"],
        rows_affected=n,
        context={
            "threshold_ms": LLM_NEAR_TIMEOUT_THRESHOLD_MS,
            "max_observed_ms": float(rt[mask].max()),
            "fraction": round(n / len(rows), 4),
        },
    )]


def _rule_high_cost_outlier(
    rows: pd.DataFrame,
    model_id: str,
    category: str,
    profiles: CohortProfiles,
) -> list[FiredRule]:
    """
    cost_z > 4 AND cost > $0.10.

    The double condition matters: a small cohort with low std produces
    extreme z-scores on tiny dollar amounts; the absolute floor suppresses
    those false positives.
    """
    stats = profiles.lookup(model_id, category, "llm_cost_usd")
    cost = pd.to_numeric(rows.get("llm_cost_usd"), errors="coerce").fillna(0)
    if stats.std == 0:
        return []
    z = (cost - stats.mean) / stats.std
    mask = (z > HIGH_COST_Z_THRESHOLD) & (cost > HIGH_COST_FLOOR_USD)
    n = int(mask.sum())
    if n == 0:
        return []
    return [FiredRule(
        rule_id="LLM_HIGH_COST_OUTLIER",
        severity=RULE_SEVERITY["LLM_HIGH_COST_OUTLIER"],
        rows_affected=n,
        context={
            "z_threshold": HIGH_COST_Z_THRESHOLD,
            "absolute_floor_usd": HIGH_COST_FLOOR_USD,
            "max_z": float(z[mask].max()),
            "max_cost_usd": float(cost[mask].max()),
            "cohort_mean_cost": stats.mean,
            "cohort_std_cost": stats.std,
        },
    )]


def _rule_exfil_shape(
    rows: pd.DataFrame,
    model_id: str,
    category: str,
    profiles: CohortProfiles,
) -> list[FiredRule]:
    """
    Small input, huge output. Classic data-exfil signature: attacker
    coaxes the model into regurgitating training data or context with a
    short trigger prompt.
    """
    pt_stats = profiles.lookup(model_id, category, "llm_prompt_tokens")
    tt_stats = profiles.lookup(model_id, category, "llm_total_tokens")

    pt = pd.to_numeric(rows.get("llm_prompt_tokens"), errors="coerce").fillna(0)
    tt = pd.to_numeric(rows.get("llm_total_tokens"), errors="coerce").fillna(0)
    mask = (pt < pt_stats.p10) & (tt > tt_stats.p99)
    n = int(mask.sum())
    if n == 0:
        return []
    return [FiredRule(
        rule_id="LLM_EXFIL_SHAPE",
        severity=RULE_SEVERITY["LLM_EXFIL_SHAPE"],
        rows_affected=n,
        context={
            "prompt_p10": pt_stats.p10,
            "total_p99": tt_stats.p99,
            "min_prompt_tokens": int(pt[mask].min()),
            "max_total_tokens": int(tt[mask].max()),
        },
    )]


# ── Cohort-level rules (spike detection) ──────────────────────────────────


def _rule_content_filter_spike(
    rows: pd.DataFrame,
    category: str,
    baselines: dict[str, dict[str, float]],
) -> list[FiredRule]:
    if len(rows) < SPIKE_MIN_BATCH_SIZE:
        return []
    baseline = baselines.get(category, {}).get("content_filter_rate", 0.0)
    if baseline <= 0:
        # Without a baseline we can't compute a ratio; skip rather than
        # firing on every category we've never seen before.
        return []
    finish_reason = (
        rows.get("llm_finish_reason", pd.Series("", index=rows.index))
        .fillna("")
        .astype(str)
        .str.lower()
    )
    cf_count = int((finish_reason == "content_filter").sum())
    observed_rate = cf_count / len(rows)
    ratio = observed_rate / baseline
    if ratio < CONTENT_FILTER_SPIKE_RATIO or observed_rate < CONTENT_FILTER_SPIKE_FLOOR:
        return []
    return [FiredRule(
        rule_id="LLM_CONTENT_FILTER_SPIKE",
        severity=RULE_SEVERITY["LLM_CONTENT_FILTER_SPIKE"],
        rows_affected=cf_count,
        context={
            "baseline_rate": baseline,
            "observed_rate": observed_rate,
            "ratio": round(ratio, 2),
            "threshold_ratio": CONTENT_FILTER_SPIKE_RATIO,
            "batch_size": int(len(rows)),
        },
    )]


def _rule_error_storm(
    rows: pd.DataFrame,
    category: str,
    baselines: dict[str, dict[str, float]],
) -> list[FiredRule]:
    if len(rows) < SPIKE_MIN_BATCH_SIZE:
        return []
    base = baselines.get(category, {})
    baseline = (base.get("error_rate", 0.0) or 0.0) + (base.get("timeout_rate", 0.0) or 0.0)
    if baseline <= 0:
        return []
    log_type = rows.get("log_type", pd.Series("", index=rows.index)).astype(str).str.upper()
    err_count = int(log_type.isin({"LLM_ERROR", "LLM_TIMEOUT"}).sum())
    observed_rate = err_count / len(rows)
    ratio = observed_rate / baseline
    if ratio < ERROR_STORM_RATIO or observed_rate < ERROR_STORM_FLOOR:
        return []
    return [FiredRule(
        rule_id="LLM_ERROR_STORM",
        severity=RULE_SEVERITY["LLM_ERROR_STORM"],
        rows_affected=err_count,
        context={
            "baseline_rate": baseline,
            "observed_rate": observed_rate,
            "ratio": round(ratio, 2),
            "threshold_ratio": ERROR_STORM_RATIO,
            "batch_size": int(len(rows)),
        },
    )]
