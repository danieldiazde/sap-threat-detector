"""
incident_report.py
------------------
Generate markdown forensic reports for high-severity anomalies.

The format mirrors ``docs/INCIDENT_REPORT.md`` (OBSERVE → ANALYZE →
DETECT → RESPOND → Remediation) and is filled from the scored anomaly
row + evidence DataFrame + metrics snapshot. Reports are written to
``settings.incident_report_dir`` and the path is stored in the
``ANOMALIES`` table for dashboard links.

Owner: Security Analyst & Visualization Lead
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import iso, utcnow

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

MAX_EVIDENCE_ROWS: int = 10


def build_incident_report(
    anomaly: dict[str, Any],
    evidence: pd.DataFrame,
    metrics_snapshot: dict[str, Any] | None = None,
) -> str:
    """Render a markdown forensic report for a single anomaly."""
    if str(anomaly.get("detector", "sap")).lower() == "llm":
        return _build_llm_incident_report(anomaly, evidence, metrics_snapshot)
    incident_id = _incident_id(anomaly)
    detected_at = anomaly.get("detected_at") or utcnow()
    source_ip = anomaly.get("source_ip", "unknown")
    threat_level = anomaly.get("threat_level", "unknown")
    score = float(anomaly.get("anomaly_score", 0) or 0)
    pipeline_mttd = anomaly.get("pipeline_mttd_ms", "—")
    e2e_mttd = anomaly.get("e2e_mttd_ms", "—")
    multi_bucket = anomaly.get("multi_bucket_count", 0)

    evidence_table = _evidence_table(evidence)
    triggering_features = _feature_table(anomaly)
    recommended_actions = _recommendations(anomaly)

    return f"""# 🛡️ Incident Report — {incident_id}

## Summary

| Field | Value |
|-------|-------|
| Incident ID | `{incident_id}` |
| Detected at | `{_fmt_dt(detected_at)}` |
| Source IP | `{source_ip}` |
| Threat Level | **{str(threat_level).upper()}** |
| Anomaly Score | `{score:.4f}` |
| Pipeline MTTD | `{pipeline_mttd} ms` |
| End-to-End MTTD | `{e2e_mttd} ms` |
| Multi-bucket count | `{multi_bucket}` |
| Model version | `{anomaly.get('model_version', 'unknown')}` |

## OBSERVE — What the logs showed

The following log entries were associated with this source IP during the
detection window:

{evidence_table}

## ANALYZE — What the model detected

The model flagged this IP because the feature values were significantly
outside the learned distribution of normal traffic.

{triggering_features}

## DETECT — Latency

- **Pipeline MTTD**: `{pipeline_mttd} ms` — time from log ingestion to alert
- **End-to-End MTTD**: `{e2e_mttd} ms` — time from the original event to alert

{_metrics_section(metrics_snapshot)}

## RESPOND — Alert actions

- Webhook fired: `{anomaly.get('webhook_sent', True)}`
- Alert ID: `{anomaly.get('alert_id', 'n/a')}`
- Dedup key: `{anomaly.get('dedup_key', 'n/a')}`

## Remediation — Recommended next steps

{recommended_actions}

## Model Performance Notes

_To be completed by the Security Analyst after review._

- False positive? ☐ yes  ☐ no
- Threshold adjustment recommended? ☐ yes  ☐ no
- Retrain recommended? ☐ yes  ☐ no

---
_Generated automatically by `src/alerting/incident_report.py` at `{_fmt_dt(utcnow())}`._
"""


def _build_llm_incident_report(
    anomaly: dict[str, Any],
    evidence: pd.DataFrame,
    metrics_snapshot: dict[str, Any] | None,
) -> str:
    incident_id = _incident_id(anomaly)
    detected_at = anomaly.get("detected_at") or utcnow()
    model_id = anomaly.get("llm_model_id", "unknown")
    category = anomaly.get("llm_prompt_category", "unknown")
    threat_level = anomaly.get("threat_level", "unknown")
    score = float(anomaly.get("anomaly_score", 0) or 0)
    if_global = anomaly.get("if_global_score")
    if_category = anomaly.get("if_category_score")
    pipeline_mttd = anomaly.get("pipeline_mttd_ms", "—")
    e2e_mttd = anomaly.get("e2e_mttd_ms", "—")
    total_requests = int(anomaly.get("total_requests", 0) or 0)
    global_frac = float(anomaly.get("global_anomaly_fraction", 0) or 0)
    category_frac = float(anomaly.get("category_anomaly_fraction", 0) or 0)

    rule_ids: list[str] = []
    raw = anomaly.get("rule_ids")
    if raw:
        try:
            import json as _json
            rule_ids = _json.loads(raw) if isinstance(raw, str) else list(raw)
        except (ValueError, TypeError):
            rule_ids = []

    rule_context: dict[str, Any] = {}
    raw_ctx = anomaly.get("rule_context")
    if raw_ctx:
        try:
            import json as _json
            rule_context = _json.loads(raw_ctx) if isinstance(raw_ctx, str) else dict(raw_ctx)
        except (ValueError, TypeError):
            rule_context = {}

    rules_md = _llm_rules_table(rule_ids, rule_context) if rule_ids else "_No rules fired — anomaly emitted by IF ensemble alone._"
    evidence_md = _llm_evidence_summary(evidence, model_id, category)

    return f"""# 🤖 Incident Report — {incident_id}

## Summary

| Field | Value |
|-------|-------|
| Incident ID | `{incident_id}` |
| Detected at | `{_fmt_dt(detected_at)}` |
| Detector | `llm` |
| LLM model | `{model_id}` |
| Prompt category | `{category}` |
| Threat Level | **{str(threat_level).upper()}** |
| Mean global IF score | `{score:.4f}` |
| Cohort size | `{total_requests}` |
| Global anomaly fraction | `{global_frac:.2%}` |
| Per-category anomaly fraction | `{category_frac:.2%}` |
| IF global score (mean) | `{if_global if if_global is not None else '—'}` |
| IF per-category score (mean) | `{if_category if if_category is not None else '—'}` |
| Pipeline MTTD | `{pipeline_mttd} ms` |
| End-to-End MTTD | `{e2e_mttd} ms` |
| Model version | `{anomaly.get('model_version', 'unknown')}` |

## OBSERVE — Cohort context

{evidence_md}

## ANALYZE — Rules fired

{rules_md}

## DETECT — Latency

- **Pipeline MTTD**: `{pipeline_mttd} ms`
- **End-to-End MTTD**: `{e2e_mttd} ms`

{_metrics_section(metrics_snapshot)}

## RESPOND — Alert actions

- Webhook fired: `{anomaly.get('webhook_sent', True)}`
- Alert ID: `{anomaly.get('alert_id', 'n/a')}`
- Dedup key: `{anomaly.get('dedup_key', 'n/a')}`

## Remediation — Recommended next steps

{_llm_recommendations(rule_ids)}

---
_Generated automatically by `src/alerting/incident_report.py` at `{_fmt_dt(utcnow())}`._
"""


def _llm_rules_table(rule_ids: list[str], rule_context: dict[str, Any]) -> str:
    rows = ["| Rule | Context |", "|------|---------|"]
    for rid in rule_ids:
        ctx = rule_context.get(rid, {})
        ctx_str = ", ".join(f"`{k}={v}`" for k, v in ctx.items()) if isinstance(ctx, dict) else str(ctx)
        rows.append(f"| `{rid}` | {ctx_str or '—'} |")
    return "\n".join(rows)


def _llm_evidence_summary(evidence: pd.DataFrame, model_id: Any, category: Any) -> str:
    if evidence is None or evidence.empty:
        return f"_No raw rows available for cohort `{model_id}/{category}`._"
    cols = [c for c in ("datetime", "llm_model_id", "llm_prompt_category", "llm_status", "llm_finish_reason", "llm_total_tokens", "llm_cost_usd", "llm_response_time_ms") if c in evidence.columns]
    if not cols:
        return f"_Cohort `{model_id}/{category}` — no LLM columns present in evidence._"
    return evidence.head(MAX_EVIDENCE_ROWS)[cols].astype(str).to_markdown(index=False)


def _llm_recommendations(rule_ids: list[str]) -> str:
    tips = {
        "LLM_TOKEN_HIGH": "Token budget anomaly — investigate prompt template inflation or runaway context-stuffing.",
        "LLM_HIGH_COST_OUTLIER": "Cost outlier — verify caller authorization and check for expensive-model misuse.",
        "LLM_NEAR_TIMEOUT": "Near-timeout pattern — capacity planning / model rerouting; possible upstream slowness.",
        "LLM_ERROR_STORM": "Error storm — check provider status; consider failover or temporary backpressure.",
        "LLM_CONTENT_FILTER_SPIKE": "Content-filter spike — investigate prompt-injection or policy-evasion attempts.",
        "LLM_EXFIL_SHAPE": "Exfiltration shape — large output/short input ratio; review caller intent and DLP policy.",
    }
    if not rule_ids:
        return "1. No rules fired — review the cohort manually before deciding on remediation."
    return "\n".join(f"{i}. **{rid}** — {tips.get(rid, 'review cohort.')}" for i, rid in enumerate(rule_ids, 1))


def write_report(report_md: str, incident_id: str, *, directory: Path | None = None) -> Path:
    """Persist *report_md* to disk and return the file path."""
    out_dir = directory or settings.incident_report_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{incident_id}.md"
    path.write_text(report_md, encoding="utf-8")
    logger.info("incident_report.written", extra={"path": str(path)})
    return path


# ─── Helpers ───────────────────────────────────────────────────────────────


def _incident_id(anomaly: dict[str, Any]) -> str:
    """Build a human-readable incident ID."""
    ts_src = anomaly.get("detected_at") or utcnow()
    if hasattr(ts_src, "strftime"):
        ts = ts_src.strftime("%Y%m%dT%H%M%S")
    else:
        ts = str(ts_src).replace(":", "").replace("-", "")[:15]
    ip = str(anomaly.get("source_ip", "unknown")).replace(".", "-")
    return f"INC-{ts}-{ip}"


def _fmt_dt(value: Any) -> str:
    if isinstance(value, datetime):
        return iso(value)
    return str(value)


def _evidence_table(evidence: pd.DataFrame) -> str:
    if evidence is None or evidence.empty:
        return "_No evidence rows captured._"
    head = evidence.head(MAX_EVIDENCE_ROWS)
    preferred = [c for c in ("datetime", "source_ip", "port_service", "event_description", "status") if c in head.columns]
    if not preferred:
        return "_Evidence columns missing._"
    sub = head[preferred].astype(str)
    return sub.to_markdown(index=False)


def _feature_table(anomaly: dict[str, Any]) -> str:
    feature_keys = [
        "total_requests",
        "error_rate",
        "post_ratio",
        "denied_ratio",
        "status_4xx_ratio",
        "status_5xx_ratio",
        "suspicious_path_ratio",
        "sql_injection_hits",
        "brute_force_score",
        "port_diversity",
        "request_rate_zscore",
    ]
    rows = []
    for key in feature_keys:
        if key in anomaly:
            value = anomaly[key]
            if isinstance(value, float):
                value = f"{value:.4f}"
            rows.append(f"| `{key}` | {value} |")
    if not rows:
        return "_No feature values available._"
    header = "| Feature | Value |\n|---------|-------|"
    return header + "\n" + "\n".join(rows)


def _metrics_section(snapshot: dict[str, Any] | None) -> str:
    if not snapshot:
        return ""
    pmttd = snapshot.get("pipeline_mttd_ms", {})
    e2e = snapshot.get("e2e_mttd_ms", {})
    return (
        "\n### Pipeline latency (rolling window)\n"
        f"- Pipeline MTTD p50: `{pmttd.get('p50', 0)} ms` / p95: `{pmttd.get('p95', 0)} ms`\n"
        f"- End-to-End MTTD p50: `{e2e.get('p50', 0)} ms` / p95: `{e2e.get('p95', 0)} ms`\n"
    )


def _recommendations(anomaly: dict[str, Any]) -> str:
    actions: list[str] = []
    sql_hits = int(anomaly.get("sql_injection_hits", 0) or 0)
    brute = float(anomaly.get("brute_force_score", 0) or 0)
    denied = float(anomaly.get("denied_ratio", 0) or 0)
    suspicious = float(anomaly.get("suspicious_path_ratio", 0) or 0)
    multi_bucket = int(anomaly.get("multi_bucket_count", 0) or 0)

    if sql_hits > 0:
        actions.append(
            "1. **SQL injection suspected** — review WAF logs, confirm "
            "parameterized queries, check DB audit logs for successful payloads."
        )
    if brute > 0.2:
        actions.append(
            "2. **Brute-force pattern** — enforce account lockout / rate-limiting "
            "on the targeted service and rotate any credentials hit."
        )
    if denied > 0.5:
        actions.append(
            "3. **High denied ratio** — confirm firewall rules are tuned correctly; "
            "consider IP-level blocking at the edge."
        )
    if suspicious > 0.2:
        actions.append(
            "4. **Directory scan** — check that sensitive paths are not exposed; "
            "rotate any admin credentials."
        )
    if multi_bucket >= 3:
        actions.append(
            "5. **Sustained attack across multiple windows** — escalate to on-call; "
            "consider short-term IP block."
        )
    if not actions:
        actions.append(
            "1. Review the triggering logs above and confirm whether the anomaly "
            "reflects a real threat or a benign pattern."
        )
    return "\n".join(actions)
