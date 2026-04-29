"""
tools.py
--------
Implementation of the v1 conversational agent's tool surface.

Every tool is an ``async`` function that returns a JSON-serialisable
dict. ``TOOL_REGISTRY`` maps the tool name (as the LLM sees it) to the
callable; the FastAPI ``/agent/tool`` dispatcher in
``src/api/agent_routes.py`` is the only caller in v1.

Tools degrade gracefully — on any failure they return
``{"error": "<message>", "_render": "raw"}`` rather than raising. The
agent loop then has the option to retry or surface the error to the
user.

Each return value carries a ``_render`` hint
(``"scalar" | "table" | "raw"``) so the Streamlit page can pick the
right widget without inferring from the tool name. v2 will add
``"line_chart"`` and ``"bar_chart"``.

See ``docs/agent_plan.md`` for the full tool list and ``docs/agent_plan_v2_insights.md``
for the v2 helpers that will land alongside this module.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from src.alerting.sap_webhook import MESSAGE_MAX_CHARS, format_alert_message
from src.common.logging import get_logger
from src.common.time_utils import iso, utcnow
from src.ingestion.sap_log_fetcher import fetch_info, fetch_logs
from src.storage.repositories import (
    anomaly_repository,
    log_repository,
    model_version_repository,
)

logger = get_logger(__name__)

# ─── Tool implementations ──────────────────────────────────────────────────


async def get_anomaly_count(hours: int = 24) -> dict[str, Any]:
    """Count anomalies detected in the last ``hours`` hours."""
    hours = _coerce_hours(hours)
    count = await anomaly_repository.count_since(hours)
    return {
        "count": count,
        "hours": hours,
        "since": iso(_cutoff(hours)),
        "_render": "scalar",
    }


async def get_top_suspicious_ips(
    limit: int = 10, hours: int = 1
) -> dict[str, Any]:
    """Top N source IPs by anomaly count within the last ``hours``.

    Returns each IP's count and ``min_score`` — the most-negative
    ANOMALY_SCORE we observed for that IP. Isolation-forest scores are
    negative and *lower means more anomalous*, so ``min_score`` is the
    "worst" score (most threatening). The lower the more dangerous.
    """
    hours = _coerce_hours(hours)
    limit = max(1, min(int(limit), 50))
    rows = await anomaly_repository.top_source_ips(hours=hours, limit=limit)
    return {
        "rows": rows,
        "hours": hours,
        "limit": limit,
        "_render": "table",
        "_score_convention": "min_score is the most-negative score; lower = more anomalous",
    }


async def get_recent_anomalies(
    limit: int = 20,
    threat_level: str | None = None,
    hours: int | None = None,
) -> dict[str, Any]:
    """Recent anomaly rows, optionally filtered by ``threat_level`` and ``hours``.

    ``threat_level`` must be one of ``HIGH``, ``MEDIUM``, ``LOW`` (case-
    insensitive). Anything else is silently ignored.
    """
    limit = max(1, min(int(limit), 50))
    hours_norm = _coerce_hours(hours) if hours is not None else None
    rows = await anomaly_repository.query_anomalies(
        limit=limit, threat_level=threat_level, hours=hours_norm
    )
    return {
        "rows": rows,
        "limit": limit,
        "threat_level": (threat_level or "").upper() or None,
        "hours": hours_norm,
        "_render": "table",
    }


async def get_mttd_stats(hours: int = 24) -> dict[str, Any]:
    """p50 / p95 pipeline MTTD over the last ``hours``."""
    hours = _coerce_hours(hours)
    stats = await anomaly_repository.mttd_percentiles(hours=hours)
    return {**stats, "hours": hours, "_render": "scalar"}


async def get_log_volume(hours: int = 24) -> dict[str, Any]:
    """Number of logs ingested in the last ``hours``."""
    hours = _coerce_hours(hours)
    count = await log_repository.count_since(hours)
    return {
        "count": count,
        "hours": hours,
        "since": iso(_cutoff(hours)),
        "_render": "scalar",
    }


async def get_model_info() -> dict[str, Any]:
    """Currently registered model version (latest by trained_at)."""
    latest = await model_version_repository.latest()
    if latest is None:
        return {"error": "no_model_registered", "_render": "raw"}
    # Trim noisy JSON-blob columns to keep the LLM context lean.
    trimmed = {
        k: v
        for k, v in latest.items()
        if k in {
            "version_tag", "model_type", "trained_at", "contamination",
            "training_samples", "is_active", "notes", "cv_scores",
        }
    }
    return {**trimmed, "_render": "raw"}


async def get_current_window_info() -> dict[str, Any]:
    """Live ``GET /info`` from the SAP API."""
    info = await fetch_info()
    if not info:
        return {"error": "info_unavailable", "_render": "raw"}
    return {**info, "_render": "raw"}


async def get_current_logs_sample(max_rows: int = 10) -> dict[str, Any]:
    """First page of live ``/logs/current``, projected to a small column set.

    Hard cap of 10 rows + projection to ``(SOURCE_IP, EVENT_DESCRIPTION,
    DATETIME, STATUS, LOG_TYPE)`` keeps the response tiny — v1 has no
    smart-truncation layer yet, and the LLM_*/JSON columns are heavy.
    """
    max_rows = max(1, min(int(max_rows), 10))
    df = await fetch_logs(page=1)
    if df is None or df.empty:
        return {"rows": [], "row_count": 0, "_render": "table"}
    keep = [c for c in ("source_ip", "event_description", "datetime",
                        "status", "log_type") if c in df.columns]
    sliced = df.head(max_rows)[keep] if keep else df.head(max_rows)
    rows = sliced.astype(object).where(sliced.notna(), None).to_dict(orient="records")
    return {
        "rows": rows,
        "row_count": len(rows),
        "columns": keep,
        "_render": "table",
    }


async def submit_alert(
    what: str, when: str, why: str
) -> dict[str, Any]:
    """Format and validate a free-form alert. **Does not send.**

    The Streamlit page renders the preview and shows an "Approve & send"
    button. On click, the page calls ``/agent/post_alert`` with the
    preview message — the agent never has a code path that posts
    automatically.

    Returns ``{preview, message_len, requires_confirmation: True}`` on
    success, or ``{error}`` if the formatted message exceeds 300 chars
    after WHY-truncation.
    """
    what_s = (what or "").strip() or "Anomaly"
    when_s = (when or "").strip() or iso(utcnow())
    why_s = (why or "").strip() or "score below threshold"

    # Reuse the same shape as send_alert() so analyst-drafted alerts
    # look the same on the wire as pipeline-generated ones.
    head = f"WHAT: {what_s} WHEN: {when_s} WHY: "
    budget = MESSAGE_MAX_CHARS - len(head)
    if budget < 1:
        return {
            "error": "what_when_too_long",
            "message_len": len(head),
            "_render": "raw",
        }
    body = why_s if len(why_s) <= budget else why_s[: budget - 1] + "."
    preview = head + body

    return {
        "preview": preview,
        "message_len": len(preview),
        "requires_confirmation": True,
        "_render": "raw",
    }


# ─── Dispatcher registry ───────────────────────────────────────────────────

ToolFn = Callable[..., Awaitable[dict[str, Any]]]

TOOL_REGISTRY: dict[str, ToolFn] = {
    "get_anomaly_count": get_anomaly_count,
    "get_top_suspicious_ips": get_top_suspicious_ips,
    "get_recent_anomalies": get_recent_anomalies,
    "get_mttd_stats": get_mttd_stats,
    "get_log_volume": get_log_volume,
    "get_model_info": get_model_info,
    "get_current_window_info": get_current_window_info,
    "get_current_logs_sample": get_current_logs_sample,
    "submit_alert": submit_alert,
}


async def dispatch(name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Look up *name* in the registry and call it with *args*.

    Returns ``{"error": ...}`` on unknown tool name or per-tool exception
    so the FastAPI route handler can return a uniform shape regardless
    of what went wrong inside the tool body.
    """
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return {"error": f"unknown_tool:{name}", "_render": "raw"}
    try:
        return await fn(**(args or {}))
    except TypeError as exc:
        return {
            "error": f"bad_args: {exc}",
            "_render": "raw",
        }
    except Exception as exc:
        logger.exception("agent.tool.error", extra={"tool": name})
        return {"error": f"{type(exc).__name__}: {exc}", "_render": "raw"}


# ─── Helpers ───────────────────────────────────────────────────────────────


def _coerce_hours(hours: int) -> int:
    """Clamp hours to [1, 720] (30d max). Defends the SQL from a
    misbehaving LLM passing 0 or negative values."""
    try:
        h = int(hours)
    except (TypeError, ValueError):
        h = 24
    return max(1, min(h, 720))


def _cutoff(hours: int):
    from datetime import timedelta

    return utcnow() - timedelta(hours=hours)


# Suppress "unused" lints — exposed for tests/devtools.
_ = (asyncio, format_alert_message)
