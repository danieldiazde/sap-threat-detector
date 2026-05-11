"""
tools.py
--------
Implementation of the conversational agent's tool surface.

Every tool is an ``async`` function that returns a JSON-serialisable
dict. ``TOOL_REGISTRY`` maps the tool name (as the LLM sees it) to the
callable. ``Agent._run_one_tool`` calls ``dispatch`` directly in-process;
``src/api/agent_routes.py`` exposes the same dispatcher via HTTP for
external callers.

Tools degrade gracefully — on any failure they return
``{"error": "<message>", "_render": "raw"}`` rather than raising. The
agent loop then has the option to retry or surface the error to the
user.

Each return value carries a ``_render`` hint
(``"scalar" | "table" | "bar_chart" | "line_chart" | "raw"``) so the
Streamlit page can pick the right widget without inferring from the
tool name.

See ``docs/CONVERSATIONAL_AGENT.md`` for the full design.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

from src.agent.helpers import (
    breakdown_by,
    compare_windows,
    correlate,
    time_series,
)
from src.agent.semantic_loader import describe_table, known_tables
from src.alerting.sap_webhook import MESSAGE_MAX_CHARS, format_alert_message
from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import iso, utcnow
from src.ingestion.sap_log_fetcher import fetch_info, fetch_logs
from src.storage.pool import pool
from src.storage.repositories import (
    anomaly_repository,
    log_repository,
    model_version_repository,
)

logger = get_logger(__name__)

# ─── v2 constants ──────────────────────────────────────────────────────────

CUSTOM_QUERY_ROW_CAP: int = 20  # plan §1
CUSTOM_QUERY_TIMEOUT_S: float = 10.0  # plan §10b
CUSTOM_QUERY_ERROR_MAX: int = 400
CUSTOM_QUERY_ALLOWED_TABLES: frozenset[str] = frozenset(
    {"SECURITY_LOGS", "ANOMALIES", "MODEL_VERSIONS"}
)

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


# ─── v2 tools ──────────────────────────────────────────────────────────────


async def describe_schema(table_name: str) -> dict[str, Any]:
    """Rich per-table metadata (columns, meanings, common filters,
    metrics, example queries). Loaded from ``semantic_model.yaml``.
    """
    payload = describe_table(table_name)
    if payload is None:
        return {
            "error": f"unknown table '{table_name}'. Known: {sorted(known_tables())}",
            "_render": "raw",
        }
    payload["_render"] = "raw"
    return payload


async def sample_table(table: str, n: int = 5) -> dict[str, Any]:
    """Return *n* sample rows (newest-first) from one of the known tables.

    Whitelist-validated against the semantic model so the agent cannot
    request arbitrary tables. Capped at 10 rows regardless of *n*.
    """
    table_u = (table or "").upper().strip()
    if table_u not in known_tables():
        return {
            "error": f"unknown table '{table}'. Known: {sorted(known_tables())}",
            "_render": "raw",
        }
    n = max(1, min(int(n), 10))

    if settings.mock_hana:
        return {
            "table": table_u, "rows": [], "row_count": 0,
            "_mock": True, "_render": "table",
        }

    # Each table has a different "newest first" column — keep the
    # ordering keys explicit instead of inferring.
    order_col = {
        "SECURITY_LOGS": "INGESTED_AT",
        "ANOMALIES": "DETECTED_AT",
        "MODEL_VERSIONS": "TRAINED_AT",
    }[table_u]
    sql = f"SELECT TOP {n} * FROM {table_u} ORDER BY {order_col} DESC"

    try:
        async with pool.acquire() as conn:
            if conn is None:
                return {"error": "hana_unavailable", "_render": "raw"}
            rows = await asyncio.to_thread(_run_select_rows, conn, sql, ())
    except Exception as exc:
        logger.exception("agent.sample_table.failed", extra={"table": table_u})
        return {"error": f"{type(exc).__name__}: {exc}"[:400], "_render": "raw"}
    return {
        "table": table_u, "rows": rows, "row_count": len(rows),
        "_render": "table",
    }


# ─── run_custom_query (hardened, plan §1 + §2) ────────────────────────────

# Single-statement SELECT only. Reject anything that smells like DML/DDL
# even if it appears after a comment — block multi-statements outright.
_FORBIDDEN_TOKENS = re.compile(
    r"(?i)\b("
    r"insert|update|delete|drop|truncate|alter|create|grant|revoke|"
    r"merge|call|exec|execute|rename|comment"
    r")\b"
)
_LIMIT_TRAILING = re.compile(r"(?is)\blimit\s+\d+\s*;?\s*$")
_SQL_STRING = re.compile(r"'(?:''|[^'])*'")
_SQL_LINE_COMMENT = re.compile(r"--[^\n\r]*")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_CTE_NAME = re.compile(r"(?is)(?:\bwith\b|,)\s*([A-Za-z_][\w$]*)\s+as\s*\(")
_TABLE_REF = re.compile(r"(?is)\b(?:from|join)\s+([A-Za-z_][\w$]*)(?:\s*\.\s*([A-Za-z_][\w$]*))?")


def _enforce_limit(sql: str, cap: int) -> str:
    """Replace any trailing LIMIT with LIMIT *cap*; otherwise append it.

    HANA accepts LIMIT as a final clause. We always pass *cap+1* (caller
    decides) so the truncated flag can be derived from the row count.
    """
    stripped = sql.rstrip().rstrip(";").rstrip()
    if _LIMIT_TRAILING.search(stripped + ";"):
        stripped = _LIMIT_TRAILING.sub("", stripped + ";").rstrip().rstrip(";").rstrip()
    return f"{stripped} LIMIT {cap}"


def _classify_error(msg: str) -> str | None:
    """One-line hint for common HANA errors."""
    low = msg.lower()
    if "invalid column name" in low or "unknown column" in low:
        return "Unknown column. Call describe_schema(table_name) for the column list."
    if "invalid table name" in low or "could not find table" in low or "table not found" in low:
        return "Unknown table. Allowed tables: SECURITY_LOGS, ANOMALIES, MODEL_VERSIONS."
    if "syntax error" in low:
        return "Syntax error — re-check keywords and parentheses."
    if "ambiguous" in low:
        return "Ambiguous column reference — qualify with the table name."
    return None


def _sql_for_scope_checks(sql: str) -> str:
    no_comments = _SQL_BLOCK_COMMENT.sub(" ", sql)
    no_comments = _SQL_LINE_COMMENT.sub(" ", no_comments)
    return _SQL_STRING.sub("''", no_comments)


def _validate_query_scope(sql: str) -> str | None:
    """Return an error if the query touches tables outside the agent allowlist."""
    scrubbed = _sql_for_scope_checks(sql)
    ctes = {m.group(1).upper() for m in _CTE_NAME.finditer(scrubbed)}
    refs: list[str] = []
    for match in _TABLE_REF.finditer(scrubbed):
        schema_or_table = match.group(1).upper()
        table = match.group(2).upper() if match.group(2) else schema_or_table
        if schema_or_table != table:
            return "schema-qualified table names are not allowed"
        refs.append(table)

    for table in refs:
        if table in ctes:
            continue
        if table not in CUSTOM_QUERY_ALLOWED_TABLES:
            allowed = ", ".join(sorted(CUSTOM_QUERY_ALLOWED_TABLES))
            return f"table '{table}' is not allowed. Allowed tables: {allowed}"
    return None


def _sanitize_error(exc: BaseException) -> dict[str, Any]:
    raw = f"{type(exc).__name__}: {exc}"
    # Strip anything that looks like a connection string (user@host:port).
    raw = re.sub(r"\S+@\S+:\d+", "<conn>", raw)
    msg = raw[:CUSTOM_QUERY_ERROR_MAX]
    out: dict[str, Any] = {"error": msg}
    hint = _classify_error(msg)
    if hint:
        out["hint"] = hint
    return out


async def run_custom_query(
    sql: str,
    count_total: bool = False,
) -> dict[str, Any]:
    """Run an analyst-authored SELECT with hard safety rails.

    - Read-only (SELECT). DML/DDL tokens trigger an immediate validation
      error before HANA is touched.
    - Always capped at ``CUSTOM_QUERY_ROW_CAP`` rows. We send LIMIT 21 to
      detect truncation; if 21 rows come back we flag ``truncated=True``
      and return only the first 20.
    - ``count_total=True`` (opt-in) wraps the inner query in
      ``SELECT COUNT(*) FROM (...)`` and returns the total instead of
      rows. Off by default — HANA re-scans on subquery COUNT, doubling
      latency on big tables (plan §1).
    - HANA errors are sanitized + classified (plan §2). The orchestrator
      counts these for the per-turn circuit breaker.
    """
    raw_sql = (sql or "").strip()
    if not raw_sql:
        return {"error": "empty_query", "_render": "raw"}
    # Reject multi-statements — HANA's hdbcli would refuse anyway, but
    # we want an obvious error before the round-trip.
    if ";" in raw_sql.rstrip(";"):
        return {
            "error": "multi-statement queries are not allowed",
            "query_attempted": raw_sql[:200],
            "_render": "raw",
        }
    no_trailing_semi = raw_sql.rstrip(";").strip()
    lowered = no_trailing_semi.lstrip().lower()
    if not (lowered.startswith("select") or lowered.startswith("with")):
        return {
            "error": "only SELECT statements are allowed",
            "query_attempted": raw_sql[:200],
            "_render": "raw",
        }
    forbidden = _FORBIDDEN_TOKENS.search(no_trailing_semi)
    if forbidden:
        return {
            "error": f"forbidden keyword '{forbidden.group(1)}'",
            "query_attempted": raw_sql[:200],
            "_render": "raw",
        }
    scope_error = _validate_query_scope(no_trailing_semi)
    if scope_error:
        return {
            "error": scope_error,
            "query_attempted": raw_sql[:200],
            "_render": "raw",
        }

    if count_total:
        executed = f"SELECT COUNT(*) AS total FROM ({no_trailing_semi})"
    else:
        executed = _enforce_limit(no_trailing_semi, CUSTOM_QUERY_ROW_CAP + 1)

    if settings.mock_hana:
        return {
            "rows": [], "row_count_returned": 0, "truncated": False,
            "columns": [], "query_executed": executed, "elapsed_ms": 0,
            "_mock": True, "_render": "table",
        }

    started = time.monotonic()
    try:
        async def _go() -> dict[str, Any]:
            return await asyncio.to_thread(_run_select_columns_fresh, executed, ())
        result = await asyncio.wait_for(_go(), timeout=CUSTOM_QUERY_TIMEOUT_S)
    except TimeoutError:
        return {
            "error": "query_timeout",
            "elapsed_ms": int(CUSTOM_QUERY_TIMEOUT_S * 1000),
            "query_attempted": executed,
            "_render": "raw",
        }
    except Exception as exc:
        logger.exception("agent.run_custom_query.failed")
        out = _sanitize_error(exc)
        out["query_attempted"] = executed
        out["_render"] = "raw"
        return out

    if "error" in result:
        return {**result, "_render": "raw"}

    rows: list[dict[str, Any]] = result["rows"]
    cols: list[str] = result["columns"]

    if count_total:
        total = rows[0].get("total") if rows else 0
        return {
            "total": int(total) if total is not None else 0,
            "query_executed": executed,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "_render": "scalar",
        }

    truncated = len(rows) > CUSTOM_QUERY_ROW_CAP
    if truncated:
        rows = rows[:CUSTOM_QUERY_ROW_CAP]
    return {
        "rows": rows,
        "row_count_returned": len(rows),
        "truncated": truncated,
        "columns": cols,
        "query_executed": executed,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "_render": "table",
    }


def _run_select_rows(conn: Any, sql: str, params: tuple) -> list[dict[str, Any]]:
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        cols = [d[0].lower() for d in (cursor.description or [])]
        return [dict(zip(cols, r, strict=False)) for r in cursor.fetchall()]
    finally:
        cursor.close()


def _run_select_columns(
    conn: Any, sql: str, params: tuple
) -> dict[str, Any]:
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        cols = [d[0].lower() for d in (cursor.description or [])]
        rows = [dict(zip(cols, r, strict=False)) for r in cursor.fetchall()]
        return {"rows": rows, "columns": cols}
    finally:
        cursor.close()


def _run_select_columns_fresh(sql: str, params: tuple) -> dict[str, Any]:
    """Run custom SQL on a short-lived connection.

    The custom-query endpoint has a hard asyncio timeout. A timed-out
    ``to_thread`` call cannot stop hdbcli mid-flight, so this path deliberately
    avoids borrowing from the shared pool; a late worker thread cannot return a
    still-busy connection to other requests.
    """
    from hdbcli import dbapi
    from src.common.cf_proxy import get_hdbcli_proxy_kwargs

    kwargs: dict = dict(
        address=settings.hana_host,
        port=settings.hana_port,
        user=settings.hana_user,
        password=settings.hana_password,
        encrypt=True,
        sslValidateCertificate=False,
        communicationTimeout=int(CUSTOM_QUERY_TIMEOUT_S * 1000),
        **get_hdbcli_proxy_kwargs(),
    )
    if settings.hana_database:
        kwargs["databaseName"] = settings.hana_database
    conn = dbapi.connect(**kwargs)
    try:
        return _run_select_columns(conn, sql, params)
    finally:
        conn.close()


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
    # ── v2 ──
    "describe_schema": describe_schema,
    "sample_table": sample_table,
    "breakdown_by": breakdown_by,
    "compare_windows": compare_windows,
    "time_series": time_series,
    "correlate": correlate,
    "run_custom_query": run_custom_query,
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
