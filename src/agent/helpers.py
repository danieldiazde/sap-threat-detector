"""
helpers.py
----------
v2 analytical helpers (`docs/agent_plan_v2_insights.md` §6).

Each helper is a parameterized SQL template whose only inputs are
whitelisted enum values (metric / dimension / bucket / top_n) plus an
hours window. There is **no string interpolation of agent-supplied
values into SQL beyond the whitelist** — that is the whole point: these
helpers eliminate the SQL-injection surface that exists in
``run_custom_query`` for the common analytical shapes.

All helpers return ``{"error": ...}`` rather than raising, so the agent
loop never sees a Python exception. Mock mode (no HANA) returns a
shape-compatible empty result with ``_mock=True`` so the dashboard does
not break locally.

Render hints (``_render``):
- ``breakdown_by``    → ``"bar_chart"``
- ``compare_windows`` → ``"scalar"``
- ``time_series``     → ``"line_chart"``
- ``correlate``       → ``"table"``
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.common.config import settings
from src.common.logging import get_logger
from src.storage.pool import pool

logger = get_logger(__name__)

# ─── Whitelists ────────────────────────────────────────────────────────────

# metric → (table, sql_expression). The expression is what goes after
# SELECT ..., either an aggregate or a sentinel that the helper
# specialises (e.g. mttd_p50/p95 use PERCENTILE_CONT).
_ANOMALY_TABLE = "ANOMALIES"
_LOG_TABLE = "SECURITY_LOGS"
_ANOMALY_TIME_COL = "DETECTED_AT"
_LOG_TIME_COL = "DATETIME"

_METRIC_SPEC: dict[str, dict[str, str]] = {
    "anomaly_count": {
        "table": _ANOMALY_TABLE, "time_col": _ANOMALY_TIME_COL,
        "expr": "COUNT(*)",
    },
    "high_severity_count": {
        "table": _ANOMALY_TABLE, "time_col": _ANOMALY_TIME_COL,
        "expr": "SUM(CASE WHEN THREAT_LEVEL='high' THEN 1 ELSE 0 END)",
    },
    "mttd_p50": {
        "table": _ANOMALY_TABLE, "time_col": _ANOMALY_TIME_COL,
        "expr": "PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY PIPELINE_MTTD_MS)",
    },
    "mttd_p95": {
        "table": _ANOMALY_TABLE, "time_col": _ANOMALY_TIME_COL,
        "expr": "PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY PIPELINE_MTTD_MS)",
    },
    "log_volume": {
        "table": _LOG_TABLE, "time_col": _LOG_TIME_COL,
        "expr": "COUNT(*)",
    },
    "login_failure_count": {
        "table": _LOG_TABLE, "time_col": _LOG_TIME_COL,
        "expr": (
            "SUM(CASE WHEN LOWER(STATUS) IN ('failed','failure','denied','error') "
            "AND LOWER(LOG_TYPE) = 'auth' THEN 1 ELSE 0 END)"
        ),
    },
    "llm_token_total": {
        "table": _LOG_TABLE, "time_col": _LOG_TIME_COL,
        "expr": "SUM(LLM_TOTAL_TOKENS)",
    },
    "llm_cost_total": {
        "table": _LOG_TABLE, "time_col": _LOG_TIME_COL,
        "expr": "SUM(LLM_COST_USD)",
    },
}

# dimension → (table-it-belongs-to, column-name). When dimension's table
# does not match the metric's table we reject the call.
_DIMENSION_SPEC: dict[str, dict[str, str]] = {
    "source_ip":           {"table": "BOTH",        "column": "SOURCE_IP"},
    "sap_application":     {"table": _LOG_TABLE,    "column": "SAP_APPLICATION"},
    "region_code":         {"table": _LOG_TABLE,    "column": "REGION_CODE"},
    "macro_region":        {"table": _LOG_TABLE,    "column": "MACRO_REGION"},
    "log_type":            {"table": _LOG_TABLE,    "column": "LOG_TYPE"},
    "http_method":         {"table": _LOG_TABLE,    "column": "HTTP_METHOD"},
    "threat_level":        {"table": _ANOMALY_TABLE,"column": "THREAT_LEVEL"},
    "llm_prompt_category": {"table": "BOTH",        "column": "LLM_PROMPT_CATEGORY"},
    "sap_source_type":     {"table": _LOG_TABLE,    "column": "SAP_SOURCE_TYPE"},
}

_VALID_BUCKETS: set[int] = {1, 5, 15, 30, 60, 240, 1440}


class HelperValidationError(ValueError):
    """Raised before any SQL runs when an arg fails the whitelist check."""


# ─── Public helpers ────────────────────────────────────────────────────────


async def breakdown_by(
    metric: str = "anomaly_count",
    dimension: str = "source_ip",
    hours: int = 24,
    top_n: int = 20,
) -> dict[str, Any]:
    """Group ``metric`` by ``dimension`` over the last ``hours``."""
    try:
        m_spec = _validate_metric(metric)
        d_spec = _validate_dimension(dimension, m_spec["table"])
        hours_n = _validate_hours(hours)
        top_n_n = _validate_top_n(top_n)
    except HelperValidationError as exc:
        return _bad_args(exc)

    sql = (
        f"SELECT {d_spec['column']} AS dim, "
        f"{m_spec['expr']} AS metric_value "
        f"FROM {m_spec['table']} "
        f"WHERE {m_spec['time_col']} > ADD_SECONDS(CURRENT_TIMESTAMP, ?) "
        f"GROUP BY {d_spec['column']} "
        f"ORDER BY metric_value DESC "
        f"LIMIT {top_n_n}"
    )
    payload = await _run_select(sql, (-hours_n * 3600,))
    payload.update(
        metric=metric, dimension=dimension, hours=hours_n,
        _render="bar_chart",
    )
    return payload


async def compare_windows(
    metric: str = "anomaly_count",
    window_a_h: int = 1,
    window_b_h: int = 24,
) -> dict[str, Any]:
    """Compare ``metric`` over two adjacent windows ending now.

    ``window_a_h`` is the *recent* window (length=window_a_h hours,
    ending now). ``window_b_h`` is the *prior* window of the same
    length, ending where window_a started.

    Returns ``{window_a, window_b, delta_abs, delta_pct}``.
    """
    try:
        m_spec = _validate_metric(metric)
        a = _validate_hours(window_a_h)
        b = _validate_hours(window_b_h)
    except HelperValidationError as exc:
        return _bad_args(exc)

    # Two equal-length windows: A is (-a, now], B is (-(a+b), -a].
    sql_a = (
        f"SELECT {m_spec['expr']} AS v FROM {m_spec['table']} "
        f"WHERE {m_spec['time_col']} > ADD_SECONDS(CURRENT_TIMESTAMP, ?)"
    )
    sql_b = (
        f"SELECT {m_spec['expr']} AS v FROM {m_spec['table']} "
        f"WHERE {m_spec['time_col']} > ADD_SECONDS(CURRENT_TIMESTAMP, ?) "
        f"AND {m_spec['time_col']} <= ADD_SECONDS(CURRENT_TIMESTAMP, ?)"
    )

    res_a = await _run_select(sql_a, (-a * 3600,))
    res_b = await _run_select(sql_b, (-(a + b) * 3600, -a * 3600))
    if "error" in res_a:
        return res_a
    if "error" in res_b:
        return res_b

    val_a = _scalar(res_a) or 0
    val_b = _scalar(res_b) or 0
    delta_abs = (val_a - val_b)
    delta_pct = (delta_abs / val_b * 100.0) if val_b else None

    return {
        "metric": metric,
        "window_a": {"hours": a, "value": val_a},
        "window_b": {"hours": b, "value": val_b, "ends_h_ago": a},
        "delta_abs": delta_abs,
        "delta_pct": delta_pct,
        "_render": "scalar",
        "_mock": res_a.get("_mock", False),
    }


async def time_series(
    metric: str = "anomaly_count",
    hours: int = 24,
    bucket_minutes: int = 60,
) -> dict[str, Any]:
    """Bucketed time series of ``metric`` over the last ``hours``.

    Returned shape is ``{rows: [{bucket, metric_value}], ...}`` — the
    Streamlit page picks ``st.line_chart`` based on ``_render``.
    """
    try:
        m_spec = _validate_metric(metric)
        hours_n = _validate_hours(hours)
        bucket_n = _validate_bucket(bucket_minutes)
    except HelperValidationError as exc:
        return _bad_args(exc)

    # Bucket via second-floor arithmetic — portable across HANA installs
    # that lack SERIES_ROUND. bucket_n is whitelisted so the f-string
    # is safe.
    bucket_secs = bucket_n * 60
    bucket_expr = (
        f"ADD_SECONDS(TO_TIMESTAMP('1970-01-01 00:00:00'), "
        f"FLOOR(SECONDS_BETWEEN(TO_TIMESTAMP('1970-01-01 00:00:00'), "
        f"{m_spec['time_col']}) / {bucket_secs}) * {bucket_secs})"
    )
    sql = (
        f"SELECT {bucket_expr} AS bucket, "
        f"  {m_spec['expr']} AS metric_value "
        f"FROM {m_spec['table']} "
        f"WHERE {m_spec['time_col']} > ADD_SECONDS(CURRENT_TIMESTAMP, ?) "
        f"GROUP BY {bucket_expr} "
        f"ORDER BY 1"
    )
    payload = await _run_select(sql, (-hours_n * 3600,))
    payload.update(
        metric=metric, hours=hours_n, bucket_minutes=bucket_n,
        _render="line_chart",
    )
    return payload


async def correlate(
    dim_a: str = "source_ip",
    dim_b: str = "log_type",
    hours: int = 24,
    top_n: int = 20,
) -> dict[str, Any]:
    """Co-occurrence matrix for two SECURITY_LOGS dimensions.

    Both dimensions must live on SECURITY_LOGS — correlate is a
    *log-side* operation. Returns the top ``top_n`` (a, b) pairs ranked
    by count.
    """
    try:
        a_spec = _validate_dimension(dim_a, _LOG_TABLE)
        b_spec = _validate_dimension(dim_b, _LOG_TABLE)
        hours_n = _validate_hours(hours)
        top_n_n = _validate_top_n(top_n)
    except HelperValidationError as exc:
        return _bad_args(exc)

    if a_spec["column"] == b_spec["column"]:
        return _bad_args(
            HelperValidationError(f"correlate: dim_a and dim_b must differ ({dim_a}=={dim_b})")
        )

    sql = (
        f"SELECT {a_spec['column']} AS a, {b_spec['column']} AS b, "
        f"COUNT(*) AS n "
        f"FROM {_LOG_TABLE} "
        f"WHERE {_LOG_TIME_COL} > ADD_SECONDS(CURRENT_TIMESTAMP, ?) "
        f"GROUP BY {a_spec['column']}, {b_spec['column']} "
        f"ORDER BY n DESC "
        f"LIMIT {top_n_n}"
    )
    payload = await _run_select(sql, (-hours_n * 3600,))
    payload.update(
        dim_a=dim_a, dim_b=dim_b, hours=hours_n,
        _render="table",
    )
    return payload


# ─── Validation ────────────────────────────────────────────────────────────


def _validate_metric(metric: str) -> dict[str, str]:
    spec = _METRIC_SPEC.get(metric)
    if spec is None:
        raise HelperValidationError(
            f"unknown metric '{metric}'. Allowed: {sorted(_METRIC_SPEC)}"
        )
    return spec


def _validate_dimension(dimension: str, metric_table: str) -> dict[str, str]:
    spec = _DIMENSION_SPEC.get(dimension)
    if spec is None:
        raise HelperValidationError(
            f"unknown dimension '{dimension}'. Allowed: {sorted(_DIMENSION_SPEC)}"
        )
    if spec["table"] != "BOTH" and spec["table"] != metric_table:
        raise HelperValidationError(
            f"dimension '{dimension}' lives on {spec['table']} but the metric "
            f"is on {metric_table}. Pick a compatible dimension."
        )
    return spec


def _validate_hours(hours: int) -> int:
    try:
        h = int(hours)
    except (TypeError, ValueError) as exc:
        raise HelperValidationError(f"hours must be an int, got {hours!r}") from exc
    if not 1 <= h <= 720:
        raise HelperValidationError(f"hours must be in [1, 720], got {h}")
    return h


def _validate_top_n(top_n: int) -> int:
    try:
        n = int(top_n)
    except (TypeError, ValueError) as exc:
        raise HelperValidationError(f"top_n must be an int, got {top_n!r}") from exc
    if not 1 <= n <= 50:
        raise HelperValidationError(f"top_n must be in [1, 50], got {n}")
    return n


def _validate_bucket(bucket_minutes: int) -> int:
    try:
        b = int(bucket_minutes)
    except (TypeError, ValueError) as exc:
        raise HelperValidationError(
            f"bucket_minutes must be an int, got {bucket_minutes!r}"
        ) from exc
    if b not in _VALID_BUCKETS:
        raise HelperValidationError(
            f"bucket_minutes must be one of {sorted(_VALID_BUCKETS)}, got {b}"
        )
    return b


# ─── SQL execution ─────────────────────────────────────────────────────────


async def _run_select(sql: str, params: tuple) -> dict[str, Any]:
    """Run a SELECT and return ``{rows, columns, row_count, elapsed_ms}``.

    Mock mode returns an empty payload with ``_mock=True``; the schema is
    the same so callers don't need to special-case it. HANA errors come
    back as ``{"error": ...}`` — helpers don't trip the circuit breaker
    (only ``run_custom_query`` does), so we keep the message terse.
    """
    if settings.mock_hana:
        return {
            "rows": [], "columns": [], "row_count": 0,
            "elapsed_ms": 0, "_mock": True,
        }

    started = time.monotonic()
    try:
        async with pool.acquire() as conn:
            if conn is None:
                return {"error": "hana_unavailable"}
            return await asyncio.to_thread(_execute_sync, conn, sql, params, started)
    except Exception as exc:
        logger.exception("agent.helpers.execute_failed", extra={"sql": sql})
        return {"error": f"{type(exc).__name__}: {exc}"[:400]}


def _execute_sync(
    conn: Any, sql: str, params: tuple, started: float
) -> dict[str, Any]:
    cursor = conn.cursor()
    try:
        cursor.execute(sql, params)
        cols = [d[0].lower() for d in (cursor.description or [])]
        raw = cursor.fetchall()
        rows = [dict(zip(cols, r, strict=False)) for r in raw]
        return {
            "rows": rows,
            "columns": cols,
            "row_count": len(rows),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    finally:
        cursor.close()


# ─── Internal utilities ────────────────────────────────────────────────────


def _bad_args(exc: HelperValidationError) -> dict[str, Any]:
    return {"error": f"validation: {exc}", "_render": "raw"}


def _scalar(payload: dict[str, Any]) -> Any:
    """Pull the single scalar out of a one-row, one-column SELECT result."""
    rows = payload.get("rows") or []
    if not rows:
        return None
    first = rows[0]
    if not isinstance(first, dict) or not first:
        return None
    return next(iter(first.values()))
