"""
audit_llm_telemetry.py
----------------------
Audit-only diagnostic for the LLM telemetry columns in SECURITY_LOGS.

Goal: ground the design of an LLM-specific anomaly detector in measured
distributions instead of guessed thresholds. This script makes NO changes
to data or schema. It prints a report and writes it to
data/reports/llm_audit_<YYYY-MM-DD>.md.

Questions answered:
  1. How many LLM rows do we have, and what fraction of total traffic?
  2. Distribution (min/p50/p95/p99/max + mean/stddev) of:
        LLM_PROMPT_TOKENS, LLM_TOTAL_TOKENS, LLM_COST_USD,
        LLM_RESPONSE_TIME_MS
  3. Per-(MODEL_ID, PROMPT_CATEGORY) row counts — viability of per-group models.
  4. Distinct values of LLM_FINISH_REASON and LLM_STATUS, with counts.
  5. LLM_ERROR / LLM_TIMEOUT volume per category per hour — baseline for
     "spike" detection rules.
  6. NULL rates on each LLM column *within LLM rows only* — pre-expansion
     rows already accounted for in schema_audit; this measures real
     missing-data within in-scope rows.

Usage:
    python scripts/audit_llm_telemetry.py
"""

from __future__ import annotations

import sys
from datetime import date

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST is not set — cannot audit mock mode.")
    print("Set HANA_HOST, HANA_USER, HANA_PASSWORD, HANA_DATABASE in your .env first.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

W = 72

# Rows are LLM-related when LOG_TYPE starts with 'LLM_'. This catches
# LLM_REQUEST, LLM_ERROR, LLM_TIMEOUT, and any future LLM_* without a code change.
LLM_PREDICATE = "LOG_TYPE LIKE 'LLM\\_%' ESCAPE '\\'"

LLM_COLUMNS = [
    "LLM_MODEL_ID",
    "LLM_PROMPT_CATEGORY",
    "LLM_STATUS",
    "LLM_FINISH_REASON",
    "LLM_PROMPT_TOKENS",
    "LLM_TOTAL_TOKENS",
    "LLM_COST_USD",
    "LLM_RESPONSE_TIME_MS",
    "LLM_ERROR_MESSAGE",
]

NUMERIC_COLUMNS = [
    "LLM_PROMPT_TOKENS",
    "LLM_TOTAL_TOKENS",
    "LLM_COST_USD",
    "LLM_RESPONSE_TIME_MS",
]


def hr(char: str = "─") -> str:
    return char * W


def q(cursor, sql: str):
    cursor.execute(sql)
    return cursor.fetchall()


def pct(numerator: int, denominator: int) -> float:
    return (numerator / denominator * 100) if denominator else 0.0


def collect_report(cur) -> dict:
    total = q(cur, "SELECT COUNT(*) FROM SECURITY_LOGS")[0][0]
    llm_total = q(cur, f"SELECT COUNT(*) FROM SECURITY_LOGS WHERE {LLM_PREDICATE}")[0][0]

    # Breakdown by LOG_TYPE inside the LLM_* family.
    llm_by_type = q(
        cur,
        f"""
        SELECT LOG_TYPE, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LOG_TYPE
        ORDER BY COUNT(*) DESC
        """,
    )

    # Numeric distributions. HANA quirk: PERCENTILE_CONT is a window function,
    # not a plain aggregate, so it needs OVER () and we pull a single row.
    distributions: list[tuple[str, dict]] = []
    for col in NUMERIC_COLUMNS:
        agg = q(
            cur,
            f"""
            SELECT
                COUNT({col})              AS N,
                MIN({col})                AS MIN_V,
                MAX({col})                AS MAX_V,
                AVG(TO_DOUBLE({col}))     AS MEAN_V,
                STDDEV(TO_DOUBLE({col}))  AS STD_V
            FROM SECURITY_LOGS
            WHERE {LLM_PREDICATE}
            """,
        )[0]
        pct_row = q(
            cur,
            f"""
            SELECT TOP 1
                PERCENTILE_CONT(0.50)  WITHIN GROUP (ORDER BY {col}) OVER () AS P50,
                PERCENTILE_CONT(0.95)  WITHIN GROUP (ORDER BY {col}) OVER () AS P95,
                PERCENTILE_CONT(0.99)  WITHIN GROUP (ORDER BY {col}) OVER () AS P99,
                PERCENTILE_CONT(0.995) WITHIN GROUP (ORDER BY {col}) OVER () AS P995
            FROM SECURITY_LOGS
            WHERE {LLM_PREDICATE} AND {col} IS NOT NULL
            """,
        )
        p50 = p95 = p99 = p995 = None
        if pct_row:
            p50, p95, p99, p995 = pct_row[0]
        distributions.append((col, {
            "n": agg[0], "min": agg[1], "max": agg[2], "mean": agg[3], "std": agg[4],
            "p50": p50, "p95": p95, "p99": p99, "p995": p995,
        }))

    # NULL counts within LLM rows only.
    nulls_within_llm = []
    for col in LLM_COLUMNS:
        n = q(
            cur,
            f"SELECT COUNT(*) FROM SECURITY_LOGS WHERE {LLM_PREDICATE} AND {col} IS NULL",
        )[0][0]
        nulls_within_llm.append((col, n, pct(n, llm_total)))

    # Per-(MODEL_ID, PROMPT_CATEGORY) cohort sizes — top 25 by count.
    cohorts = q(
        cur,
        f"""
        SELECT TOP 25
            COALESCE(LLM_MODEL_ID, '<null>')        AS MODEL,
            COALESCE(LLM_PROMPT_CATEGORY, '<null>') AS CATEGORY,
            COUNT(*)                                AS CNT
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY
        ORDER BY COUNT(*) DESC
        """,
    )
    cohort_total_groups = q(
        cur,
        f"""
        SELECT COUNT(*) FROM (
            SELECT LLM_MODEL_ID, LLM_PROMPT_CATEGORY
            FROM SECURITY_LOGS
            WHERE {LLM_PREDICATE}
            GROUP BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY
        )
        """,
    )[0][0]
    cohorts_under_500 = q(
        cur,
        f"""
        SELECT COUNT(*) FROM (
            SELECT LLM_MODEL_ID, LLM_PROMPT_CATEGORY, COUNT(*) AS CNT
            FROM SECURITY_LOGS
            WHERE {LLM_PREDICATE}
            GROUP BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY
            HAVING COUNT(*) < 500
        )
        """,
    )[0][0]

    # Categorical distinct value counts.
    finish_reasons = q(
        cur,
        f"""
        SELECT COALESCE(LLM_FINISH_REASON, '<null>') AS V, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LLM_FINISH_REASON
        ORDER BY COUNT(*) DESC
        """,
    )
    statuses = q(
        cur,
        f"""
        SELECT COALESCE(LLM_STATUS, '<null>') AS V, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LLM_STATUS
        ORDER BY COUNT(*) DESC
        """,
    )
    models = q(
        cur,
        f"""
        SELECT COALESCE(LLM_MODEL_ID, '<null>') AS V, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LLM_MODEL_ID
        ORDER BY COUNT(*) DESC
        """,
    )
    categories = q(
        cur,
        f"""
        SELECT COALESCE(LLM_PROMPT_CATEGORY, '<null>') AS V, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LLM_PROMPT_CATEGORY
        ORDER BY COUNT(*) DESC
        """,
    )

    # Error / timeout rate per category per hour.
    # We measure "errors per hour" as: error_rows / distinct_hours_seen.
    # Distinct hours is taken across the whole LLM dataset — gives a stable
    # denominator even for low-volume categories.
    distinct_hours = q(
        cur,
        f"""
        SELECT COUNT(DISTINCT TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24'))
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        """,
    )[0][0] or 1

    error_rates = q(
        cur,
        f"""
        SELECT TOP 25
            COALESCE(LLM_PROMPT_CATEGORY, '<null>')                         AS CATEGORY,
            SUM(CASE WHEN LOG_TYPE = 'LLM_ERROR'   THEN 1 ELSE 0 END)       AS ERRORS,
            SUM(CASE WHEN LOG_TYPE = 'LLM_TIMEOUT' THEN 1 ELSE 0 END)       AS TIMEOUTS,
            COUNT(*)                                                        AS TOTAL
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE}
        GROUP BY LLM_PROMPT_CATEGORY
        ORDER BY COUNT(*) DESC
        """,
    )

    # Per-cohort percentiles needed by the LLM_EXFIL_SHAPE rule and by the
    # cohort-profile JSON the trainer will emit. Limited to cohorts with
    # >= 200 rows so percentiles are statistically meaningful. Restricted to
    # rows with the LLM payload populated (LLM_MODEL_ID IS NOT NULL).
    cohort_percentiles = q(
        cur,
        f"""
        SELECT DISTINCT
            LLM_MODEL_ID                                                                      AS MODEL,
            LLM_PROMPT_CATEGORY                                                               AS CATEGORY,
            COUNT(*)                       OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS N,
            PERCENTILE_CONT(0.10)  WITHIN GROUP (ORDER BY LLM_PROMPT_TOKENS)
                                           OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS PT_P10,
            PERCENTILE_CONT(0.50)  WITHIN GROUP (ORDER BY LLM_PROMPT_TOKENS)
                                           OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS PT_P50,
            PERCENTILE_CONT(0.99)  WITHIN GROUP (ORDER BY LLM_PROMPT_TOKENS)
                                           OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS PT_P99,
            PERCENTILE_CONT(0.99)  WITHIN GROUP (ORDER BY LLM_TOTAL_TOKENS)
                                           OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS TT_P99,
            PERCENTILE_CONT(0.99)  WITHIN GROUP (ORDER BY LLM_COST_USD)
                                           OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS COST_P99,
            PERCENTILE_CONT(0.99)  WITHIN GROUP (ORDER BY LLM_RESPONSE_TIME_MS)
                                           OVER (PARTITION BY LLM_MODEL_ID, LLM_PROMPT_CATEGORY) AS RT_P99
        FROM SECURITY_LOGS
        WHERE {LLM_PREDICATE} AND LLM_MODEL_ID IS NOT NULL
        ORDER BY MODEL, CATEGORY
        """,
    )
    # Filter to cohorts with at least 200 rows for the report (full set goes
    # to the trainer at fit time — this is just for the markdown).
    cohort_percentiles_meaningful = [r for r in cohort_percentiles if (r[2] or 0) >= 200]

    return {
        "total": total,
        "llm_total": llm_total,
        "pct_llm": pct(llm_total, total),
        "llm_by_type": llm_by_type,
        "distributions": distributions,
        "nulls_within_llm": nulls_within_llm,
        "cohorts": cohorts,
        "cohort_total_groups": cohort_total_groups,
        "cohorts_under_500": cohorts_under_500,
        "finish_reasons": finish_reasons,
        "statuses": statuses,
        "models": models,
        "categories": categories,
        "distinct_hours": distinct_hours,
        "error_rates": error_rates,
        "cohort_percentiles": cohort_percentiles_meaningful,
        "cohort_percentiles_total": len(cohort_percentiles),
    }


def fmt(v):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:,.4f}" if abs(v) < 10 else f"{v:,.2f}"
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def render_report(r: dict) -> str:
    lines: list[str] = []
    lines.append(f"# LLM Telemetry Audit — {date.today().isoformat()}")
    lines.append("")
    lines.append(
        f"**Headline:** {r['llm_total']:,} of {r['total']:,} rows "
        f"({r['pct_llm']:.1f}%) are LLM-typed. "
        f"Distinct (MODEL_ID, PROMPT_CATEGORY) groups: "
        f"{r['cohort_total_groups']:,} — of which {r['cohorts_under_500']:,} "
        f"have fewer than 500 rows (too small for per-group Isolation Forest)."
    )
    lines.append("")

    lines.append("## LLM rows by LOG_TYPE")
    lines.append("")
    lines.append("| LOG_TYPE | Rows | % of LLM |")
    lines.append("|---|---:|---:|")
    for lt, cnt in r["llm_by_type"]:
        lines.append(f"| `{lt}` | {cnt:,} | {pct(cnt, r['llm_total']):.1f}% |")
    lines.append("")

    lines.append("## Numeric distributions (LLM rows only)")
    lines.append("")
    lines.append("| Column | N | Min | p50 | p95 | p99 | p99.5 | Max | Mean | Stddev |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for col, d in r["distributions"]:
        lines.append(
            f"| `{col}` | {fmt(d['n'])} | {fmt(d['min'])} | {fmt(d['p50'])} | "
            f"{fmt(d['p95'])} | {fmt(d['p99'])} | {fmt(d['p995'])} | "
            f"{fmt(d['max'])} | {fmt(d['mean'])} | {fmt(d['std'])} |"
        )
    lines.append("")
    lines.append(
        "*Use p99.5 (or p99) of `LLM_PROMPT_TOKENS` as the data-driven floor "
        "for the 'token bomb' rule rather than the spec's suggested 50,000.*"
    )
    lines.append("")

    lines.append("## NULL rates *within* LLM rows")
    lines.append("")
    lines.append("| Column | NULLs | % of LLM rows |")
    lines.append("|---|---:|---:|")
    for col, n, p in r["nulls_within_llm"]:
        lines.append(f"| `{col}` | {n:,} | {p:.1f}% |")
    lines.append("")
    lines.append(
        "*High NULL % here (unlike in the schema-expansion audit) is a real "
        "missing-data signal — these rows ARE LLM rows, so the field should "
        "have been populated.*"
    )
    lines.append("")

    lines.append("## Top 25 (MODEL_ID, PROMPT_CATEGORY) cohorts")
    lines.append("")
    lines.append("| Model | Category | Rows |")
    lines.append("|---|---|---:|")
    for model, cat, cnt in r["cohorts"]:
        lines.append(f"| `{model}` | `{cat}` | {cnt:,} |")
    lines.append("")

    lines.append("## Distinct LLM_MODEL_ID")
    lines.append("")
    lines.append("| Value | Rows |")
    lines.append("|---|---:|")
    for v, c in r["models"]:
        lines.append(f"| `{v}` | {c:,} |")
    lines.append("")

    lines.append("## Distinct LLM_PROMPT_CATEGORY")
    lines.append("")
    lines.append("| Value | Rows |")
    lines.append("|---|---:|")
    for v, c in r["categories"]:
        lines.append(f"| `{v}` | {c:,} |")
    lines.append("")

    lines.append("## Distinct LLM_FINISH_REASON")
    lines.append("")
    lines.append("| Value | Rows |")
    lines.append("|---|---:|")
    for v, c in r["finish_reasons"]:
        lines.append(f"| `{v}` | {c:,} |")
    lines.append("")
    lines.append(
        "*Plan calls out `content_filter` as a prompt-injection signal — confirm "
        "whether that exact string appears above before keying the rule on it.*"
    )
    lines.append("")

    lines.append("## Distinct LLM_STATUS")
    lines.append("")
    lines.append("| Value | Rows |")
    lines.append("|---|---:|")
    for v, c in r["statuses"]:
        lines.append(f"| `{v}` | {c:,} |")
    lines.append("")

    lines.append(
        f"## Error / timeout rates by category "
        f"(across {r['distinct_hours']:,} distinct hours seen)"
    )
    lines.append("")
    lines.append("| Category | Errors | Timeouts | Total | Errors/hr | Timeouts/hr |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for cat, errs, tos, tot in r["error_rates"]:
        eph = (errs or 0) / r["distinct_hours"]
        tph = (tos or 0) / r["distinct_hours"]
        lines.append(
            f"| `{cat}` | {errs or 0:,} | {tos or 0:,} | {tot:,} | "
            f"{eph:,.2f} | {tph:,.2f} |"
        )
    lines.append("")
    lines.append(
        "*Use these per-category baselines to set 'spike' thresholds. "
        "A '10x baseline' rule only makes sense when the baseline itself "
        "is non-trivial (>= ~1/hr).*"
    )
    lines.append("")

    lines.append(
        f"## Per-cohort percentiles (top 30 of {r['cohort_percentiles_total']:,} cohorts, N >= 200)"
    )
    lines.append("")
    lines.append(
        "Used by the trainer to build the cohort-profile artifact and to "
        "set the `LLM_EXFIL_SHAPE` rule's per-cohort `prompt_tokens < p10 "
        "AND total_tokens > p99` thresholds. Showing top 30 by cohort size; "
        "full table is computed at fit time."
    )
    lines.append("")
    lines.append(
        "| Model | Category | N | PT p10 | PT p50 | PT p99 | TT p99 | Cost p99 | RT p99 |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    sorted_cohorts = sorted(r["cohort_percentiles"], key=lambda x: -(x[2] or 0))[:30]
    for model, cat, n, pt_p10, pt_p50, pt_p99, tt_p99, cost_p99, rt_p99 in sorted_cohorts:
        lines.append(
            f"| `{model}` | `{cat}` | {fmt(n)} | {fmt(pt_p10)} | {fmt(pt_p50)} | "
            f"{fmt(pt_p99)} | {fmt(tt_p99)} | {fmt(cost_p99)} | {fmt(rt_p99)} |"
        )
    lines.append("")

    return "\n".join(lines)


def print_summary(r: dict) -> None:
    print()
    print("═" * W)
    print("  SAP THREAT DETECTOR — LLM TELEMETRY AUDIT")
    print("═" * W)
    print()
    print(f"  Total rows                    : {r['total']:,}")
    print(f"  LLM rows                      : {r['llm_total']:,} ({r['pct_llm']:.1f}%)")
    print(f"  Distinct (model, category)    : {r['cohort_total_groups']:,}")
    print(f"    of which < 500 rows         : {r['cohorts_under_500']:,}")
    print(f"  Distinct hours of LLM data    : {r['distinct_hours']:,}")
    print()
    print("  Numeric distributions (p50 / p99 / max):")
    for col, d in r["distributions"]:
        print(
            f"    {col:<24} p50={fmt(d['p50']):>10}  "
            f"p99={fmt(d['p99']):>10}  max={fmt(d['max']):>10}"
        )
    print()


def main() -> None:
    print("Connecting to HANA...")
    conn = dbapi.connect(
        address=settings.hana_host,
        port=settings.hana_port,
        user=settings.hana_user,
        password=settings.hana_password,
        databaseName=settings.hana_database,
    )
    cur = conn.cursor()
    try:
        report = collect_report(cur)
    finally:
        cur.close()
        conn.close()

    print_summary(report)

    out_dir = settings.project_root / "data" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"llm_audit_{date.today().isoformat()}.md"
    out_path.write_text(render_report(report))
    print(f"  Written: {out_path}")
    print()


if __name__ == "__main__":
    main()
