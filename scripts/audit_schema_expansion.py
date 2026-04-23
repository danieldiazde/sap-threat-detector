"""
audit_schema_expansion.py
-------------------------
Audit-only diagnostic for the SECURITY_LOGS schema expansion (commit 5b5d777).

Goal: measure how much of the current HANA data predates the 16-column
expansion so we can pick among drop / impute / legacy-model strategies.
This script makes NO changes to data or schema. It prints a report and
writes it to data/reports/schema_audit_<YYYY-MM-DD>.md.

Usage:
    python scripts/audit_schema_expansion.py
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

EXPANSION_COLUMNS = [
    "REQUEST_PATH",
    "SAP_APPLICATION",
    "REGION_CODE",
    "MACRO_REGION",
    "HTTP_METHOD",
    "SAP_SOURCE_TYPE",
    "SAP_APP_ENV",
    "LLM_TOTAL_TOKENS",
    "LLM_COST_USD",
    "LLM_FINISH_REASON",
    "LLM_STATUS",
    "LLM_RESPONSE_TIME_MS",
    "LLM_PROMPT_CATEGORY",
    "LLM_ERROR_MESSAGE",
    "LLM_MODEL_ID",
    "LLM_PROMPT_TOKENS",
]

# LLM_* columns are NULL by design for non-LLM traffic, so a high null % on
# these is not a data-quality signal. Mark them explicitly in the report.
LLM_COLUMNS = {
    "LLM_TOTAL_TOKENS",
    "LLM_COST_USD",
    "LLM_FINISH_REASON",
    "LLM_STATUS",
    "LLM_RESPONSE_TIME_MS",
    "LLM_PROMPT_CATEGORY",
    "LLM_ERROR_MESSAGE",
    "LLM_MODEL_ID",
    "LLM_PROMPT_TOKENS",
}

# If these three are all NULL, the row almost certainly predates the expansion
# (they are always populated by the current parser for any log type).
PRE_EXPANSION_PREDICATE = "HTTP_METHOD IS NULL AND REGION_CODE IS NULL AND SAP_APPLICATION IS NULL"


def hr(char: str = "─") -> str:
    return char * W


def q(cursor, sql: str):
    cursor.execute(sql)
    return cursor.fetchall()


def pct(numerator: int, denominator: int) -> float:
    return (numerator / denominator * 100) if denominator else 0.0


def collect_report(cur) -> dict:
    total = q(cur, "SELECT COUNT(*) FROM SECURITY_LOGS")[0][0]
    pre = q(
        cur,
        f"SELECT COUNT(*) FROM SECURITY_LOGS WHERE {PRE_EXPANSION_PREDICATE}",
    )[0][0]

    boundary = q(
        cur,
        """
        SELECT MIN(INGESTED_AT), MAX(INGESTED_AT)
        FROM SECURITY_LOGS
        WHERE HTTP_METHOD IS NOT NULL
          AND REGION_CODE IS NOT NULL
          AND SAP_APPLICATION IS NOT NULL
        """,
    )[0]

    per_column: list[tuple[str, int, float, bool]] = []
    for col in EXPANSION_COLUMNS:
        nulls = q(cur, f"SELECT COUNT(*) FROM SECURITY_LOGS WHERE {col} IS NULL")[0][0]
        per_column.append((col, nulls, pct(nulls, total), col in LLM_COLUMNS))

    log_type_dist = q(
        cur,
        f"""
        SELECT LOG_TYPE, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {PRE_EXPANSION_PREDICATE}
        GROUP BY LOG_TYPE
        ORDER BY COUNT(*) DESC
        """,
    )

    top_ips = q(
        cur,
        f"""
        SELECT TOP 10 SOURCE_IP, COUNT(*) AS CNT
        FROM SECURITY_LOGS
        WHERE {PRE_EXPANSION_PREDICATE}
        GROUP BY SOURCE_IP
        ORDER BY COUNT(*) DESC
        """,
    )

    return {
        "total": total,
        "pre_expansion": pre,
        "pct_pre_expansion": pct(pre, total),
        "boundary_min": boundary[0],
        "boundary_max": boundary[1],
        "per_column": per_column,
        "log_type_dist": log_type_dist,
        "top_ips": top_ips,
    }


def render_report(r: dict) -> str:
    lines: list[str] = []
    lines.append(f"# Schema Expansion Audit — {date.today().isoformat()}")
    lines.append("")
    lines.append(
        f"Headline: **{r['pre_expansion']:,} of {r['total']:,} rows "
        f"({r['pct_pre_expansion']:.1f}%) appear to predate commit 5b5d777**."
    )
    lines.append("")
    lines.append(
        "A row is classified as pre-expansion when `HTTP_METHOD`, "
        "`REGION_CODE`, and `SAP_APPLICATION` are all NULL. This is a heuristic: "
        "post-expansion rows can still be NULL on individual columns, but all "
        "three simultaneously is a strong pre-expansion signal."
    )
    lines.append("")
    lines.append(f"- First row with all three populated: `{r['boundary_min']}`")
    lines.append(f"- Most recent row with all three populated: `{r['boundary_max']}`")
    lines.append("")

    lines.append("## Per-column NULL counts (16 expansion columns)")
    lines.append("")
    lines.append("| Column | NULLs | % NULL | Design-NULL? |")
    lines.append("|---|---:|---:|:---:|")
    for col, nulls, p, is_llm in r["per_column"]:
        flag = "yes (LLM)" if is_llm else "no"
        lines.append(f"| `{col}` | {nulls:,} | {p:.1f}% | {flag} |")
    lines.append("")
    lines.append(
        "*LLM_\\* columns are NULL by design for non-LLM traffic — high NULL "
        "percentages on these rows are not a data-quality signal.*"
    )
    lines.append("")

    lines.append("## Pre-expansion rows by LOG_TYPE")
    lines.append("")
    lines.append("| LOG_TYPE | Rows |")
    lines.append("|---|---:|")
    for lt, cnt in r["log_type_dist"]:
        lines.append(f"| `{lt}` | {cnt:,} |")
    lines.append("")

    lines.append("## Top 10 pre-expansion SOURCE_IPs")
    lines.append("")
    lines.append("| SOURCE_IP | Rows |")
    lines.append("|---|---:|")
    for ip, cnt in r["top_ips"]:
        lines.append(f"| `{ip}` | {cnt:,} |")
    lines.append("")

    lines.append("## Projected impact under three strategies")
    lines.append("")
    pre = r["pre_expansion"]
    total = r["total"]
    post = total - pre
    lines.append("| Strategy | Rows in training | Rows lost | Notes |")
    lines.append("|---|---:|---:|---|")
    lines.append(
        f"| Drop pre-expansion | {post:,} | {pre:,} "
        f"({r['pct_pre_expansion']:.1f}%) | Simplest; loses all historical breadth. |"
    )
    lines.append(f"| Impute (mean/mode) | {total:,} | 0 | No loss; bias risk on the 16 columns. |")
    lines.append(
        f"| Legacy-only model | {pre:,} (legacy) + {post:,} (modern) | 0 | "
        "Two models; routing logic at predict time. |"
    )
    lines.append("")

    lines.append("## Decision rubric (from the plan)")
    lines.append("")
    lines.append("| pct_pre_expansion | Likely choice |")
    lines.append("|---|---|")
    lines.append("| < 10% | Drop pre-expansion rows. |")
    lines.append("| 10-40% | Impute with column-aware defaults; monitor bias on holdout. |")
    lines.append("| > 40% | Legacy-only model + ensemble, or full re-ingest/backfill. |")
    lines.append("")
    lines.append(
        f"Current measurement: **{r['pct_pre_expansion']:.1f}%** → "
        "follow the matching row above."
    )
    lines.append("")
    return "\n".join(lines)


def print_summary(r: dict) -> None:
    print()
    print("═" * W)
    print("  SAP THREAT DETECTOR — SCHEMA EXPANSION AUDIT")
    print("═" * W)
    print()
    print(f"  Total rows in SECURITY_LOGS   : {r['total']:,}")
    print(f"  Likely pre-expansion rows     : {r['pre_expansion']:,}")
    print(f"  Pre-expansion percentage      : {r['pct_pre_expansion']:.1f}%")
    print(f"  Earliest fully-populated row  : {r['boundary_min']}")
    print(f"  Latest fully-populated row    : {r['boundary_max']}")
    print()
    print("  Per-column NULL % (16 expansion columns):")
    print(f"  {'COLUMN':<24}  {'NULLS':>10}  {'% NULL':>8}  design?")
    print("  " + "-" * (W - 4))
    for col, nulls, p, is_llm in r["per_column"]:
        flag = "yes" if is_llm else "no"
        print(f"  {col:<24}  {nulls:>10,}  {p:>7.1f}%  {flag}")
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
    out_path = out_dir / f"schema_audit_{date.today().isoformat()}.md"
    out_path.write_text(render_report(report))
    print(f"  Written: {out_path}")
    print()
    print("═" * W)
    print(
        f"  Decision: {report['pct_pre_expansion']:.1f}% pre-expansion → "
        "see report for strategy."
    )
    print("═" * W)


if __name__ == "__main__":
    main()
