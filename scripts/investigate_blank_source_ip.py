"""
investigate_blank_source_ip.py
-------------------------------
One-off forensic query for the 247,816 rows where SOURCE_IP = '' (empty string).
Answers four questions:
  1. Time distribution — date range and daily burst pattern
  2. Endpoint targeting — top 5 PORT_SERVICE + top EVENT_DESCRIPTION prefixes
     (REQUEST_PATH is NULL for all pre-expansion rows, so these are the proxies)
  3. STATUS diversity — unique STATUS values and counts
  4. Status comparison — STATUS breakdown for blank-IP vs non-blank-IP rows

Run:
    python scripts/investigate_blank_source_ip.py
"""

from __future__ import annotations

import sys
from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: script requires a live HANA connection (HANA_HOST not set).")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

W = 72
BLANK_FILTER = "SOURCE_IP = ''"


def q(cur, sql: str):
    cur.execute(sql)
    return cur.fetchall()


def section(title: str) -> None:
    print()
    print("─" * W)
    print(f"  {title}")
    print("─" * W)


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

    print()
    print("═" * W)
    print("  BLANK SOURCE_IP FORENSIC INVESTIGATION")
    print("═" * W)

    # ── 1. Time distribution ──────────────────────────────────────────────────
    section("1. TIME DISTRIBUTION")

    row = q(cur, f"""
        SELECT
            COUNT(*),
            MIN(DATETIME),
            MAX(DATETIME),
            MIN(INGESTED_AT),
            MAX(INGESTED_AT)
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
    """)[0]
    total_blank, dt_min, dt_max, ing_min, ing_max = row
    print(f"  Total blank-IP rows   : {total_blank:,}")
    print(f"  Earliest DATETIME     : {dt_min}")
    print(f"  Latest   DATETIME     : {dt_max}")
    print(f"  Earliest INGESTED_AT  : {ing_min}")
    print(f"  Latest   INGESTED_AT  : {ing_max}")

    daily = q(cur, f"""
        SELECT
            TO_VARCHAR(DATETIME, 'YYYY-MM-DD') AS day,
            COUNT(*) AS cnt
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
        GROUP BY TO_VARCHAR(DATETIME, 'YYYY-MM-DD')
        ORDER BY day
    """)
    print()
    print(f"  {'Date':<14}  {'Rows':>10}")
    print("  " + "-" * 28)
    for day, cnt in daily:
        bar = "█" * min(40, cnt // max(1, total_blank // 40))
        print(f"  {day:<14}  {cnt:>10,}  {bar}")

    hourly_spread = q(cur, f"""
        SELECT
            TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24') AS hour_bucket,
            COUNT(*) AS cnt
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
        GROUP BY TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24')
        ORDER BY cnt DESC
        LIMIT 5
    """)
    print()
    print("  Top 5 busiest hours:")
    print(f"  {'Hour (UTC)':<20}  {'Rows':>10}")
    print("  " + "-" * 34)
    for hr, cnt in hourly_spread:
        print(f"  {hr:<20}  {cnt:>10,}")

    # ── 2. Endpoint / service targeting ──────────────────────────────────────
    section("2. ENDPOINT / SERVICE TARGETING")
    print("  NOTE: REQUEST_PATH is NULL for all pre-expansion rows.")
    print("  Using PORT_SERVICE and LOG_TYPE as proxies.")

    port_dist = q(cur, f"""
        SELECT TOP 5
            COALESCE(PORT_SERVICE, '<NULL>') AS svc,
            COUNT(*) AS cnt
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
        GROUP BY PORT_SERVICE
        ORDER BY COUNT(*) DESC
    """)
    print()
    print("  Top 5 PORT_SERVICE values:")
    print(f"  {'PORT_SERVICE':<40}  {'Rows':>10}")
    print("  " + "-" * 54)
    for svc, cnt in port_dist:
        print(f"  {svc:<40}  {cnt:>10,}")

    log_type_dist = q(cur, f"""
        SELECT
            COALESCE(LOG_TYPE, '<NULL>') AS lt,
            COUNT(*) AS cnt
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
        GROUP BY LOG_TYPE
        ORDER BY COUNT(*) DESC
    """)
    print()
    print("  LOG_TYPE breakdown (blank-IP rows):")
    print(f"  {'LOG_TYPE':<30}  {'Rows':>10}")
    print("  " + "-" * 44)
    for lt, cnt in log_type_dist:
        print(f"  {lt:<30}  {cnt:>10,}")

    # ── 3. STATUS / "User-Agent proxy" diversity ──────────────────────────────
    section("3. STATUS DIVERSITY  (no User-Agent column in schema)")
    print("  Showing all distinct STATUS values for blank-IP rows.")
    print("  High cardinality → normal mix; single value → pipeline artefact.")

    status_uniq = q(cur, f"""
        SELECT
            COALESCE(STATUS, '<NULL>') AS s,
            COUNT(*) AS cnt
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
        GROUP BY STATUS
        ORDER BY COUNT(*) DESC
    """)
    uniq_count = len(status_uniq)
    print(f"  Unique STATUS values: {uniq_count}")
    print()
    print(f"  {'STATUS':<40}  {'Rows':>10}")
    print("  " + "-" * 54)
    for s, cnt in status_uniq:
        print(f"  {s:<40}  {cnt:>10,}")

    # ── 4. STATUS comparison: blank-IP vs rest ────────────────────────────────
    section("4. STATUS COMPARISON — blank-IP vs non-blank-IP")

    status_all = q(cur, """
        SELECT
            COALESCE(STATUS, '<NULL>') AS s,
            SUM(CASE WHEN SOURCE_IP = '' THEN 1 ELSE 0 END) AS blank_cnt,
            SUM(CASE WHEN SOURCE_IP != '' THEN 1 ELSE 0 END) AS other_cnt
        FROM SECURITY_LOGS
        GROUP BY STATUS
        ORDER BY blank_cnt DESC
    """)

    total_other = q(cur, f"SELECT COUNT(*) FROM SECURITY_LOGS WHERE SOURCE_IP != ''")[0][0]

    print(f"  Total non-blank-IP rows: {total_other:,}")
    print(f"  Total blank-IP rows    : {total_blank:,}")
    print()
    print(f"  {'STATUS':<35}  {'blank %':>8}  {'other %':>8}")
    print("  " + "-" * 56)
    for s, b_cnt, o_cnt in status_all:
        b_pct = b_cnt / total_blank * 100 if total_blank else 0
        o_pct = o_cnt / total_other * 100 if total_other else 0
        print(f"  {s:<35}  {b_pct:>7.1f}%  {o_pct:>7.1f}%")

    # ── 5. EVENT_DESCRIPTION sample ───────────────────────────────────────────
    section("5. EVENT_DESCRIPTION SAMPLE (10 random blank-IP rows)")
    print("  Checking for structured content that might indicate attack signatures.")

    samples = q(cur, f"""
        SELECT TOP 10
            TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24:MI') AS ts,
            LOG_TYPE,
            COALESCE(PORT_SERVICE, '<NULL>') AS svc,
            COALESCE(STATUS, '<NULL>') AS status,
            LEFT(COALESCE(EVENT_DESCRIPTION, '<NULL>'), 80) AS desc_preview
        FROM SECURITY_LOGS
        WHERE {BLANK_FILTER}
        ORDER BY RAND()
    """)
    print()
    for ts, lt, svc, st, desc in samples:
        print(f"  [{ts}] {lt} | {svc} | {st}")
        print(f"    {desc}")

    print()
    print("═" * W)
    print("  Investigation complete.")
    print("═" * W)
    print()

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
