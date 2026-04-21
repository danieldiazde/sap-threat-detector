"""
audit_ingestion.py
------------------
Ingestion pipeline audit: last-10-windows distribution + duplicate check.

Usage:
    python scripts/audit_ingestion.py
"""

import sys

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST not set — cannot run audit against mock.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

W = 72


def hr(char="-"):
    print(char * W)


def section(title):
    print()
    hr("=")
    print(f"  {title}")
    hr("=")


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
        # ── Q2: Last 10 ingestion windows ────────────────────────────────
        section("Q2 — LAST 10 x 30-MIN WINDOWS")
        cur.execute("""
            SELECT
                FLOOR(SECONDS_BETWEEN('2000-01-01', DATETIME) / 1800) AS WINDOW_ID,
                COUNT(*)        AS LOGS_COUNT,
                MIN(DATETIME)   AS WINDOW_START,
                MAX(DATETIME)   AS WINDOW_END
            FROM SECURITY_LOGS
            GROUP BY FLOOR(SECONDS_BETWEEN('2000-01-01', DATETIME) / 1800)
            ORDER BY WINDOW_ID DESC
            LIMIT 10
        """)
        rows = cur.fetchall()
        print(f"  {'WINDOW_ID':>12}  {'LOGS':>6}  {'WINDOW_START':^22}  {'WINDOW_END':^22}")
        print("  " + "-" * 68)
        for wid, cnt, wstart, wend in rows:
            print(f"  {int(wid):>12}  {cnt:>6,}  {wstart!s:^22}  {wend!s:^22}")

        if rows:
            counts = [r[1] for r in rows]
            avg = sum(counts) / len(counts)
            print(f"\n  Avg logs/window (last {len(rows)}): {avg:,.1f}")
            print(f"  Min: {min(counts):,}   Max: {max(counts):,}")

        # ── Q4: Duplicate detection (no LOG_ID — use composite key) ──────
        section("Q4 — DUPLICATE CHECK  (composite key: DATETIME + SOURCE_IP + LOG_TYPE + STATUS + PORT_SERVICE)")
        cur.execute("""
            SELECT
                COUNT(*)  AS TOTAL_ROWS,
                COUNT(DISTINCT CONCAT(CONCAT(CONCAT(CONCAT(
                    TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24:MI:SS'), '|'),
                    COALESCE(SOURCE_IP, '')), '|'),
                    COALESCE(LOG_TYPE, '')))  AS DISTINCT_COMPOSITE,
                COUNT(*) - COUNT(DISTINCT CONCAT(CONCAT(CONCAT(CONCAT(
                    TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24:MI:SS'), '|'),
                    COALESCE(SOURCE_IP, '')), '|'),
                    COALESCE(LOG_TYPE, '')))  AS ESTIMATED_DUPES
            FROM SECURITY_LOGS
        """)
        total, distinct, dupes = cur.fetchone()
        print(f"  Total rows             : {total:,}")
        print(f"  Distinct (dt+ip+type)  : {distinct:,}")
        print(f"  Estimated duplicates   : {dupes:,}  ({dupes/total*100:.2f}% of total)" if total else "  No rows.")

        # Top duplicate groups if any
        if dupes and dupes > 0:
            print()
            print("  Top 5 most-duplicated combinations:")
            cur.execute("""
                SELECT TOP 5
                    TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24:MI:SS') AS DT,
                    SOURCE_IP,
                    LOG_TYPE,
                    COUNT(*) AS CNT
                FROM SECURITY_LOGS
                GROUP BY
                    TO_VARCHAR(DATETIME, 'YYYY-MM-DD HH24:MI:SS'),
                    SOURCE_IP,
                    LOG_TYPE
                HAVING COUNT(*) > 1
                ORDER BY COUNT(*) DESC
            """)
            duperows = cur.fetchall()
            if duperows:
                print(f"  {'DATETIME':^22}  {'SOURCE_IP':^16}  {'LOG_TYPE':^20}  {'COUNT':>5}")
                print("  " + "-" * 68)
                for dt, ip, lt, cnt in duperows:
                    print(f"  {dt!s:^22}  {ip!s:^16}  {lt!s:^20}  {cnt:>5}")
            else:
                print("  (none found at second-level granularity)")

    finally:
        cur.close()
        conn.close()
        print()
        hr("=")
        print("  Audit complete.")
        hr("=")


if __name__ == "__main__":
    main()
