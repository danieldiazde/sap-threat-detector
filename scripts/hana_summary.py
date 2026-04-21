"""
hana_summary.py
---------------
Comprehensive data summary against HANA SECURITY_LOGS and ANOMALIES.

Usage:
    python scripts/hana_summary.py
"""

import sys

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST is not set — running in mock mode, no real HANA to query.")
    print("Set HANA_HOST, HANA_USER, HANA_PASSWORD, HANA_DATABASE in your .env first.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

W = 72


def hr(char="─"):
    print(char * W)


def header(title):
    hr("═")
    print(f"  {title}")
    hr("═")


def section(title):
    print()
    hr()
    print(f"  {title}")
    hr()


def q(cursor, sql):
    cursor.execute(sql)
    return cursor.fetchall()


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
        header("SAP THREAT DETECTOR — HANA DATA SUMMARY")

        # ── 1. Total rows ────────────────────────────────────────────────
        section("1. TOTAL ROWS — SECURITY_LOGS")
        total_logs = q(cur, "SELECT COUNT(*) FROM SECURITY_LOGS")[0][0]
        print(f"  Total rows: {total_logs:,}")

        # ── 2. Distinct 30-minute windows ────────────────────────────────
        section("2. DISTINCT 30-MINUTE WINDOWS")
        rows = q(cur, """
            SELECT
                COUNT(DISTINCT
                    FLOOR(SECONDS_BETWEEN(TO_TIMESTAMP('1970-01-01 00:00:00'), DATETIME) / 1800)
                ) AS DISTINCT_WINDOWS,
                MIN(DATETIME) AS FIRST_DT,
                MAX(DATETIME) AS LAST_DT
            FROM SECURITY_LOGS
            WHERE DATETIME IS NOT NULL
        """)
        distinct_windows, first_dt, last_dt = rows[0]
        print(f"  Distinct 30-min windows : {distinct_windows:,}")
        print(f"  First window start      : {first_dt}")
        print(f"  Last window start       : {last_dt}")

        # ── 3. Per-column cardinality & top 5 ───────────────────────────
        section("3. COLUMN CARDINALITY & TOP-5 MOST FREQUENT VALUES")
        for col in ("SOURCE_IP", "PORT_SERVICE", "STATUS", "LOG_TYPE", "EVENT_DESCRIPTION"):
            distinct = q(cur, f"SELECT COUNT(DISTINCT {col}) FROM SECURITY_LOGS")[0][0]
            top5 = q(cur, f"""
                SELECT TOP 5 {col}, COUNT(*) AS CNT
                FROM SECURITY_LOGS
                WHERE {col} IS NOT NULL
                GROUP BY {col}
                ORDER BY COUNT(*) DESC
            """)
            print(f"\n  ── {col}  (distinct: {distinct:,}) ──")
            print(f"  {'VALUE':<44}  {'COUNT':>8}  {'%':>6}")
            print("  " + "-" * 63)
            for val, cnt in top5:
                pct = cnt / total_logs * 100 if total_logs else 0
                print(f"  {str(val)[:43]:<44}  {cnt:>8,}  {pct:>5.1f}%")

        # ── 4. Date range ────────────────────────────────────────────────
        section("4. DATE RANGE — DATETIME COLUMN")
        rows = q(cur, """
            SELECT
                MIN(DATETIME)  AS MIN_DT,
                MAX(DATETIME)  AS MAX_DT,
                DAYS_BETWEEN(MIN(DATETIME), MAX(DATETIME)) AS SPAN_DAYS
            FROM SECURITY_LOGS
            WHERE DATETIME IS NOT NULL
        """)
        min_dt, max_dt, span_days = rows[0]
        print(f"  MIN : {min_dt}")
        print(f"  MAX : {max_dt}")
        print(f"  Span: {span_days} day(s)")

        # ── 5. Anomalies ─────────────────────────────────────────────────
        section("5. ANOMALIES — COUNT & PERCENTAGE")
        total_anomalies = q(cur, "SELECT COUNT(*) FROM ANOMALIES")[0][0]
        rate = total_anomalies / total_logs * 100 if total_logs else 0.0
        print(f"  Total anomalies : {total_anomalies:,}")
        print(f"  Total logs      : {total_logs:,}")
        print(f"  Anomaly rate    : {rate:.3f}%")

        threat_rows = q(cur, """
            SELECT THREAT_LEVEL, COUNT(*) AS CNT
            FROM ANOMALIES
            GROUP BY THREAT_LEVEL
            ORDER BY COUNT(*) DESC
        """)
        if threat_rows:
            print()
            print(f"  {'THREAT LEVEL':<18}  {'COUNT':>8}  {'% of anomalies':>15}")
            print("  " + "-" * 46)
            for lvl, cnt in threat_rows:
                lvl_pct = cnt / total_anomalies * 100 if total_anomalies else 0
                print(f"  {str(lvl):<18}  {cnt:>8,}  {lvl_pct:>14.1f}%")

        print()
        hr("═")
        print("  Summary complete.")
        hr("═")

    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
