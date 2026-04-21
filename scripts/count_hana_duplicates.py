"""
count_hana_duplicates.py
------------------------
Count duplicate rows in SECURITY_LOGS (rows with identical DATETIME,
SOURCE_IP, EVENT_DESCRIPTION, STATUS, LOG_TYPE but different auto-increment IDs).

Usage:
    python scripts/count_hana_duplicates.py
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

COUNT_SQL = """
SELECT
    COUNT(*) AS total_rows,
    COUNT(DISTINCT
        CONCAT(TO_VARCHAR(DATETIME),
        CONCAT('|', CONCAT(COALESCE(SOURCE_IP, ''),
        CONCAT('|', CONCAT(COALESCE(EVENT_DESCRIPTION, ''),
        CONCAT('|', CONCAT(COALESCE(STATUS, ''),
        CONCAT('|', COALESCE(LOG_TYPE, ''))
    )))))))
    ) AS unique_rows,
    COUNT(*) - COUNT(DISTINCT
        CONCAT(TO_VARCHAR(DATETIME),
        CONCAT('|', CONCAT(COALESCE(SOURCE_IP, ''),
        CONCAT('|', CONCAT(COALESCE(EVENT_DESCRIPTION, ''),
        CONCAT('|', CONCAT(COALESCE(STATUS, ''),
        CONCAT('|', COALESCE(LOG_TYPE, ''))
    )))))))
    ) AS duplicate_rows
FROM SECURITY_LOGS
"""


def main() -> None:
    print("Connecting to HANA...")
    conn = dbapi.connect(
        address=settings.hana_host,
        port=settings.hana_port,
        user=settings.hana_user,
        password=settings.hana_password,
        databaseName=settings.hana_database,
    )
    cursor = conn.cursor()
    try:
        print("Running duplicate count query...\n")
        cursor.execute(COUNT_SQL)
        row = cursor.fetchone()
        total_rows, unique_rows, duplicate_rows = row[0], row[1], row[2]

        print("=" * 40)
        print(f"  Total rows      : {total_rows:,}")
        print(f"  Unique rows     : {unique_rows:,}")
        print(f"  Duplicate rows  : {duplicate_rows:,}")
        print("=" * 40)

        if duplicate_rows == 0:
            print("\nNo duplicates found — SECURITY_LOGS is already clean.")
        else:
            pct = (duplicate_rows / total_rows * 100) if total_rows else 0
            print(f"\n{duplicate_rows:,} rows ({pct:.1f}%) can be safely deleted.")
            print("Run scripts/delete_hana_duplicates.py to clean up.")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
