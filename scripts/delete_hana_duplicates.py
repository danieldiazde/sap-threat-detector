"""
delete_hana_duplicates.py
-------------------------
Delete duplicate rows from SECURITY_LOGS, keeping the lowest ID
(first-inserted copy) for each unique (DATETIME, SOURCE_IP,
EVENT_DESCRIPTION, STATUS, LOG_TYPE) combination.

Usage:
    python scripts/delete_hana_duplicates.py
"""

import sys

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST is not set — running in mock mode.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

DELETE_SQL = """
DELETE FROM SECURITY_LOGS
WHERE ID NOT IN (
    SELECT MIN(ID)
    FROM SECURITY_LOGS
    GROUP BY DATETIME, SOURCE_IP, EVENT_DESCRIPTION, STATUS, LOG_TYPE
)
"""

VERIFY_SQL = "SELECT COUNT(*) FROM SECURITY_LOGS"


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
        cursor.execute(VERIFY_SQL)
        before = cursor.fetchone()[0]
        print(f"Rows before delete : {before:,}")

        print("Deleting duplicates (keeping MIN(ID) per unique log)...")
        cursor.execute(DELETE_SQL)
        conn.commit()
        deleted = cursor.rowcount

        cursor.execute(VERIFY_SQL)
        after = cursor.fetchone()[0]

        print()
        print("=" * 40)
        print(f"  Rows deleted      : {deleted:,}")
        print(f"  Rows remaining    : {after:,}")
        print("=" * 40)
        print("\nSECURITY_LOGS is now clean.")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
