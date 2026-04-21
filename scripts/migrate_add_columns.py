"""
migrate_add_columns.py
----------------------
One-shot migration: adds the 16 new columns to SECURITY_LOGS in HANA.

HANA does not support ALTER TABLE ... ADD COLUMN IF NOT EXISTS.
We catch the "already exists" error so the script is safe to re-run.

Usage:
    python -m scripts.migrate_add_columns
"""

import sys

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST not set — cannot migrate mock mode.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

_ALREADY_EXISTS_HINTS = ("already exists", "existing object", "cannot use duplicate")

NEW_COLUMNS = [
    "ALTER TABLE SECURITY_LOGS ADD (REQUEST_PATH         NVARCHAR(500))",
    "ALTER TABLE SECURITY_LOGS ADD (SAP_APPLICATION      NVARCHAR(100))",
    "ALTER TABLE SECURITY_LOGS ADD (REGION_CODE          NVARCHAR(20))",
    "ALTER TABLE SECURITY_LOGS ADD (MACRO_REGION         NVARCHAR(50))",
    "ALTER TABLE SECURITY_LOGS ADD (HTTP_METHOD          NVARCHAR(10))",
    "ALTER TABLE SECURITY_LOGS ADD (SAP_SOURCE_TYPE      NVARCHAR(50))",
    "ALTER TABLE SECURITY_LOGS ADD (SAP_APP_ENV          NVARCHAR(50))",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_TOTAL_TOKENS     INTEGER)",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_COST_USD         DOUBLE)",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_FINISH_REASON    NVARCHAR(50))",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_STATUS           NVARCHAR(50))",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_RESPONSE_TIME_MS DOUBLE)",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_PROMPT_CATEGORY  NVARCHAR(100))",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_ERROR_MESSAGE    NVARCHAR(500))",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_MODEL_ID         NVARCHAR(100))",
    "ALTER TABLE SECURITY_LOGS ADD (LLM_PROMPT_TOKENS    INTEGER)",
]


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
    added = 0
    skipped = 0
    try:
        for stmt in NEW_COLUMNS:
            col = stmt.split("(")[1].split()[0]
            try:
                cur.execute(stmt)
                conn.commit()
                print(f"  ADDED    {col}")
                added += 1
            except Exception as exc:
                msg = str(exc).lower()
                if any(hint in msg for hint in _ALREADY_EXISTS_HINTS):
                    print(f"  SKIPPED  {col}  (already exists)")
                    skipped += 1
                else:
                    print(f"  ERROR    {col}: {exc}")
                    raise
    finally:
        cur.close()
        conn.close()

    print(f"\nDone. Added: {added}  Skipped: {skipped}  Total: {len(NEW_COLUMNS)}")


if __name__ == "__main__":
    main()
