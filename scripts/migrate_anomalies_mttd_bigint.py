"""
migrate_anomalies_mttd_bigint.py
--------------------------------
One-shot migration: widens ANOMALIES MTTD columns from INTEGER to BIGINT.

HANA INTEGER overflows at ~24.8 days in milliseconds. E2E MTTD can exceed
that for backfilled or delayed logs, so existing tables need this ALTER.

Usage:
    python -m scripts.migrate_anomalies_mttd_bigint
"""

import sys

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST not set — cannot migrate mock mode.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

MIGRATIONS = [
    "ALTER TABLE ANOMALIES ALTER (PIPELINE_MTTD_MS BIGINT)",
    "ALTER TABLE ANOMALIES ALTER (E2E_MTTD_MS BIGINT)",
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
    changed = 0
    try:
        for stmt in MIGRATIONS:
            label = stmt.rsplit("(", 1)[1].split()[0]
            try:
                cur.execute(stmt)
                conn.commit()
                print(f"  ALTERED  {label}")
                changed += 1
            except Exception as exc:
                msg = str(exc).lower()
                if "same" in msg or "no need" in msg:
                    print(f"  SKIPPED  {label}  ({exc})")
                else:
                    print(f"  ERROR    {label}: {exc}")
                    raise
    finally:
        cur.close()
        conn.close()

    print(f"\nDone. Altered: {changed}  Total: {len(MIGRATIONS)}")


if __name__ == "__main__":
    main()
