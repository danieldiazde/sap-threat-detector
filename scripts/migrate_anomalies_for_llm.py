"""
migrate_anomalies_for_llm.py
----------------------------
One-shot migration: extends ANOMALIES to support both SAP and LLM detectors
under a single-table-inheritance pattern.

Changes (all additive / nullability-relaxing — no data loss):
  - ADD DETECTOR             NVARCHAR(20)  default 'sap'  (discriminator)
  - ADD LLM_MODEL_ID         NVARCHAR(100) nullable
  - ADD LLM_PROMPT_CATEGORY  NVARCHAR(100) nullable
  - ADD RULE_IDS             NCLOB         nullable       (JSON array of fired rule_ids)
  - ADD IF_GLOBAL_SCORE      DECIMAL(10,6) nullable
  - ADD IF_CATEGORY_SCORE    DECIMAL(10,6) nullable
  - ALTER SOURCE_IP NULL     (LLM anomalies are not IP-keyed)
  - CREATE INDEX on DETECTOR for fast filtered reads from the dashboard

HANA does not support ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so each
statement is wrapped in a try/except that catches "already exists" / "is
already nullable" so the script is safe to re-run.

Usage:
    python -m scripts.migrate_anomalies_for_llm
"""

import sys

from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST not set — cannot migrate mock mode.")
    sys.exit(1)

from hdbcli import dbapi  # noqa: E402

# Hints that mean "the change you're trying to make is already in effect."
# Different HANA versions phrase these differently; widening the list as we
# encounter new wording is intentional.
_IDEMPOTENT_HINTS = (
    "already exists",
    "existing object",
    "cannot use duplicate",
    "is already nullable",
    "no change",
)

STATEMENTS = [
    "ALTER TABLE ANOMALIES ADD (DETECTOR            NVARCHAR(20)  DEFAULT 'sap')",
    "ALTER TABLE ANOMALIES ADD (LLM_MODEL_ID        NVARCHAR(100))",
    "ALTER TABLE ANOMALIES ADD (LLM_PROMPT_CATEGORY NVARCHAR(100))",
    "ALTER TABLE ANOMALIES ADD (RULE_IDS            NCLOB)",
    "ALTER TABLE ANOMALIES ADD (IF_GLOBAL_SCORE     DECIMAL(10,6))",
    "ALTER TABLE ANOMALIES ADD (IF_CATEGORY_SCORE   DECIMAL(10,6))",
    # Relax NOT NULL on SOURCE_IP so LLM anomalies can omit it.
    "ALTER TABLE ANOMALIES ALTER (SOURCE_IP NVARCHAR(50) NULL)",
    # Backfill discriminator on existing rows (idempotent — safe to re-run).
    "UPDATE ANOMALIES SET DETECTOR = 'sap' WHERE DETECTOR IS NULL",
    "CREATE INDEX IDX_ANOMALIES_DETECTOR ON ANOMALIES (DETECTOR)",
]


def _label_for(stmt: str) -> str:
    upper = stmt.upper()
    if upper.startswith("ALTER TABLE") and " ADD " in upper:
        return "ADD " + stmt.split("(", 1)[1].split()[0]
    if upper.startswith("ALTER TABLE") and " ALTER " in upper:
        return "ALTER " + stmt.split("(", 1)[1].split()[0]
    if upper.startswith("CREATE") and "INDEX" in upper:
        parts = stmt.split()
        try:
            return "INDEX " + parts[parts.index("INDEX") + 1]
        except (ValueError, IndexError):
            return stmt[:60]
    if upper.startswith("UPDATE"):
        return "BACKFILL DETECTOR"
    return stmt[:60]


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
    applied = 0
    skipped = 0
    try:
        for stmt in STATEMENTS:
            label = _label_for(stmt)
            try:
                cur.execute(stmt)
                conn.commit()
                rc = cur.rowcount if cur.rowcount and cur.rowcount > 0 else None
                tail = f" (rows: {rc})" if rc else ""
                print(f"  APPLIED  {label}{tail}")
                applied += 1
            except Exception as exc:
                msg = str(exc).lower()
                if any(hint in msg for hint in _IDEMPOTENT_HINTS):
                    print(f"  SKIPPED  {label}  (already in effect)")
                    skipped += 1
                else:
                    print(f"  ERROR    {label}: {exc}")
                    raise
    finally:
        cur.close()
        conn.close()

    print(f"\nDone. Applied: {applied}  Skipped: {skipped}  Total: {len(STATEMENTS)}")


if __name__ == "__main__":
    main()
