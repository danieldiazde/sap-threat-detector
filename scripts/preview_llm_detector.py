"""
preview_llm_detector.py
-----------------------
Throwaway validation script: runs the trained LLM detector against a slice
of real HANA data and prints what it emits. Use this BEFORE the integration
PR rewires src/pipeline.py — the goal is to see the false-positive / false-
negative behavior on production-shape data and calibrate thresholds if
needed.

Usage::

    python -m scripts.preview_llm_detector
    python -m scripts.preview_llm_detector --limit 5000
    python -m scripts.preview_llm_detector --since 2026-04-26
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402

if settings.mock_hana:
    print("ERROR: HANA_HOST not set — preview requires real data.")
    sys.exit(1)


def _column_map() -> dict[str, str]:
    return {
        "DATETIME": "datetime",
        "SOURCE_IP": "source_ip",
        "STATUS": "status",
        "EVENT_DESCRIPTION": "event_description",
        "PORT_SERVICE": "port_service",
        "LOG_TYPE": "log_type",
        "LLM_MODEL_ID": "llm_model_id",
        "LLM_PROMPT_CATEGORY": "llm_prompt_category",
        "LLM_PROMPT_TOKENS": "llm_prompt_tokens",
        "LLM_TOTAL_TOKENS": "llm_total_tokens",
        "LLM_COST_USD": "llm_cost_usd",
        "LLM_RESPONSE_TIME_MS": "llm_response_time_ms",
        "LLM_FINISH_REASON": "llm_finish_reason",
        "LLM_STATUS": "llm_status",
        "LLM_ERROR_MESSAGE": "llm_error_message",
        "INGESTED_AT": "ingested_at",
    }


def fetch_recent_llm_rows(limit: int, since: str | None) -> pd.DataFrame:
    from hdbcli import dbapi

    conn = dbapi.connect(
        address=settings.hana_host,
        port=settings.hana_port,
        user=settings.hana_user,
        password=settings.hana_password,
        databaseName=settings.hana_database,
    )
    try:
        cur = conn.cursor()
        cmap = _column_map()
        cols = ", ".join(cmap.keys())
        where = ["LOG_TYPE LIKE 'LLM\\_%' ESCAPE '\\'", "LLM_MODEL_ID IS NOT NULL"]
        if since:
            where.append(f"INGESTED_AT >= '{since}'")
        sql = (
            f"SELECT TOP {limit} {cols} FROM SECURITY_LOGS "
            f"WHERE {' AND '.join(where)} ORDER BY INGESTED_AT DESC"
        )
        cur.execute(sql)
        rows = cur.fetchall()
        df = pd.DataFrame(rows, columns=list(cmap.keys())).rename(columns=cmap)
        cur.close()
    finally:
        conn.close()
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview LLM detector on real HANA data")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--since", type=str, default=None)
    parser.add_argument("--show-rows", type=int, default=10, help="Per-cohort sample rows to print")
    args = parser.parse_args()

    from src.model.llm_predict import predict_llm
    from src.model.llm_train import llm_registry

    print(f"Fetching up to {args.limit:,} most-recent LLM rows from HANA...")
    df = fetch_recent_llm_rows(args.limit, args.since)
    if df.empty:
        print("No LLM rows returned. Check filters / data freshness.")
        sys.exit(0)
    print(f"  Got {len(df):,} rows. INGESTED_AT range: {df['ingested_at'].min()}  →  {df['ingested_at'].max()}")
    print()

    bundle = llm_registry.load("latest")
    print(f"Loaded bundle: {bundle.metadata.get('version_tag', 'unknown')}")
    print(f"  Categories modeled: {len(bundle.category_models)}")
    print(f"  Cohorts profiled  : {bundle.profiles.n_cohorts}")
    print()

    ingested_at = datetime.now(tz=UTC)
    result = predict_llm(df, ingested_at=ingested_at, bundle=bundle)

    print("=" * 80)
    print(f"  PREDICT RESULT: {len(result)} anomalous cohort(s) emitted from {len(df):,} rows")
    print("=" * 80)
    print()

    if result.empty:
        print("No anomalies emitted. If you expected some, thresholds may be too tight.")
        return

    # Sort by severity desc, then anomaly fraction desc
    severity_order = {"high": 3, "medium": 2, "low": 1}
    result = result.assign(_sev=result["threat_level"].map(severity_order)).sort_values(
        ["_sev", "global_anomaly_fraction"], ascending=False
    )

    severity_counts = result["threat_level"].value_counts().to_dict()
    print(f"  Severity breakdown: {severity_counts}")
    print()

    for _, row in result.iterrows():
        print(f"── {row['threat_level'].upper():<6} ─ ({row['llm_model_id']}, {row['llm_prompt_category']})")
        print(f"     cohort size           : {row['total_requests']}")
        print(f"     global anomaly frac   : {row['global_anomaly_fraction']:.2%}")
        print(f"     category anomaly frac : {row['category_anomaly_fraction']:.2%}")
        print(f"     global IF score (mean): {row['anomaly_score']:.4f}")
        print(f"     rules fired           : {row['rule_ids']}")
        if row["rule_context"]:
            ctx = json.loads(row["rule_context"])
            for rule_id, rule_ctx in ctx.items():
                summary = ", ".join(f"{k}={v}" for k, v in rule_ctx.items() if k not in ("baseline_rate",))
                print(f"        - {rule_id}: {summary}")
        print()


if __name__ == "__main__":
    main()
