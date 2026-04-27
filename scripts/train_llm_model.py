"""
train_llm_model.py
------------------
CLI entrypoint to train the LLM threat-detection ensemble.

Pulls scorable LLM rows from HANA (LOG_TYPE in LLM_*, LLM_MODEL_ID IS NOT
NULL, LLM_STATUS = 'success'), trains the global IF + per-category IFs +
cohort profiles, and persists the bundle under ``models/llm/<version_tag>/``.

Usage::

    python -m scripts.train_llm_model
    python -m scripts.train_llm_model --limit 100000
    python -m scripts.train_llm_model --since 2026-04-21
    python -m scripts.train_llm_model --notes "post-audit baseline"
"""

from __future__ import annotations

import argparse
import json
import sys

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

from src.common.config import settings  # noqa: E402
from src.common.logging import get_logger  # noqa: E402

logger = get_logger(__name__)


def _column_map() -> dict[str, str]:
    """HANA column → canonical lowercase column expected by feature code."""
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


def fetch_training_rows(*, limit: int | None, since: str | None) -> pd.DataFrame:
    """Pull scorable LLM rows from HANA into a DataFrame."""
    if settings.mock_hana:
        raise RuntimeError(
            "HANA_HOST not set — cannot train against mock mode. "
            "Set HANA_* env vars in .env first."
        )

    from hdbcli import dbapi  # noqa: I001  (deferred so mock-mode error fires first)

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

        # Pull every scorable LLM row (success + error + timeout). The
        # trainer needs error/timeout rows to compute per-category baselines
        # for the spike rules; it filters down to LLM_STATUS='success'
        # internally before fitting the IsolationForests.
        where = [
            "LOG_TYPE LIKE 'LLM\\_%' ESCAPE '\\'",
            "LLM_MODEL_ID IS NOT NULL",
        ]
        if since:
            where.append(f"INGESTED_AT >= '{since}'")
        sql = f"SELECT {'TOP ' + str(limit) + ' ' if limit else ''}{cols} FROM SECURITY_LOGS WHERE " + " AND ".join(where)

        logger.info("llm_train.cli.fetching", extra={"limit": limit, "since": since})
        cur.execute(sql)
        rows = cur.fetchall()
        df = pd.DataFrame(rows, columns=list(cmap.keys()))
        df = df.rename(columns=cmap)
        cur.close()
    finally:
        conn.close()

    logger.info("llm_train.cli.fetched", extra={"rows": len(df)})
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the LLM threat-detection ensemble")
    parser.add_argument("--limit", type=int, default=None, help="Cap rows fetched from HANA")
    parser.add_argument("--since", type=str, default=None, help="Only INGESTED_AT >= YYYY-MM-DD")
    parser.add_argument("--notes", type=str, default="", help="Free-form note for the manifest")
    parser.add_argument(
        "--min-cohort-size",
        type=int,
        default=200,
        help="Min (model, category) row count to get its own profile entry",
    )
    parser.add_argument(
        "--min-category-size",
        type=int,
        default=500,
        help="Min row count for a category to get its own per-category IF",
    )
    args = parser.parse_args()

    # Lazy imports — defer until after argparse so --help is fast.
    from src.model.llm_train import llm_registry, train_llm_ensemble

    df = fetch_training_rows(limit=args.limit, since=args.since)
    if df.empty:
        print("No training rows returned from HANA. Check filters / data freshness.")
        sys.exit(1)

    print(f"Fetched {len(df):,} rows from HANA. Training ensemble...")
    bundle = train_llm_ensemble(
        df,
        min_cohort_size=args.min_cohort_size,
        min_category_size=args.min_category_size,
    )

    version_tag = llm_registry.save(bundle, notes=args.notes)

    md = bundle.metadata
    print()
    print("=" * 72)
    print(f"  LLM ensemble trained — {version_tag}")
    print("=" * 72)
    print(f"  Training rows           : {md['training_samples']:,}")
    print(f"  Categories modeled      : {len(bundle.category_models)}")
    print(f"  Categories skipped (small): {len(md['skipped_small_categories'])}")
    print(f"  Cohorts profiled        : {md['n_cohorts_profiled']}")
    print(f"  Global anomaly rate     : {md['global_anomaly_rate']:.4f}")
    print()
    print("  Per-category anomaly rates:")
    for cat, rate in sorted(md["category_anomaly_rates"].items()):
        n_cat = bundle.category_models[cat].n_estimators
        print(f"    {cat:<20} rate={rate:.4f}  trees={n_cat}")
    print()
    if md["skipped_small_categories"]:
        print("  Skipped categories (under min-category-size):")
        for cat, n in md["skipped_small_categories"].items():
            print(f"    {cat:<20} rows={n}")
        print()
    print(f"  Elapsed                 : {md['elapsed_seconds']:.2f}s")
    print(f"  Bundle path             : {llm_registry.root}/{version_tag}/")
    print()


if __name__ == "__main__":
    main()
