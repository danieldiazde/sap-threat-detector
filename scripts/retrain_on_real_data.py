"""
retrain_on_real_data.py
-----------------------
Bulk retrain against every non-LLM row in SECURITY_LOGS.

Steps:
    1. Pull all non-LLM rows from HANA into a DataFrame.
    2. Sweep contamination ∈ {0.01, 0.02, 0.03, 0.05} on the modern split
       and pick the value that maximises ``score_decile_gap``.
    3. Call ``train_split`` with the winning contamination — produces both
       legacy (13-feature) and modern (16-feature) models, wired via the
       ``latest-legacy.txt`` / ``latest-modern.txt`` pointers.
    4. Register both manifests to the HANA ``MODEL_VERSIONS`` table.
    5. Compute percentile-based threshold recommendations from the modern
       model's score distribution on the full dataset.

Outputs a summary JSON at ``reports/retrain/retrain_<timestamp>.json``.

Usage::

    python -m scripts.retrain_on_real_data
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow
from src.model.evaluate import evaluate
from src.model.features import extract_features, feature_matrix
from src.model.schema import FEATURE_COLUMNS
from src.model.train import _modern_mask
from src.storage.pool import pool
from src.storage.repositories import model_version_repository

logger = get_logger(__name__)

CONTAMINATION_CANDIDATES: tuple[float, ...] = (0.01, 0.02, 0.03, 0.05)

FETCH_SQL = """
    SELECT DATETIME, SOURCE_IP, PORT_SERVICE, EVENT_DESCRIPTION, STATUS,
           LOG_TYPE, REQUEST_PATH, SAP_APPLICATION, REGION_CODE, MACRO_REGION,
           HTTP_METHOD, SAP_SOURCE_TYPE, SAP_APP_ENV
    FROM SECURITY_LOGS
    WHERE SOURCE_IP IS NOT NULL AND SOURCE_IP != ''
"""


async def fetch_all_logs() -> pd.DataFrame:
    async with pool.acquire() as conn:
        if conn is None:
            raise RuntimeError("Cannot acquire HANA connection — check HANA_HOST / creds")

        def _fetch() -> pd.DataFrame:
            cursor = conn.cursor()
            try:
                cursor.execute(FETCH_SQL)
                cols = [d[0].lower() for d in cursor.description]
                rows = cursor.fetchall()
                return pd.DataFrame(rows, columns=cols)
            finally:
                cursor.close()

        return await asyncio.to_thread(_fetch)


def sweep_contamination(features_df: pd.DataFrame) -> tuple[float, list[dict]]:
    """Return (best_contamination, sweep_results)."""
    modern_mask = _modern_mask(features_df)
    modern_df = features_df[modern_mask].reset_index(drop=True)
    if modern_df.empty:
        return settings.model_contamination, []

    X = feature_matrix(modern_df, columns=FEATURE_COLUMNS)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    results: list[dict] = []
    for c in CONTAMINATION_CANDIDATES:
        model = IsolationForest(
            contamination=c,
            n_estimators=settings.model_n_estimators,
            max_samples="auto",
            random_state=settings.model_random_state,
        )
        model.fit(X_scaled)
        metrics = evaluate(model=model, X_scaled=X_scaled, model_type="isolation_forest")
        dist = metrics["score_distribution"]
        results.append(
            {
                "contamination": c,
                "anomaly_rate": metrics["anomaly_rate"],
                "score_decile_gap": metrics["score_decile_gap"],
                "score_min": dist["min"],
                "score_p10": dist["p10"],
                "score_median": dist["median"],
                "score_p90": dist["p90"],
                "score_max": dist["max"],
            }
        )

    # Best = widest decile gap (most separation). Tie-break on lower anomaly rate.
    best = max(results, key=lambda r: (r["score_decile_gap"], -r["anomaly_rate"]))
    return best["contamination"], results


def compute_threshold_recs(features_df: pd.DataFrame, contamination: float) -> dict:
    """Re-fit a modern model with the winning contamination and return percentile thresholds."""
    modern_mask = _modern_mask(features_df)
    modern_df = features_df[modern_mask].reset_index(drop=True)
    X = feature_matrix(modern_df, columns=FEATURE_COLUMNS)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(
        contamination=contamination,
        n_estimators=settings.model_n_estimators,
        max_samples="auto",
        random_state=settings.model_random_state,
    )
    model.fit(X_scaled)
    scores = model.decision_function(X_scaled)

    return {
        "samples": int(len(scores)),
        "score_min": float(scores.min()),
        "score_p01": float(np.percentile(scores, 1)),
        "score_p05": float(np.percentile(scores, 5)),
        "score_p10": float(np.percentile(scores, 10)),
        "score_p25": float(np.percentile(scores, 25)),
        "score_median": float(np.median(scores)),
        "score_max": float(scores.max()),
        # Recommendations
        "rec_anomaly_score_threshold": float(np.percentile(scores, 10)),
        "rec_alert_medium_threshold": float(np.percentile(scores, 5)),
        "rec_alert_high_threshold": float(np.percentile(scores, 1)),
    }


async def register_manifests(reports: dict) -> None:
    for split, report in reports.items():
        manifest = {
            "version_tag": report["version_tag"],
            "model_type": report["model_type"],
            "trained_at": report["trained_at"],
            "contamination": report["contamination"],
            "training_samples": report["training_samples"],
            "feature_columns": report["feature_columns"],
            "hyperparams": report["hyperparams"],
            "cv_scores": report["cv_scores"],
            "is_active": True,
            "notes": f"Bulk retrain on real HANA data (split={split})",
        }
        await model_version_repository.register(manifest)
        logger.info("retrain.registered", extra={"split": split, "version_tag": report["version_tag"]})


async def main() -> None:
    print("Fetching non-LLM rows from HANA...")
    raw_df = await fetch_all_logs()
    print(f"  fetched {len(raw_df):,} rows")

    print("Extracting features (groupby source_ip)...")
    features_df = extract_features(raw_df)
    print(f"  produced {len(features_df):,} per-IP feature rows")

    modern_count = int(_modern_mask(features_df).sum())
    legacy_count = len(features_df) - modern_count
    print(f"  split: legacy={legacy_count:,}  modern={modern_count:,}")

    print("\nSweeping contamination on modern split...")
    best_c, sweep = sweep_contamination(features_df)
    for r in sweep:
        marker = "  <-- picked" if r["contamination"] == best_c else ""
        print(
            f"  c={r['contamination']:.3f}  "
            f"anomaly_rate={r['anomaly_rate']:.4f}  "
            f"decile_gap={r['score_decile_gap']:.4f}{marker}"
        )
    print(f"  winning contamination: {best_c}")

    # Override the settings contamination for this training run via env,
    # then reload settings + train modules so train_split picks up the new value.
    import os
    from importlib import reload

    import src.common.config as _cfg
    import src.model.train as _train

    os.environ["MODEL_CONTAMINATION"] = str(best_c)
    reload(_cfg)
    reload(_train)

    print("\nTraining legacy + modern via train_split...")
    reports = _train.train_split(raw_df)
    for split, report in reports.items():
        cv = report["metrics"].get("cv_anomaly_rate_stability", {})
        dist = report["metrics"]["score_distribution"]
        print(f"  [{split}] version={report['version_tag']}  samples={report['training_samples']:,}")
        print(f"    anomaly_rate={report['metrics']['anomaly_rate']:.4f}  "
              f"decile_gap={report['metrics']['score_decile_gap']:.4f}")
        print(f"    score range [{dist['min']:.4f}, {dist['max']:.4f}]  "
              f"median={dist['median']:.4f}")
        if cv:
            print(f"    CV: mean={cv['mean']:.4f} std={cv['std']:.4f}")

    print("\nRegistering manifests to HANA MODEL_VERSIONS...")
    await register_manifests(reports)

    print("\nComputing percentile threshold recommendations (modern split)...")
    thresholds = compute_threshold_recs(features_df, best_c)
    print(f"  score percentiles: p1={thresholds['score_p01']:.4f} "
          f"p5={thresholds['score_p05']:.4f} "
          f"p10={thresholds['score_p10']:.4f} "
          f"median={thresholds['score_median']:.4f}")
    print(f"  RECOMMEND  ANOMALY_SCORE_THRESHOLD  = {thresholds['rec_anomaly_score_threshold']:.4f}  (p10)")
    print(f"  RECOMMEND  ALERT_MEDIUM_THRESHOLD   = {thresholds['rec_alert_medium_threshold']:.4f}  (p5)")
    print(f"  RECOMMEND  ALERT_HIGH_THRESHOLD     = {thresholds['rec_alert_high_threshold']:.4f}  (p1)")

    out_dir = Path("reports/retrain")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"retrain_{utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    out_path.write_text(
        json.dumps(
            {
                "completed_at": utcnow().isoformat(),
                "raw_rows": int(len(raw_df)),
                "feature_rows": int(len(features_df)),
                "legacy_count": legacy_count,
                "modern_count": modern_count,
                "contamination_sweep": sweep,
                "winning_contamination": best_c,
                "reports": reports,
                "thresholds": thresholds,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    print(f"\nFull summary written to: {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
