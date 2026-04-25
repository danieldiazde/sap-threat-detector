"""
train_model.py
--------------
CLI entrypoint for model training.

Usage::

    python -m scripts.train_model                       # default: IsolationForest
    python -m scripts.train_model --model-type dbscan
    python -m scripts.train_model --data data/samples/sample_logs.csv

Loads logs from the default mock CSV (or a user-specified path), runs
feature extraction, trains, evaluates, and writes a versioned model to
``models/<version_tag>/`` with a ``manifest.json``.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import pandas as pd
from src.common.config import settings
from src.common.logging import get_logger
from src.ingestion.log_parser import normalize_columns
from src.model.train import train_split
from src.storage.repositories import model_version_repository

logger = get_logger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train an anomaly detection model")
    parser.add_argument(
        "--data",
        type=str,
        default="data/samples/sample_logs.csv",
        help="Path to the log CSV (or parquet) to train on",
    )
    parser.add_argument(
        "--model-type",
        type=str,
        default=None,
        help="Model type: isolation_forest (default) or dbscan",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        logger.error("train.data_not_found", extra={"path": str(data_path)})
        print(f"Error: data file not found: {data_path}")
        print("Run 'make mock' first to generate sample data.")
        sys.exit(1)

    # Load
    df = pd.read_parquet(data_path) if data_path.suffix == ".parquet" else pd.read_csv(data_path)
    df = normalize_columns(df)
    print(f"Loaded {len(df)} log rows from {data_path}")

    # Train (train_split handles extract_features + legacy/modern split internally)
    model_type = args.model_type or settings.model_type
    print(f"Training {model_type} model(s)...")
    reports = train_split(df, model_type=model_type)

    # Report one section per split
    print(f"\nTraining complete ({len(reports)} model(s) trained):")
    for split, report in reports.items():
        print(f"\n  [{split.upper()}]")
        print(f"  Version tag:      {report['version_tag']}")
        print(f"  Model type:       {report['model_type']}")
        print(f"  Training samples: {report['training_samples']}")
        print(f"  Feature columns:  {len(report['feature_columns'])}")
        print(f"  Elapsed:          {report['elapsed_seconds']}s")
        print(f"  Anomaly rate:     {report['metrics'].get('anomaly_rate', 'n/a')}")

        score_dist = report["metrics"].get("score_distribution", {})
        if score_dist:
            print(f"  Score range:      [{score_dist.get('min', '?'):.4f}, {score_dist.get('max', '?'):.4f}]")
            print(f"  Score median:     {score_dist.get('median', '?'):.4f}")

        cv = report["metrics"].get("cv_anomaly_rate_stability", {})
        if cv:
            print(f"  CV stability:     mean={cv.get('mean', '?'):.4f}, std={cv.get('std', '?'):.4f}")

        report_path = Path(settings.model_dir) / report["version_tag"] / "training_report.json"
        report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"  Full report: {report_path}")

    # Register manifests in HANA MODEL_VERSIONS so the registry tracks
    # every model regardless of whether it was trained via the pipeline
    # auto-retrain, the bulk retrain script, or this CLI.
    async def _register_all() -> None:
        for report in reports.values():
            await model_version_repository.register(report)

    try:
        asyncio.run(_register_all())
        print(f"\nRegistered {len(reports)} manifest(s) in MODEL_VERSIONS.")
    except Exception as exc:
        print(f"\nWarning: HANA registration failed ({exc}). Models still saved on disk.")


if __name__ == "__main__":
    main()
