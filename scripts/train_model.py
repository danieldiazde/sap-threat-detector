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
import json
import sys
from pathlib import Path

import pandas as pd

from src.common.config import settings
from src.common.logging import get_logger
from src.ingestion.log_parser import normalize_columns
from src.model.features import extract_features
from src.model.train import train

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
    if data_path.suffix == ".parquet":
        df = pd.read_parquet(data_path)
    else:
        df = pd.read_csv(data_path)
    df = normalize_columns(df)
    print(f"Loaded {len(df)} log rows from {data_path}")

    # Feature extraction
    features_df = extract_features(df)
    print(f"Extracted features for {len(features_df)} unique IPs")

    if features_df.empty:
        print("Error: no features extracted — check your data.")
        sys.exit(1)

    # Train
    model_type = args.model_type or settings.model_type
    print(f"Training {model_type} model...")
    report = train(features_df, model_type=model_type)

    # Report
    print(f"\nTraining complete:")
    print(f"  Version tag:      {report['version_tag']}")
    print(f"  Model type:       {report['model_type']}")
    print(f"  Training samples: {report['training_samples']}")
    print(f"  Elapsed:          {report['elapsed_seconds']}s")
    print(f"  Anomaly rate:     {report['metrics'].get('anomaly_rate', 'n/a')}")

    score_dist = report["metrics"].get("score_distribution", {})
    if score_dist:
        print(f"  Score range:      [{score_dist.get('min', '?'):.4f}, {score_dist.get('max', '?'):.4f}]")
        print(f"  Score median:     {score_dist.get('median', '?'):.4f}")

    cv = report["metrics"].get("cv_anomaly_rate_stability", {})
    if cv:
        print(f"  CV stability:     mean={cv.get('mean', '?'):.4f}, std={cv.get('std', '?'):.4f}")

    # Write human-readable report
    report_path = Path(settings.model_dir) / report["version_tag"] / "training_report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nFull report: {report_path}")
    print(f"Model dir:   {settings.model_dir / report['version_tag']}/")


if __name__ == "__main__":
    main()
