"""
audit_window_sizes.py
---------------------
Fast sweep over candidate training windows. Reports sample counts and
median rows-per-sample across windows in {1, 5, 15, 30, 60, 120} minutes
on the real HANA dataset. Used to pick the training window for the
train/inference aggregation-mismatch fix.

Counts only — does NOT run the full per-IP feature extraction (that's
too slow at 1-min granularity over 900k rows). Final pick is then
re-tested with the real ``extract_features_windowed`` on one window
size before committing.

Usage::

    python -m scripts.audit_window_sizes
"""

from __future__ import annotations

import asyncio

import pandas as pd

from scripts.retrain_on_real_data import fetch_all_logs

CANDIDATE_WINDOWS_MINUTES: tuple[int, ...] = (1, 5, 15, 30, 60, 120)


def _summarize(df: pd.DataFrame, *, window_minutes: int) -> None:
    window_ns = int(window_minutes) * 60 * 1_000_000_000
    floored = (df["datetime"].astype("int64") // window_ns) * window_ns
    df = df.assign(_window_start=floored)
    counts = df.groupby(["_window_start", "source_ip"], sort=False).size()
    if counts.empty:
        print(f"  [{window_minutes:>3}m] empty")
        return
    samples = len(counts)
    n_windows = int(df["_window_start"].nunique())
    p50 = int(counts.median())
    p10 = int(counts.quantile(0.10))
    p90 = int(counts.quantile(0.90))
    mx = int(counts.max())
    print(
        f"  [{window_minutes:>3}m] samples={samples:>7,}  windows={n_windows:>5,}  "
        f"rows/sample p10={p10:>3}  p50={p50:>4}  p90={p90:>5}  max={mx:>6}"
    )


async def main() -> None:
    print("Fetching non-LLM rows from HANA...")
    df = await fetch_all_logs()
    print(f"  fetched {len(df):,} rows")
    if df.empty:
        return

    df = df.copy()
    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", utc=True)
    df = df.dropna(subset=["datetime"])
    df = df[df["source_ip"].astype(str).str.strip().ne("")]
    print(f"  after datetime+ip filter: {len(df):,} rows")

    span = df["datetime"].max() - df["datetime"].min()
    n_ips = df["source_ip"].nunique()
    print(f"  span: {span}  unique IPs: {n_ips}")

    print("\nWindow sweep (rows/sample = log rows aggregated into one training row):")
    for w in CANDIDATE_WINDOWS_MINUTES:
        _summarize(df, window_minutes=w)


if __name__ == "__main__":
    asyncio.run(main())
