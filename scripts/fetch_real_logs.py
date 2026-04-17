"""
fetch_real_logs.py
------------------
Downloads all pages of real SAP security logs from the live API
and saves them to data/samples/sample_logs.csv so that
`make train` trains on real data instead of mock data.

Usage:
    python scripts/fetch_real_logs.py

Owner: Cloud Integration Engineer
"""

import asyncio
import os
import sys
from pathlib import Path

import httpx
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# ─── Config ────────────────────────────────────────────────────────────────

API_URL = os.getenv("SAP_API_URL", "")
API_KEY = os.getenv("SAP_API_KEY", "")
OUTPUT_PATH = Path("data/samples/sample_logs.csv")

# Maps real API field names → canonical pipeline names
COLUMN_ALIASES = {
    "@timestamp":            "datetime",
    "client_ip":             "source_ip",
    "http_status_code":      "status",
    "sap_function_message":  "event_description",
    "service_id":            "port_service",
    "sap_function_log_type": "log_type",
}


# ─── Main ──────────────────────────────────────────────────────────────────

async def fetch_all_pages() -> pd.DataFrame:
    if not API_URL or not API_KEY:
        print("ERROR: SAP_API_URL or SAP_API_KEY not set in .env")
        sys.exit(1)

    headers = {"Authorization": f"Bearer {API_KEY}"}
    all_pages: list[pd.DataFrame] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Get total page count first
        info = (await client.get(f"{API_URL}/info", headers=headers)).json()
        total_pages = info["total_pages"]
        total_records = info["total_records"]
        window_start = info["window_start"]
        window_end = info["window_end"]

        print(f"Window    : {window_start}  to  {window_end}")
        print(f"Records   : {total_records}")
        print(f"Pages     : {total_pages}")
        print()

        for page in range(1, total_pages + 1):
            print(f"  Fetching page {page}/{total_pages}...", end=" ", flush=True)
            r = await client.get(
                f"{API_URL}/logs/current",
                headers=headers,
                params={"page": page},
            )
            r.raise_for_status()
            records = r.json().get("data", [])
            df = pd.DataFrame(records).rename(columns=COLUMN_ALIASES)
            all_pages.append(df)
            print(f"{len(records)} rows")

    return pd.concat(all_pages, ignore_index=True)


async def main() -> None:
    print("=" * 50)
    print("  SAP Real Log Fetcher")
    print("=" * 50)
    print()

    df = await fetch_all_pages()

    print()
    print(f"Total rows fetched : {len(df)}")
    print(f"Columns            : {list(df.columns)}")

    # Verify required columns are present
    required = ["datetime", "source_ip", "status", "event_description"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"\nWARNING: Missing required columns: {missing}")
        print("Training may fail. Check column mapping in this script.")
    else:
        print("Required columns   : ALL PRESENT")

    # Save to CSV
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved to           : {OUTPUT_PATH}")
    print()
    print("You can now run:  make train")


if __name__ == "__main__":
    asyncio.run(main())
