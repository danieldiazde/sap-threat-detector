"""
generate_mock_logs.py
---------------------
Generate realistic mock security logs in SAP CSV format.

Usage::

    python -m scripts.generate_mock_logs --rows 5000 --attack-ratio 0.05 \
        --with-spikes --with-brute-force --seed 42 --out data/samples/sample_logs.csv

The output CSV has the canonical columns:
  datetime, source_ip, port_service, event_description, status, log_type

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

# ─── Constants ─────────────────────────────────────────────────────────────

NORMAL_IPS_POOL_SIZE = 80
ATTACKER_IPS_POOL_SIZE = 10
SPIKE_IP_COUNT = 3

NORMAL_PATHS = [
    "GET /index.html HTTP/1.1",
    "GET /api/v1/users HTTP/1.1",
    "POST /api/v1/login HTTP/1.1",
    "GET /api/v1/dashboard HTTP/1.1",
    "GET /static/styles.css HTTP/1.1",
    "GET /api/v1/reports HTTP/1.1",
    "POST /api/v1/orders HTTP/1.1",
    "GET /favicon.ico HTTP/1.1",
]

ATTACK_PATHS = [
    "GET /phpmyadmin/ HTTP/1.1",
    "GET /wp-login.php HTTP/1.1",
    "GET /admin/ HTTP/1.1",
    "GET /.env HTTP/1.1",
    "GET /.git/config HTTP/1.1",
    "GET /cgi-bin/test.cgi HTTP/1.1",
    "POST /xmlrpc.php HTTP/1.1",
    "GET /etc/passwd HTTP/1.1",
]

SQLI_EVENTS = [
    "WAF Alert: Possible SQL injection UNION SELECT",
    "WAF Alert: Possible SQL injection OR 1=1",
    "WAF Alert: Possible SQL injection DROP TABLE",
]

BRUTE_FORCE_EVENTS = [
    "Failed login attempt: user 'root'",
    "Failed login attempt: user 'admin'",
    "Multiple authentication attempts (Brute force)",
    "Authentication failure for user 'sa'",
]

NORMAL_STATUSES = ["200", "200", "200", "200", "301", "304"]
ATTACK_STATUSES = ["DENIED", "BLOCKED", "404 NOT FOUND", "ACCOUNT LOCKED", "DROPPED"]

PORTS_NORMAL = ["TCP/80", "TCP/443", "TCP/8080"]
PORTS_ATTACK = ["TCP/22", "TCP/3389", "TCP/80", "TCP/443"]


def generate(
    rows: int = 5000,
    attack_ratio: float = 0.05,
    with_spikes: bool = False,
    with_brute_force: bool = False,
    seed: int | None = None,
) -> pd.DataFrame:
    """Return a DataFrame of synthetic security logs."""
    rng = random.Random(seed)
    base_time = datetime(2026, 4, 4, 14, 0, 0, tzinfo=timezone.utc)

    normal_ips = [f"10.10.1.{i}" for i in range(1, NORMAL_IPS_POOL_SIZE + 1)]
    attacker_ips = [f"203.0.113.{i}" for i in range(1, ATTACKER_IPS_POOL_SIZE + 1)]
    spike_ips = [f"198.51.100.{i}" for i in range(1, SPIKE_IP_COUNT + 1)]

    n_attack = int(rows * attack_ratio)
    n_normal = rows - n_attack

    records: list[dict[str, str]] = []

    # Normal traffic
    for _ in range(n_normal):
        offset = timedelta(seconds=rng.randint(0, 3600))
        records.append({
            "datetime": (base_time + offset).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": rng.choice(normal_ips),
            "port_service": rng.choice(PORTS_NORMAL),
            "event_description": rng.choice(NORMAL_PATHS),
            "status": rng.choice(NORMAL_STATUSES),
            "log_type": "access",
        })

    # Attack traffic (directory scans, SQLi)
    for _ in range(n_attack):
        offset = timedelta(seconds=rng.randint(0, 3600))
        is_sqli = rng.random() < 0.3
        records.append({
            "datetime": (base_time + offset).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": rng.choice(attacker_ips),
            "port_service": rng.choice(PORTS_ATTACK),
            "event_description": rng.choice(SQLI_EVENTS if is_sqli else ATTACK_PATHS),
            "status": rng.choice(ATTACK_STATUSES),
            "log_type": "security",
        })

    # Spike injection: one IP, massive burst in a 5-minute window
    if with_spikes:
        spike_ip = rng.choice(spike_ips)
        spike_start = base_time + timedelta(minutes=rng.randint(10, 50))
        spike_rows = max(50, int(rows * 0.02))
        for i in range(spike_rows):
            offset = timedelta(seconds=rng.randint(0, 300))
            records.append({
                "datetime": (spike_start + offset).strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": spike_ip,
                "port_service": "TCP/80",
                "event_description": rng.choice(ATTACK_PATHS),
                "status": rng.choice(ATTACK_STATUSES),
                "log_type": "security",
            })

    # Brute-force injection: sustained failed logins from one IP
    if with_brute_force:
        bf_ip = rng.choice(attacker_ips)
        bf_start = base_time + timedelta(minutes=rng.randint(5, 55))
        bf_rows = max(80, int(rows * 0.03))
        for i in range(bf_rows):
            offset = timedelta(seconds=i * 2 + rng.randint(0, 1))
            records.append({
                "datetime": (bf_start + offset).strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": bf_ip,
                "port_service": "TCP/22",
                "event_description": rng.choice(BRUTE_FORCE_EVENTS),
                "status": rng.choice(["DENIED", "ACCOUNT LOCKED"]),
                "log_type": "security",
            })

    rng.shuffle(records)
    df = pd.DataFrame(records)
    df = df.sort_values("datetime").reset_index(drop=True)
    return df


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate mock SAP security logs for development"
    )
    parser.add_argument("--rows", type=int, default=5000, help="Total log rows to generate")
    parser.add_argument("--attack-ratio", type=float, default=0.05, help="Fraction of attack traffic (0-1)")
    parser.add_argument("--out", type=str, default="data/samples/sample_logs.csv", help="Output CSV path")
    parser.add_argument("--with-spikes", action="store_true", help="Inject a spike attack from one IP")
    parser.add_argument("--with-brute-force", action="store_true", help="Inject a brute-force SSH attack")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    df = generate(
        rows=args.rows,
        attack_ratio=args.attack_ratio,
        with_spikes=args.with_spikes,
        with_brute_force=args.with_brute_force,
        seed=args.seed,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} rows to {out_path}")

    # Summary
    attack_count = len(df[df["log_type"] == "security"])
    unique_ips = df["source_ip"].nunique()
    print(f"  Normal: {len(df) - attack_count} | Attack: {attack_count} | Unique IPs: {unique_ips}")


if __name__ == "__main__":
    main()
