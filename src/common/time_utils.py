"""
time_utils.py
-------------
Datetime helpers. Always UTC, always tz-aware.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd


def utcnow() -> datetime:
    """Return the current UTC time as a tz-aware datetime."""
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Format a datetime as ISO-8601 with a ``Z`` suffix when in UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_log_datetime(value: object) -> datetime | None:
    """
    Parse a log timestamp into a tz-aware UTC datetime.

    Accepts:
    - ISO-8601 strings ("2026-04-04T14:45:01Z", "2026-04-04T14:45:01+00:00")
    - SAP sample CSV format ("2026-04-04 14:45:01")
    - pandas.Timestamp and datetime instances
    - None / NaN → returns None

    Naive datetimes are assumed to already be UTC.
    """
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime()
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    try:
        ts = pd.to_datetime(value, errors="coerce", utc=True)
    except (ValueError, TypeError):
        return None
    if ts is pd.NaT or pd.isna(ts):
        return None
    return ts.to_pydatetime()


def elapsed_ms(start: datetime, end: datetime | None = None) -> int:
    """
    Return the number of whole milliseconds between *start* and *end*.

    If *end* is omitted, uses :func:`utcnow`. Always returns a non-negative
    value — if *end* is before *start*, returns 0.
    """
    if end is None:
        end = utcnow()
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    delta_ms = int((end - start).total_seconds() * 1000)
    return max(delta_ms, 0)
