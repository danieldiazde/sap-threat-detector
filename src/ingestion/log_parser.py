"""
log_parser.py
-------------
Pure parsing / normalization / validation of raw SAP log payloads.

Keeping this logic separate from ``sap_log_fetcher.py`` means the April 13
schema adaptation is a one-function change. The async fetcher just calls
``parse_raw_response(payload) -> DataFrame`` and every downstream module
assumes the canonical schema from ``src/model/schema.py``.

Owner: Data Architect & Backend Developer
"""

from __future__ import annotations

from typing import Any

import pandas as pd
from src.common.logging import get_logger
from src.model.schema import (
    ALL_LOG_COLUMNS,
)

logger = get_logger(__name__)


# ─── Column aliases ────────────────────────────────────────────────────────
#
# Maps candidate SAP field names → our canonical names. Extend this map on
# April 13 once we see the real API response. The normalization function
# is case-insensitive.
_COLUMN_ALIASES: dict[str, str] = {
    # datetime
    "@timestamp": "datetime",
    "timestamp": "datetime",
    "time": "datetime",
    "event_time": "datetime",
    "logged_at": "datetime",
    # source_ip
    "client_ip": "source_ip",
    "ip": "source_ip",
    "src_ip": "source_ip",
    "remote_addr": "source_ip",
    "sourceip": "source_ip",
    # status  — real API sends "http_status_code"
    "http_status_code": "status",
    "status_code": "status",
    "response_status": "status",
    "http_status": "status",
    # event_description  — real API sends "sap_function_message"
    "sap_function_message": "event_description",
    "message": "event_description",
    "description": "event_description",
    "event": "event_description",
    "log_message": "event_description",
    # port_service  — real API sends "service_id"
    "service_id": "port_service",
    "port": "port_service",
    "service": "port_service",
    "protocol": "port_service",
    # log_type  — real API sends "sap_function_log_type"
    "sap_function_log_type": "log_type",
    "type": "log_type",
    "category": "log_type",
    "source": "log_type",
}


def parse_raw_response(payload: Any) -> pd.DataFrame:
    """
    Convert a raw SAP API JSON payload into a normalized DataFrame.

    The SAP API is expected to return either:
    - ``{"logs": [...]}`` (wrapped), or
    - ``[...]`` (bare array of log objects).

    After April 13 this may need tweaking — adapt inside this function.
    """
    if payload is None:
        return pd.DataFrame()

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        # Try common envelope keys in order.
        for key in ("logs", "data", "items", "records", "results"):
            if key in payload and isinstance(payload[key], list):
                records = payload[key]
                break
        else:
            logger.warning("parse_raw_response: no known envelope key in payload")
            return pd.DataFrame()
    else:
        logger.warning(
            "parse_raw_response: unexpected payload type",
            extra={"payload_type": type(payload).__name__},
        )
        return pd.DataFrame()

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df = normalize_columns(df)
    return df


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Rename columns to the canonical schema using :data:`_COLUMN_ALIASES`.

    Matching is case-insensitive. Columns already in canonical form pass
    through unchanged. Extra columns are preserved (we only rename, never
    drop — downstream code selects what it needs).
    """
    if df.empty:
        return df

    canonical = set(ALL_LOG_COLUMNS)
    rename_map: dict[str, str] = {}
    for col in df.columns:
        if col in canonical:
            continue
        alias_target = _COLUMN_ALIASES.get(col.lower())
        if alias_target and alias_target not in df.columns:
            rename_map[col] = alias_target

    if rename_map:
        df = df.rename(columns=rename_map)
        logger.debug("normalize_columns: renamed", extra={"rename_map": rename_map})

    return df


# validate_schema is imported from src.model.schema (defined there to avoid circular imports)
