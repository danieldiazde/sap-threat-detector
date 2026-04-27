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
    # log_id — Elasticsearch/SAP API per-row primary key, used for dedup.
    "_id": "log_id",
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
    # request_path — SAP API has a typo: "heathers_" instead of "headers_"
    "heathers_request_path": "request_path",
    "headers_request_path": "request_path",
    # sap_application
    "sap_function_application": "sap_application",
    # http_method
    "headers_http_request_method": "http_method",
    # region_code, macro_region, sap_source_type, sap_app_env, llm_* already match canonical names
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
            logger.warning(
                "parse_raw_response.unknown_envelope",
                extra={"actual_keys": list(payload.keys())},
            )
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
    Rename columns to the canonical schema using :data:`_COLUMN_ALIASES`,
    then normalize values to remove known noise sources.

    Value normalization:
    - ``status``: strip a trailing ``.0`` so float-coerced numeric codes
      (``"200.0"``) collapse onto their integer form (``"200"``).
    - ``log_type``: uppercase, so ``"access"``/``"AUDIT"``/``"security"``
      collapse onto a single canonical bucket.

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

    if "status" in df.columns:
        s = df["status"].astype(str).str.strip()
        # "200.0" → "200" but leave non-numeric tokens alone ("DENIED", "")
        df["status"] = s.str.replace(r"^(\d+)\.0+$", r"\1", regex=True)

    if "log_type" in df.columns:
        df["log_type"] = df["log_type"].astype(str).str.strip().str.upper()

    return df


# validate_schema is imported from src.model.schema (defined there to avoid circular imports)
