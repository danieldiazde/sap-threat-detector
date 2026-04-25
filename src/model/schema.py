"""
schema.py
---------
Single source of truth for the feature matrix and raw log schema.

Before this file existed, ``FEATURE_COLUMNS`` was defined independently in
``features.py``, ``train.py``, ``predict.py``, and the test module — and
they had already drifted. Every downstream file now imports from here.

Owner: AI & Data Science Specialist
"""

from __future__ import annotations

from typing import Final

import pandas as pd

# ─── Raw log columns expected from the SAP API / mock CSV ──────────────────
#
# If the SAP API response uses different names, adapt them inside
# ``src/ingestion/log_parser.py::normalize_columns`` — everywhere else in the
# codebase assumes this canonical shape.
REQUIRED_LOG_COLUMNS: Final[tuple[str, ...]] = (
    "datetime",
    "source_ip",
    "status",
    "event_description",
)

OPTIONAL_LOG_COLUMNS: Final[tuple[str, ...]] = (
    "port_service",
    "log_type",
    "request_path",
    "sap_application",
    "region_code",
    "macro_region",
    "http_method",
    "sap_source_type",
    "sap_app_env",
    "llm_total_tokens",
    "llm_cost_usd",
    "llm_finish_reason",
    "llm_status",
    "llm_response_time_ms",
    "llm_prompt_category",
    "llm_error_message",
    "llm_model_id",
    "llm_prompt_tokens",
)

ALL_LOG_COLUMNS: Final[tuple[str, ...]] = REQUIRED_LOG_COLUMNS + OPTIONAL_LOG_COLUMNS


# ─── Feature matrix columns (model input) ──────────────────────────────────
#
# Order matters: this is the column order the scaler was trained on.
# If you add/remove features, retrain the model via ``scripts/train_model.py``
# — the ``ModelRegistry`` will persist the feature list into the manifest so
# inference can detect drift.
FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "total_requests",
    "error_rate",
    "post_ratio",
    "unique_paths",
    "status_4xx_ratio",
    "status_5xx_ratio",
    "denied_ratio",
    "suspicious_path_ratio",
    "sql_injection_hits",
    "port_diversity",
    "brute_force_score",
    "interarrival_std",
    "request_rate_zscore",
    "app_diversity",
    "region_diversity",
    "is_destructive_ratio",
)

# Features available on pre-expansion rows (ingested before commit 5b5d777, 2026-04-21).
# app_diversity, region_diversity, and is_destructive_ratio all derive from expansion-only
# columns (sap_application, region_code, http_method) that are NULL on legacy rows.
# The legacy model trains exclusively on these 13 features to avoid zero-bias corruption.
_EXPANSION_ONLY_FEATURES: Final[frozenset[str]] = frozenset(
    {"app_diversity", "region_diversity", "is_destructive_ratio"}
)
FEATURE_COLUMNS_LEGACY: Final[tuple[str, ...]] = tuple(
    c for c in FEATURE_COLUMNS if c not in _EXPANSION_ONLY_FEATURES
)


# ─── Status code buckets ───────────────────────────────────────────────────
#
# The SAP sample logs use both numeric HTTP codes ("200", "404") *and* free-text
# statuses ("DENIED", "BLOCKED", "ACCOUNT LOCKED", "DROPPED"). The old code
# only handled numeric codes, so brute-force attempts registered as "no error".
# We map the text statuses to synthetic HTTP codes for consistent bucketing.
TEXT_STATUS_TO_CODE: Final[dict[str, int]] = {
    "DENIED": 401,
    "BLOCKED": 403,
    "ACCOUNT LOCKED": 423,
    "DROPPED": 444,
    "404 NOT FOUND": 404,
}

# Anything matching these text statuses counts towards the "denied" ratio
# in addition to the 4xx bucket.
DENIED_STATUSES: Final[frozenset[str]] = frozenset(
    {"DENIED", "BLOCKED", "ACCOUNT LOCKED", "DROPPED"}
)


# ─── Suspicious path fragments ─────────────────────────────────────────────
#
# Case-insensitive substrings that bump the ``suspicious_path_ratio`` feature.
SUSPICIOUS_PATH_FRAGMENTS: Final[tuple[str, ...]] = (
    "/cgi-bin/",
    "/phpmyadmin",
    "/wp-login",
    "/wp-admin",
    "/admin/",
    "/.env",
    "/.git/",
    "/etc/passwd",
    "/xmlrpc.php",
    "/shell.php",
)

# SQL injection keyword fragments (case-insensitive).
SQL_INJECTION_KEYWORDS: Final[tuple[str, ...]] = (
    "UNION SELECT",
    "OR 1=1",
    "' OR '",
    "--",
    "/*",
    "DROP TABLE",
    "INFORMATION_SCHEMA",
)

# Brute-force indicator keywords in the event description (case-insensitive).
BRUTE_FORCE_KEYWORDS: Final[tuple[str, ...]] = (
    "failed login",
    "brute force",
    "authentication attempt",
    "authentication failure",
)

# HTTP methods that modify or delete resources — used for is_destructive_ratio feature.
DESTRUCTIVE_METHODS: Final[frozenset[str]] = frozenset({"DELETE", "PUT", "PATCH"})


class InvalidLogSchemaError(ValueError):
    """Raised when a log DataFrame is missing required columns."""

    def __init__(self, missing: list[str], available: list[str]) -> None:
        self.missing = missing
        self.available = available
        super().__init__(
            f"Log DataFrame is missing required columns: {missing}. "
            f"Got: {available}. Fix in src/ingestion/log_parser.py::normalize_columns."
        )


def validate_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Verify that *df* has the required columns.

    Raises :class:`InvalidLogSchemaError` if any required column is missing.
    Returns the DataFrame unchanged on success (for chainable use).
    """

    if df.empty:
        return df

    missing = [c for c in REQUIRED_LOG_COLUMNS if c not in df.columns]
    if missing:
        raise InvalidLogSchemaError(missing=missing, available=list(df.columns))
    return df
