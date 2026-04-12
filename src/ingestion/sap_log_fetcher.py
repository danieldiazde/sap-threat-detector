"""
sap_log_fetcher.py
------------------
OBSERVE phase — paginated ingestion of security logs from the SAP API.

Ingestion is async and auto-retried on transient errors. Until
``SAP_API_URL`` is set, the fetcher returns rows from the local mock CSV
so the rest of the pipeline can run end-to-end before April 13.

Every returned batch carries an ``ingested_at`` timestamp so downstream
code (``predict``, ``pipeline``) can compute the pipeline MTTD.

Owner: Data Architect & Backend Developer
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime
from pathlib import Path

import httpx
import pandas as pd

from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow
from src.ingestion.log_parser import normalize_columns, parse_raw_response

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

MOCK_DATA_PATH: Path = Path("data/samples/sample_logs.csv")
HTTP_TIMEOUT_SECONDS: float = 10.0
RETRY_MAX_ATTEMPTS: int = 3
RETRY_BASE_DELAY: float = 0.5
RETRY_MAX_DELAY: float = 5.0

# ─── Shared HTTP client ────────────────────────────────────────────────────
#
# httpx.AsyncClient opens a connection pool on first use — sharing one
# across the process is 10-100× faster than constructing a new client per
# request. We close it explicitly via ``close_client()`` from the API
# lifespan context.
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)
    return _client


async def close_client() -> None:
    """Close the shared httpx client. Called at pipeline shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# ─── Public API ────────────────────────────────────────────────────────────


async def fetch_logs(page: int = 1) -> pd.DataFrame:
    """
    Fetch a single page of logs. Returns a normalized DataFrame with an
    ``ingested_at`` column stamped on every row.
    """
    if settings.mock_api:
        return _fetch_mock_logs()

    raw = await _get_with_retry(
        url=settings.sap_api_url,
        headers={"Authorization": f"Bearer {settings.sap_api_key}"},
        params={"page": page, "page_size": settings.sap_api_page_size},
    )
    df = parse_raw_response(raw)
    return _stamp_ingested_at(df)


async def fetch_all_logs() -> pd.DataFrame:
    """
    Fetch every page of logs by following the ``next_page`` envelope field.

    Falls back to "stop when page is empty" if the API doesn't expose
    next-page metadata. This preserves ``ingested_at`` — the timestamp is
    captured once at the start of the pagination loop so every row in the
    final concatenated batch shares the same ``ingested_at`` (the moment
    the pipeline started reading).
    """
    if settings.mock_api:
        return _fetch_mock_logs()

    ingested_at = utcnow()
    collected: list[pd.DataFrame] = []
    page = 1
    while True:
        raw = await _get_with_retry(
            url=settings.sap_api_url,
            headers={"Authorization": f"Bearer {settings.sap_api_key}"},
            params={"page": page, "page_size": settings.sap_api_page_size},
        )
        df = parse_raw_response(raw)
        if df.empty:
            break
        df["ingested_at"] = ingested_at
        collected.append(df)

        if not _has_next_page(raw, page):
            break
        page += 1

    if not collected:
        return pd.DataFrame()
    return pd.concat(collected, ignore_index=True)


async def poll_logs(
    on_batch_received: "_BatchCallback",
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    """
    Continuously poll the SAP API and call *on_batch_received* for each
    non-empty batch. Cleanly exits when *stop_event* is set.
    """
    interval = settings.poll_interval_seconds
    logger.info(
        "fetcher.poll.start",
        extra={"interval_s": interval, "mock": settings.mock_api},
    )
    try:
        while stop_event is None or not stop_event.is_set():
            try:
                df = await fetch_all_logs()
                if not df.empty:
                    await on_batch_received(df)
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("fetcher.poll.error", extra={"error": str(exc)})

            try:
                if stop_event is None:
                    await asyncio.sleep(interval)
                else:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
    finally:
        await close_client()
        logger.info("fetcher.poll.stopped")


# ─── Internal helpers ──────────────────────────────────────────────────────

# Callback signature: ``async def handler(df: pd.DataFrame) -> None``
from typing import Awaitable, Callable

_BatchCallback = Callable[[pd.DataFrame], Awaitable[None]]


async def _get_with_retry(
    *, url: str, headers: dict[str, str], params: dict[str, object]
) -> object:
    """GET *url* with exponential-backoff retry on transient errors."""
    last_exc: Exception | None = None
    for attempt in range(1, RETRY_MAX_ATTEMPTS + 1):
        try:
            client = _get_client()
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as exc:
            last_exc = exc
            _log_retry(attempt, exc)
        except httpx.HTTPStatusError as exc:
            # Retry 5xx / 429; fail-fast on other 4xx.
            status = exc.response.status_code
            if status >= 500 or status == 429:
                last_exc = exc
                _log_retry(attempt, exc)
            else:
                logger.error(
                    "fetcher.http_error_fatal",
                    extra={"status": status, "url": url},
                )
                raise

        if attempt < RETRY_MAX_ATTEMPTS:
            delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
            delay *= 0.5 + random.random()  # jitter, 0.5x..1.5x
            await asyncio.sleep(delay)

    assert last_exc is not None  # noqa: S101 — for the type checker
    raise last_exc


def _log_retry(attempt: int, exc: Exception) -> None:
    logger.warning(
        "fetcher.retry",
        extra={"attempt": attempt, "max": RETRY_MAX_ATTEMPTS, "error": str(exc)},
    )


def _has_next_page(raw: object, current_page: int) -> bool:
    """Best-effort detection of pagination continuation."""
    if not isinstance(raw, dict):
        return False
    if raw.get("next_page") is not None:
        return True
    pagination = raw.get("pagination") or {}
    if isinstance(pagination, dict):
        total_pages = pagination.get("total_pages")
        if total_pages is not None:
            return current_page < int(total_pages)
        if pagination.get("has_more") is True:
            return True
    return False


def _stamp_ingested_at(df: pd.DataFrame, at: datetime | None = None) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    df["ingested_at"] = at or utcnow()
    return df


def _fetch_mock_logs() -> pd.DataFrame:
    """Load the sample CSV and normalize it to the canonical schema."""
    if not MOCK_DATA_PATH.exists():
        logger.warning("fetcher.mock.missing", extra={"path": str(MOCK_DATA_PATH)})
        return pd.DataFrame()

    df = pd.read_csv(MOCK_DATA_PATH)
    df = normalize_columns(df)
    return _stamp_ingested_at(df)
