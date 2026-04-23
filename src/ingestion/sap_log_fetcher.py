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
from collections.abc import Awaitable, Callable
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
HTTP_TIMEOUT_SECONDS: float = 30.0  # raised from 10s — LLM payload pages are larger
RETRY_MAX_ATTEMPTS: int = 3
RETRY_BASE_DELAY: float = 0.5
RETRY_MAX_DELAY: float = 5.0
MAX_PAGES_PER_WINDOW: int = 200  # ~100k rows at page_size=500; circuit-breaker for runaway windows

# ─── Shared HTTP client ────────────────────────────────────────────────────
#
# httpx.AsyncClient opens a connection pool on first use -- sharing one
# across the process is 10-100x faster than constructing a new client per
# request. We close it explicitly via ``close_client()`` from the API
# lifespan context.
_client: httpx.AsyncClient | None = None
_last_window_start: str | None = None  # tracks the last fetched window


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


def reset_window_start() -> None:
    """
    Un-acknowledge the current window so the next cycle re-fetches it.

    Call this when processing fails after ``fetch_all_logs`` already committed
    ``_last_window_start`` — e.g. a HANA insert error or a predict failure.
    Without this, the window would be silently skipped for up to 30 minutes.
    """
    global _last_window_start
    _last_window_start = None


# ─── Public API ────────────────────────────────────────────────────────────


async def fetch_logs(page: int = 1) -> pd.DataFrame:
    """
    Fetch a single page of logs. Returns a normalized DataFrame with an
    ``ingested_at`` column stamped on every row.
    """
    if settings.mock_api:
        return _fetch_mock_logs()

    raw = await _get_with_retry(
        url=f"{settings.sap_api_url}/logs/current",
        headers={"Authorization": f"Bearer {settings.sap_api_key}"},
        params={"page": page, "page_size": settings.sap_api_page_size},
    )
    df = parse_raw_response(raw)
    return _stamp_ingested_at(df)


async def fetch_all_logs() -> pd.DataFrame:
    """
    Fetch every page of logs for the current 30-minute window.

    Calls /info first to check the window_start. If the window hasn't
    changed since the last fetch, returns an empty DataFrame immediately
    (saving 12 API calls and ~5,753 duplicate HANA inserts per skipped cycle).
    """
    global _last_window_start

    if settings.mock_api:
        return _fetch_mock_logs()

    # Check if the window has rolled over since our last fetch.
    headers = {"Authorization": f"Bearer {settings.sap_api_key}"}
    info = await _get_with_retry(
        url=f"{settings.sap_api_url}/info",
        headers=headers,
        params={},
    )
    window_start = info.get("window_start") if isinstance(info, dict) else None
    if window_start is not None and window_start == _last_window_start:
        logger.debug("fetcher.skip_duplicate_window", extra={"window_start": window_start})
        return pd.DataFrame()

    # NOTE: _last_window_start is committed AFTER the pagination loop, not here.
    # Committing early would permanently skip the window if any page fetch fails.

    ingested_at = utcnow()
    collected: list[pd.DataFrame] = []
    page = 1
    while True:
        raw = await _get_with_retry(
            url=f"{settings.sap_api_url}/logs/current",
            headers=headers,
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
        if page > MAX_PAGES_PER_WINDOW:
            logger.warning(
                "fetcher.max_pages_reached",
                extra={"max_pages": MAX_PAGES_PER_WINDOW, "window_start": window_start},
            )
            break

    # Commit only after all pages fetched successfully. If _get_with_retry raised
    # above, this line is never reached and the window stays unacknowledged so
    # the next 30-second cycle retries it from page 1.
    _last_window_start = window_start

    logger.info(
        "fetcher.window_fetched",
        extra={"window_start": window_start, "pages": page, "rows": sum(len(d) for d in collected)},
    )
    if not collected:
        return pd.DataFrame()
    return pd.concat(collected, ignore_index=True)


async def poll_logs(
    on_batch_received: _BatchCallback,
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
            except TimeoutError:
                pass
    finally:
        await close_client()
        logger.info("fetcher.poll.stopped")


# ─── Internal helpers ──────────────────────────────────────────────────────

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
        except httpx.ConnectError as exc:
            last_exc = exc
            _log_retry(attempt, exc)
            # Stale connection pool — recreate the client so the next retry
            # gets fresh connections rather than reusing broken ones.
            await close_client()
        except (httpx.TimeoutException, httpx.ReadError) as exc:
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

    assert last_exc is not None
    raise last_exc


def _log_retry(attempt: int, exc: Exception) -> None:
    logger.warning(
        "fetcher.retry",
        extra={"attempt": attempt, "max": RETRY_MAX_ATTEMPTS, "error": str(exc)},
    )


def _has_next_page(raw: object, current_page: int) -> bool:
    """Detect pagination continuation from the SAP API response envelope.

    The API returns top-level fields: current_page, total_pages, records_in_page,
    batch_size. Falls back to nested pagination dict for other API shapes.
    """
    if not isinstance(raw, dict):
        return False
    # SAP API: top-level total_pages
    total_pages = raw.get("total_pages")
    if total_pages is not None:
        try:
            return current_page < int(total_pages)
        except (ValueError, TypeError):
            logger.warning("fetcher.invalid_total_pages", extra={"value": total_pages})
            return False
    # Fallback: next_page pointer
    if raw.get("next_page") is not None:
        return True
    # Fallback: nested pagination object
    pagination = raw.get("pagination") or {}
    if isinstance(pagination, dict):
        nested_total = pagination.get("total_pages")
        if nested_total is not None:
            try:
                return current_page < int(nested_total)
            except (ValueError, TypeError):
                logger.warning("fetcher.invalid_total_pages", extra={"value": nested_total})
                return False
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
