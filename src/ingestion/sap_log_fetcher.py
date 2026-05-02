"""
sap_log_fetcher.py
------------------
OBSERVE phase — paginated ingestion of security logs from the SAP API.

Ingestion is async and auto-retried on transient errors. When ``SAP_API_URL``
is unset, the fetcher returns rows from the local mock CSV so the pipeline
can run end-to-end without the live API.

Every returned batch carries an ``ingested_at`` timestamp so downstream
code (``predict``, ``pipeline``) can compute the pipeline MTTD.
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

    Per the spec, clients only send ``page`` — server controls batch size.
    """
    if settings.mock_api:
        return _fetch_mock_logs()

    raw = await _get_with_retry(
        url=f"{settings.sap_api_url}/logs/current",
        headers={"Authorization": f"Bearer {settings.sap_api_key}"},
        params={"page": page},
    )
    df = parse_raw_response(raw)
    return _stamp_ingested_at(df)


async def fetch_info() -> dict[str, object]:
    """
    Fetch ``/info`` for the current SAP window.

    Returns the parsed JSON dict, or ``{}`` when the API is unreachable
    (spec status 503 = "data not loaded yet"). Mock mode returns ``{}``.

    Used by :func:`fetch_all_logs` to drive the page loop and by the
    conversational agent's ``get_current_window_info`` tool.
    """
    if settings.mock_api:
        return {}
    headers = {"Authorization": f"Bearer {settings.sap_api_key}"}
    info = await _get_with_retry(
        url=f"{settings.sap_api_url}/info",
        headers=headers,
        params={},
        non_fatal_statuses=(503,),
    )
    if not isinstance(info, dict):
        return {}
    return info


async def fetch_all_logs() -> pd.DataFrame:
    """
    Fetch every page of logs for the current 30-minute window.

    Spec-driven loop:
    1. ``GET /info`` — read ``total_pages`` and ``window_start``.
    2. If ``window_start`` matches our last successful fetch, skip.
    3. Iterate ``GET /logs/current?page=1..total_pages``.

    Status-code handling per spec:
    - ``503`` on /info or /logs/current → "data not loaded yet". Return an
      empty frame; the next 30-second poll will retry without raising.
    - ``422`` on /logs/current → "page out of range". Treat as end-of-loop
      (defensive: should be unreachable since we drive from total_pages).
    """
    global _last_window_start

    if settings.mock_api:
        return _fetch_mock_logs()

    headers = {"Authorization": f"Bearer {settings.sap_api_key}"}

    # Step 1: /info — also tells us if the window rolled.
    info = await fetch_info()
    if not info:
        logger.info("fetcher.info_unavailable")
        return pd.DataFrame()

    window_start = info.get("window_start")
    if window_start is not None and window_start == _last_window_start:
        logger.debug("fetcher.skip_duplicate_window", extra={"window_start": window_start})
        return pd.DataFrame()

    try:
        total_pages = int(info.get("total_pages", 0) or 0)
    except (TypeError, ValueError):
        logger.warning("fetcher.invalid_total_pages", extra={"value": info.get("total_pages")})
        return pd.DataFrame()

    if total_pages <= 0:
        logger.info("fetcher.empty_window", extra={"window_start": window_start})
        _last_window_start = window_start
        return pd.DataFrame()

    if total_pages > MAX_PAGES_PER_WINDOW:
        logger.warning(
            "fetcher.max_pages_clamped",
            extra={"requested": total_pages, "max": MAX_PAGES_PER_WINDOW},
        )
        total_pages = MAX_PAGES_PER_WINDOW

    # Step 2: deterministic page loop.
    ingested_at = utcnow()
    collected: list[pd.DataFrame] = []
    pages_fetched = 0
    for page in range(1, total_pages + 1):
        raw = await _get_with_retry(
            url=f"{settings.sap_api_url}/logs/current",
            headers=headers,
            params={"page": page},
            non_fatal_statuses=(422, 503),
        )
        if raw is None:
            # 422 (out of range) or 503 (not loaded) — stop iterating; the
            # rows we already have are still valid for this window.
            logger.info("fetcher.page_skipped", extra={"page": page})
            break
        pages_fetched += 1
        df = parse_raw_response(raw)
        if df.empty:
            continue
        df["ingested_at"] = ingested_at
        collected.append(df)

    # Commit window_start only after the loop completes (success or graceful
    # break). If _get_with_retry raised on a fatal status / network error,
    # this line is never reached and the next cycle retries from page 1.
    _last_window_start = window_start

    logger.info(
        "fetcher.window_fetched",
        extra={
            "window_start": window_start,
            "pages_expected": total_pages,
            "pages_fetched": pages_fetched,
            "rows": sum(len(d) for d in collected),
        },
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
    *,
    url: str,
    headers: dict[str, str],
    params: dict[str, object],
    non_fatal_statuses: tuple[int, ...] = (),
) -> object:
    """GET *url* with exponential-backoff retry on transient errors.

    Status codes in *non_fatal_statuses* short-circuit to ``None`` instead of
    raising. Used by callers that want spec-defined codes (e.g., 503 on
    /info, 422 on /logs/current page-out-of-range) to be treated as
    "no data this cycle" rather than pipeline errors.
    """
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
            status = exc.response.status_code
            if status in non_fatal_statuses:
                logger.info(
                    "fetcher.http_non_fatal",
                    extra={"status": status, "url": url},
                )
                return None
            # Retry 5xx / 429; fail-fast on other 4xx.
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
