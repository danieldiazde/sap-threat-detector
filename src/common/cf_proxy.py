"""
cf_proxy.py
-----------
Cloud Foundry Connectivity Service proxy helpers.

When the app is bound to the `connectivity` CF service, all outbound traffic
that would otherwise be blocked by the CF trial network policy can be routed
through the Cloud Connector tunnel:

  CF App → Connectivity proxy (internal CF) → Cloud Connector agent → target

The proxy requires a short-lived OAuth token from UAA.  We cache it in a
module-level variable and refresh only when it is missing (process restart
is the normal refresh path; tokens last ~12h).

Usage:
  from src.common.cf_proxy import get_hdbcli_proxy_kwargs, get_httpx_proxy_url
"""

from __future__ import annotations

import urllib.parse

import httpx

from src.common.config import settings
from src.common.logging import get_logger

logger = get_logger(__name__)

_cached_token: str = ""


def _ensure_token() -> str:
    """Return a valid UAA token, fetching one if the cache is empty.

    Sync, safe to call from a thread (used by hdbcli path via asyncio.to_thread).
    """
    global _cached_token
    if _cached_token:
        return _cached_token

    token_url = f"{settings.cf_proxy_token_url}/oauth/token"
    logger.info("cf_proxy.token_fetch", extra={"url": token_url})
    try:
        resp = httpx.post(
            token_url,
            params={"grant_type": "client_credentials", "response_type": "token"},
            auth=(settings.cf_proxy_client_id, settings.cf_proxy_client_secret),
            timeout=10.0,
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("cf_proxy.token_fetch_failed", extra={"error": str(exc)})
        raise
    _cached_token = resp.json()["access_token"]
    logger.info("cf_proxy.token_fetched")
    return _cached_token


def get_hdbcli_proxy_kwargs() -> dict:
    """Return proxy kwargs for hdbcli ``dbapi.connect()``.

    Returns an empty dict when the connectivity proxy is not configured so
    callers can do ``dbapi.connect(**base_kwargs, **get_hdbcli_proxy_kwargs())``.
    """
    if not settings.cf_proxy_enabled:
        return {}
    token = _ensure_token()
    return {
        "proxyHost": settings.cf_proxy_host,
        "proxyPort": settings.cf_proxy_port,
        "proxyUserName": settings.cf_proxy_client_id,
        "proxyPassword": token,
    }


def get_httpx_proxy_url() -> str | None:
    """Return an ``http://user:token@host:port`` proxy URL for httpx.

    Returns ``None`` when the connectivity proxy is not configured.
    Token is URL-encoded so special characters in access tokens are safe.
    """
    if not settings.cf_proxy_enabled:
        return None
    token = _ensure_token()
    cid = urllib.parse.quote(settings.cf_proxy_client_id, safe="")
    tok = urllib.parse.quote(token, safe="")
    return f"http://{cid}:{tok}@{settings.cf_proxy_host}:{settings.cf_proxy_port}"
