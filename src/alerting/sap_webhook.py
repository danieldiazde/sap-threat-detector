"""
sap_webhook.py
--------------
RESPOND phase — fire alerts to the SAP alerting webhook.

Design:
- HMAC-SHA256 signature on every outbound payload (when the secret is set)
- Idempotency key (``alert_id``) prevents duplicate server-side processing
- Short-circuit via :class:`AlertDeduper` to avoid alert storms
- Exponential-backoff retry with max 3 attempts on 5xx / network errors
- Shared ``httpx.AsyncClient`` for connection reuse

Until April 27, ``SAP_WEBHOOK_URL`` is empty so ``_mock_alert`` logs the
payload to stdout instead of firing. No code change is needed to switch.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
from typing import Any

import httpx
import pandas as pd

from src.alerting.deduplication import deduper
from src.common.config import settings
from src.common.logging import get_logger
from src.common.metrics import metrics
from src.common.time_utils import iso, utcnow

logger = get_logger(__name__)

# ─── Constants ─────────────────────────────────────────────────────────────

HTTP_TIMEOUT_SECONDS: float = 10.0
RETRY_MAX_ATTEMPTS: int = 3
RETRY_BASE_DELAY: float = 0.5
RETRY_MAX_DELAY: float = 5.0
EVIDENCE_SAMPLE_SIZE: int = 5


# ─── Shared client ─────────────────────────────────────────────────────────
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# ─── Public API ────────────────────────────────────────────────────────────


async def send_alert(anomaly_row: dict[str, Any], evidence_df: pd.DataFrame) -> bool:
    """
    Fire a threat alert for *anomaly_row*, suppressing duplicates.

    Returns True if the alert was sent (mock or real) or deduplicated,
    False if a real send attempt failed.
    """
    if not deduper.should_fire(anomaly_row):
        metrics.incr_alerts_suppressed()
        logger.info(
            "webhook.suppressed",
            extra={
                "source_ip": anomaly_row.get("source_ip"),
                "threat_level": anomaly_row.get("threat_level"),
            },
        )
        return True

    payload = _build_payload(anomaly_row, evidence_df)

    if settings.mock_webhook:
        _mock_alert(payload)
        metrics.incr_alerts_sent()
        return True

    success = await _send_with_retry(payload)
    if success:
        metrics.incr_alerts_sent()
    else:
        metrics.incr_alerts_failed()
    return success


# ─── Payload construction ──────────────────────────────────────────────────


def _build_payload(anomaly_row: dict[str, Any], evidence_df: pd.DataFrame) -> dict[str, Any]:
    detected_at = anomaly_row.get("detected_at") or utcnow()
    source_ip = str(anomaly_row.get("source_ip", "unknown"))
    threat_level = str(anomaly_row.get("threat_level", "high"))
    alert_id = _alert_id(source_ip, threat_level, detected_at)

    return {
        "alert_id": alert_id,
        "team_id": settings.sap_team_id,
        "detected_at": iso(detected_at) if hasattr(detected_at, "isoformat") else str(detected_at),
        "source_ip": source_ip,
        "threat_level": threat_level,
        "anomaly_score": float(anomaly_row.get("anomaly_score", 0) or 0),
        "pipeline_mttd_ms": int(anomaly_row.get("pipeline_mttd_ms", 0) or 0),
        "e2e_mttd_ms": _int_or_none(anomaly_row.get("e2e_mttd_ms")),
        "model_version": str(anomaly_row.get("model_version", "unknown")),
        "model_type": str(anomaly_row.get("model_type", "isolation_forest")),
        "evidence": {
            "total_requests": int(anomaly_row.get("total_requests", 0) or 0),
            "error_rate": float(anomaly_row.get("error_rate", 0) or 0),
            "denied_ratio": float(anomaly_row.get("denied_ratio", 0) or 0),
            "post_ratio": float(anomaly_row.get("post_ratio", 0) or 0),
            "suspicious_path_ratio": float(anomaly_row.get("suspicious_path_ratio", 0) or 0),
            "sql_injection_hits": int(anomaly_row.get("sql_injection_hits", 0) or 0),
            "brute_force_score": float(anomaly_row.get("brute_force_score", 0) or 0),
            "multi_bucket_count": int(anomaly_row.get("multi_bucket_count", 0) or 0),
            "log_sample": _evidence_sample(evidence_df),
        },
    }


def _alert_id(source_ip: str, threat_level: str, detected_at: Any) -> str:
    """
    Deterministic alert ID for idempotency.

    Rounded to the minute so retries within the same minute share the
    same ID and the SAP webhook can deduplicate server-side.
    """
    if hasattr(detected_at, "strftime"):
        minute = detected_at.strftime("%Y%m%dT%H%M")
    else:
        minute = str(detected_at)[:16]
    raw = f"{source_ip}|{threat_level}|{minute}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _evidence_sample(df: pd.DataFrame) -> list[dict[str, Any]]:
    if df is None or df.empty:
        return []
    head = df.head(EVIDENCE_SAMPLE_SIZE).copy()
    for col in head.columns:
        if pd.api.types.is_datetime64_any_dtype(head[col]):
            head[col] = head[col].astype(str)
    return head.to_dict(orient="records")


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ─── Sending with retry ────────────────────────────────────────────────────


async def _send_with_retry(payload: dict[str, Any]) -> bool:
    last_error: str | None = None
    for attempt in range(1, RETRY_MAX_ATTEMPTS + 1):
        try:
            await _send_once(payload)
            logger.info(
                "webhook.sent",
                extra={
                    "alert_id": payload["alert_id"],
                    "source_ip": payload["source_ip"],
                    "threat_level": payload["threat_level"],
                    "attempt": attempt,
                },
            )
            return True
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            last_error = f"HTTP {status}"
            if status < 500 and status != 429:
                logger.error(
                    "webhook.fatal_http",
                    extra={"status": status, "alert_id": payload["alert_id"]},
                )
                return False
            logger.warning(
                "webhook.retry",
                extra={"attempt": attempt, "status": status, "alert_id": payload["alert_id"]},
            )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as exc:
            last_error = str(exc)
            logger.warning(
                "webhook.retry",
                extra={"attempt": attempt, "error": str(exc), "alert_id": payload["alert_id"]},
            )

        if attempt < RETRY_MAX_ATTEMPTS:
            delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
            delay *= 0.5 + random.random()
            await asyncio.sleep(delay)

    logger.error(
        "webhook.failed",
        extra={"alert_id": payload["alert_id"], "error": last_error},
    )
    return False


async def _send_once(payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-SAP-Team-ID": settings.sap_team_id,
        "X-Alert-ID": payload["alert_id"],
    }
    if settings.sap_webhook_secret:
        signature = hmac.new(
            settings.sap_webhook_secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        headers["X-SAP-Signature"] = signature

    client = _get_client()
    response = await client.post(
        settings.sap_webhook_url,
        content=body,
        headers=headers,
    )
    response.raise_for_status()


def _mock_alert(payload: dict[str, Any]) -> None:
    logger.info(
        "webhook.mock",
        extra={
            "alert_id": payload["alert_id"],
            "source_ip": payload["source_ip"],
            "threat_level": payload["threat_level"],
            "anomaly_score": payload["anomaly_score"],
            "pipeline_mttd_ms": payload["pipeline_mttd_ms"],
        },
    )
