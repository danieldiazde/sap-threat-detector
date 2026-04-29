"""
sap_webhook.py
--------------
RESPOND phase — fire alerts to the SAP SOC ``POST /alert`` endpoint.

Spec contract (see memory/project_sap_api_spec.md):
- ``POST {SAP_API_URL}/alert`` with header ``Authorization: Bearer <SAP_API_KEY>``
- Body is exactly ``{"message": "<= 300 char string"}``. The team is identified
  from the Bearer token; no other fields are accepted.
- The message must answer WHAT happened, WHEN it occurred, WHY it triggered.
- Success returns 201 with ``{status, team_name, message, timestamp_utc}``.

Local design:
- Client-side TTL dedup via :class:`AlertDeduper` to avoid alert storms.
- Exponential-backoff retry with max 3 attempts on 5xx / network errors.
- Shared ``httpx.AsyncClient`` for connection reuse.
- ``build_alert_id`` is still produced for our internal ``ANOMALIES.ALERT_ID``
  identity; it does not travel on the wire.

When ``SAP_API_URL`` is empty the fetcher / alerter run in mock mode and the
payload is logged locally instead of sent.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import asyncio
import hashlib
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

# Spec: message max length is 300 characters.
MESSAGE_MAX_CHARS: int = 300


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

    message = format_alert_message(anomaly_row, evidence_df)
    payload = {"message": message}

    if settings.mock_webhook:
        _mock_alert(anomaly_row, message)
        metrics.incr_alerts_sent()
        return True

    success = await _send_with_retry(payload, anomaly_row)
    if success:
        metrics.incr_alerts_sent()
    else:
        metrics.incr_alerts_failed()
    return success


# ─── Message construction ──────────────────────────────────────────────────


def format_alert_message(anomaly_row: dict[str, Any], evidence_df: pd.DataFrame) -> str:
    """
    Build the WHAT / WHEN / WHY string the spec requires (≤300 chars).

    The "why" section is selected from the strongest evidence signal so judges
    see the most relevant indicator first. Long fields are trimmed before the
    final truncation so we lose detail (not structure) when we hit the cap.
    """
    what = _what_clause(anomaly_row)
    when = _when_clause(anomaly_row)
    why = _why_clause(anomaly_row, evidence_df)

    msg = f"WHAT: {what} WHEN: {when} WHY: {why}"
    if len(msg) > MESSAGE_MAX_CHARS:
        # Hard cap — keep the WHAT/WHEN intact, truncate the WHY tail.
        head = f"WHAT: {what} WHEN: {when} WHY: "
        budget = MESSAGE_MAX_CHARS - len(head)
        msg = (
            msg[:MESSAGE_MAX_CHARS]
            if budget < 1
            else head + why[: max(budget - 1, 0)] + "."
        )
    return msg


def _what_clause(anomaly_row: dict[str, Any]) -> str:
    """Pick the most specific threat label available, fall back to a generic."""
    if str(anomaly_row.get("detector", "sap")).lower() == "llm":
        return _llm_what_clause(anomaly_row)

    sql_hits = int(anomaly_row.get("sql_injection_hits", 0) or 0)
    brute_score = float(anomaly_row.get("brute_force_score", 0) or 0)
    suspicious = float(anomaly_row.get("suspicious_path_ratio", 0) or 0)
    threat_level = str(anomaly_row.get("threat_level", "anomaly")).lower()
    target = _target_label(anomaly_row)

    if sql_hits > 0:
        kind = "SQL injection attempt"
    elif brute_score >= 0.2:
        kind = "Brute-force login attempt"
    elif suspicious >= 0.3:
        kind = "Suspicious path scanning"
    else:
        kind = f"{threat_level.title()} anomaly"

    return f"{kind} on {target}."


def _llm_what_clause(anomaly_row: dict[str, Any]) -> str:
    rule_label = _first_rule_label(anomaly_row)
    threat_level = str(anomaly_row.get("threat_level", "anomaly")).lower()
    model = str(anomaly_row.get("llm_model_id", "unknown"))
    category = str(anomaly_row.get("llm_prompt_category", "unknown"))
    kind = rule_label or f"{threat_level.title()} LLM cohort anomaly"
    return f"{kind} on LLM {model}/{category}."


def _first_rule_label(anomaly_row: dict[str, Any]) -> str | None:
    raw = anomaly_row.get("rule_ids")
    if not raw:
        return None
    try:
        ids = json.loads(raw) if isinstance(raw, str) else list(raw)
    except (ValueError, TypeError):
        return None
    if not ids:
        return None
    return _RULE_LABELS.get(str(ids[0]), str(ids[0]))


_RULE_LABELS: dict[str, str] = {
    "LLM_TOKEN_HIGH": "LLM token-budget anomaly",
    "LLM_HIGH_COST_OUTLIER": "LLM high-cost outlier",
    "LLM_NEAR_TIMEOUT": "LLM near-timeout pattern",
    "LLM_ERROR_STORM": "LLM error storm",
    "LLM_CONTENT_FILTER_SPIKE": "LLM content-filter spike",
    "LLM_EXFIL_SHAPE": "LLM exfiltration-shape pattern",
}


def _when_clause(anomaly_row: dict[str, Any]) -> str:
    detected_at = anomaly_row.get("detected_at") or utcnow()
    if hasattr(detected_at, "isoformat"):
        return f"{iso(detected_at)}."
    return f"{detected_at!s}."


def _why_clause(anomaly_row: dict[str, Any], evidence_df: pd.DataFrame) -> str:
    if str(anomaly_row.get("detector", "sap")).lower() == "llm":
        return _llm_why_clause(anomaly_row)

    total = int(anomaly_row.get("total_requests", 0) or 0)
    error_rate = float(anomaly_row.get("error_rate", 0) or 0)
    denied = float(anomaly_row.get("denied_ratio", 0) or 0)
    sql_hits = int(anomaly_row.get("sql_injection_hits", 0) or 0)
    brute_score = float(anomaly_row.get("brute_force_score", 0) or 0)
    score = float(anomaly_row.get("anomaly_score", 0) or 0)
    source_ip = str(anomaly_row.get("source_ip", "unknown"))

    parts: list[str] = []
    if sql_hits > 0:
        parts.append(f"{sql_hits} SQLi hits")
    if brute_score >= 0.2:
        parts.append(f"brute_score={brute_score:.2f}")
    if error_rate >= 0.3:
        parts.append(f"err_rate={error_rate:.0%}")
    if denied >= 0.3:
        parts.append(f"denied={denied:.0%}")
    if total:
        parts.append(f"{total} reqs")
    parts.append(f"score={score:.2f}")

    window = _evidence_window(evidence_df)
    head = ", ".join(parts)
    if window:
        return f"{head} from IP {source_ip} {window}."
    return f"{head} from IP {source_ip}."


def _llm_why_clause(anomaly_row: dict[str, Any]) -> str:
    total = int(anomaly_row.get("total_requests", 0) or 0)
    global_frac = float(anomaly_row.get("global_anomaly_fraction", 0) or 0)
    cat_frac = float(anomaly_row.get("category_anomaly_fraction", 0) or 0)
    score = float(anomaly_row.get("anomaly_score", 0) or 0)
    rule_ids: list[str] = []
    raw = anomaly_row.get("rule_ids")
    if raw:
        try:
            rule_ids = json.loads(raw) if isinstance(raw, str) else list(raw)
        except (ValueError, TypeError):
            rule_ids = []
    parts: list[str] = []
    if rule_ids:
        parts.append("rules=" + ",".join(rule_ids[:3]))
    parts.append(f"global_anom={global_frac:.0%}")
    if cat_frac:
        parts.append(f"cat_anom={cat_frac:.0%}")
    parts.append(f"{total} reqs")
    parts.append(f"score={score:.2f}")
    return ", ".join(parts) + "."


_TARGET_LABEL_MAX = 80


def _target_label(anomaly_row: dict[str, Any]) -> str:
    """Prefer SAP application name (richer signal); fall back to source IP.

    Capped so a malformed ``sap_application`` cannot blow past the 300-char
    message budget on its own.
    """
    app = anomaly_row.get("sap_application")
    label = str(app) if app else f"IP {anomaly_row.get('source_ip', 'unknown')}"
    if len(label) > _TARGET_LABEL_MAX:
        label = label[: _TARGET_LABEL_MAX - 1] + "…"
    return label


def _evidence_window(evidence_df: pd.DataFrame) -> str:
    """Return a short ``within Xs`` / ``within Xm`` span from the evidence rows."""
    if evidence_df is None or evidence_df.empty or "datetime" not in evidence_df.columns:
        return ""
    times = pd.to_datetime(evidence_df["datetime"], errors="coerce", utc=True).dropna()
    if len(times) < 2:
        return ""
    span_s = (times.max() - times.min()).total_seconds()
    if span_s < 60:
        return f"within {int(span_s)}s"
    return f"within {int(span_s // 60)}m"


# ─── Internal helpers ──────────────────────────────────────────────────────


def build_alert_id(
    entity: str,
    threat_level: str,
    detected_at: Any,
    *,
    detector: str = "sap",
) -> str:
    """
    Deterministic alert ID for our internal ``ANOMALIES.ALERT_ID`` column.

    *entity* is the source_ip for SAP anomalies and ``"<model_id>|<category>"``
    for LLM cohort anomalies. Rounded to the minute so retries within the same
    minute share the same ID. Not transmitted to the SAP /alert endpoint.
    """
    if hasattr(detected_at, "strftime"):
        minute = detected_at.strftime("%Y%m%dT%H%M")
    else:
        minute = str(detected_at)[:16]
    raw = f"{detector}|{entity}|{threat_level}|{minute}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


# ─── Sending with retry ────────────────────────────────────────────────────


async def _send_with_retry(
    payload: dict[str, Any], anomaly_row: dict[str, Any]
) -> bool:
    last_error: str | None = None
    log_ctx = {
        "source_ip": anomaly_row.get("source_ip"),
        "threat_level": anomaly_row.get("threat_level"),
    }
    for attempt in range(1, RETRY_MAX_ATTEMPTS + 1):
        try:
            await _send_once(payload)
            logger.info("webhook.sent", extra={**log_ctx, "attempt": attempt})
            return True
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            last_error = f"HTTP {status}"
            if status < 500 and status != 429:
                logger.error(
                    "webhook.fatal_http",
                    extra={**log_ctx, "status": status, "body": exc.response.text[:300]},
                )
                return False
            logger.warning(
                "webhook.retry",
                extra={**log_ctx, "attempt": attempt, "status": status},
            )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as exc:
            last_error = str(exc)
            logger.warning(
                "webhook.retry",
                extra={**log_ctx, "attempt": attempt, "error": str(exc)},
            )

        if attempt < RETRY_MAX_ATTEMPTS:
            delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
            delay *= 0.5 + random.random()
            await asyncio.sleep(delay)

    logger.error("webhook.failed", extra={**log_ctx, "error": last_error})
    return False


async def _send_once(payload: dict[str, Any]) -> None:
    headers = {
        "Authorization": f"Bearer {settings.sap_api_key}",
        "Content-Type": "application/json",
    }
    url = f"{settings.sap_api_url}/alert"
    client = _get_client()
    response = await client.post(url, json=payload, headers=headers)
    response.raise_for_status()


def _mock_alert(anomaly_row: dict[str, Any], message: str) -> None:
    logger.info(
        "webhook.mock",
        extra={
            "source_ip": anomaly_row.get("source_ip"),
            "threat_level": anomaly_row.get("threat_level"),
            "message": message,
            "message_len": len(message),
        },
    )
