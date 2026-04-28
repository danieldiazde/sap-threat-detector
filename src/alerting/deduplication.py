"""
deduplication.py
----------------
TTL-based alert deduper.

Without this, a sustained attack that spans N polling cycles would fire
N webhook alerts for the same ``(source_ip, threat_level)`` pair —
spamming the SAP alerting system and blowing past any rate-limits they
impose.

The deduper is keyed by ``(source_ip, threat_level)`` and cached for
``settings.anomaly_dedup_ttl_seconds``. The first alert fires; repeats
within the TTL are suppressed.

Owner: Cloud Integration Engineer
"""

from __future__ import annotations

import threading
from typing import Any

from src.common.config import settings
from src.common.logging import get_logger
from src.common.time_utils import utcnow

logger = get_logger(__name__)


class AlertDeduper:
    """Thread-safe in-memory TTL cache."""

    def __init__(self, ttl_seconds: int | None = None) -> None:
        self._ttl: int = ttl_seconds if ttl_seconds is not None else settings.anomaly_dedup_ttl_seconds
        self._lock = threading.Lock()
        # key → expiry POSIX timestamp
        self._cache: dict[tuple[str, ...], float] = {}

    @staticmethod
    def key_for(anomaly: dict[str, Any]) -> tuple[str, ...]:
        """Build the dedup key from an anomaly row.

        SAP anomalies key on ``(detector, source_ip, threat_level)``; LLM
        cohort anomalies key on ``(detector, llm_model_id, llm_prompt_category,
        threat_level)``. Threat level is in the key so an attacker escalating
        from medium → high produces a fresh alert.
        """
        detector = str(anomaly.get("detector") or "sap").lower()
        threat_level = str(anomaly.get("threat_level", "unknown"))
        if detector == "llm":
            return (
                "llm",
                str(anomaly.get("llm_model_id", "unknown")),
                str(anomaly.get("llm_prompt_category", "unknown")),
                threat_level,
            )
        return ("sap", str(anomaly.get("source_ip", "unknown")), threat_level)

    def should_fire(self, anomaly: dict[str, Any]) -> bool:
        """
        Return True if an alert for this anomaly should be fired.

        Also marks the key as recently-fired, extending the TTL window
        so repeat calls within the TTL return False.
        """
        key = self.key_for(anomaly)
        now_ts = utcnow().timestamp()

        with self._lock:
            self._evict_expired(now_ts)
            if key in self._cache:
                logger.debug("dedup.suppressed", extra={"key": list(key)})
                return False
            self._cache[key] = now_ts + self._ttl
            return True

    def reset(self) -> None:
        """Clear the cache. Used by tests."""
        with self._lock:
            self._cache.clear()

    def _evict_expired(self, now_ts: float) -> None:
        expired = [k for k, exp in self._cache.items() if exp <= now_ts]
        for key in expired:
            del self._cache[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


# Module-level singleton used by the webhook sender.
deduper: AlertDeduper = AlertDeduper()
