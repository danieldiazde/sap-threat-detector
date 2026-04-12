"""Unit tests for src/alerting/deduplication.py."""

from __future__ import annotations

import time

from src.alerting.deduplication import AlertDeduper


class TestAlertDeduper:
    def test_first_alert_fires(self):
        d = AlertDeduper(ttl_seconds=60)
        anomaly = {"source_ip": "10.0.0.1", "threat_level": "high"}
        assert d.should_fire(anomaly) is True

    def test_duplicate_suppressed(self):
        d = AlertDeduper(ttl_seconds=60)
        anomaly = {"source_ip": "10.0.0.1", "threat_level": "high"}
        d.should_fire(anomaly)
        assert d.should_fire(anomaly) is False

    def test_different_ip_fires(self):
        d = AlertDeduper(ttl_seconds=60)
        d.should_fire({"source_ip": "10.0.0.1", "threat_level": "high"})
        assert d.should_fire({"source_ip": "10.0.0.2", "threat_level": "high"}) is True

    def test_different_level_fires(self):
        d = AlertDeduper(ttl_seconds=60)
        d.should_fire({"source_ip": "10.0.0.1", "threat_level": "high"})
        assert d.should_fire({"source_ip": "10.0.0.1", "threat_level": "medium"}) is True

    def test_expired_entry_fires_again(self):
        d = AlertDeduper(ttl_seconds=1)
        anomaly = {"source_ip": "10.0.0.1", "threat_level": "high"}
        d.should_fire(anomaly)
        time.sleep(1.1)
        assert d.should_fire(anomaly) is True

    def test_reset_clears_cache(self):
        d = AlertDeduper(ttl_seconds=60)
        d.should_fire({"source_ip": "10.0.0.1", "threat_level": "high"})
        d.reset()
        assert d.should_fire({"source_ip": "10.0.0.1", "threat_level": "high"}) is True

    def test_len(self):
        d = AlertDeduper(ttl_seconds=60)
        assert len(d) == 0
        d.should_fire({"source_ip": "10.0.0.1", "threat_level": "high"})
        assert len(d) == 1
