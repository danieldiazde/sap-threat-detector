"""Unit tests for src/alerting/sap_webhook.py — payload shape, alert_id, HMAC."""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from src.alerting.sap_webhook import _alert_id, _build_payload


class TestAlertId:
    def test_deterministic(self):
        dt = datetime(2026, 4, 4, 14, 45, 0, tzinfo=timezone.utc)
        a = _alert_id("10.0.0.1", "high", dt)
        b = _alert_id("10.0.0.1", "high", dt)
        assert a == b

    def test_different_ips_differ(self):
        dt = datetime(2026, 4, 4, 14, 45, 0, tzinfo=timezone.utc)
        a = _alert_id("10.0.0.1", "high", dt)
        b = _alert_id("10.0.0.2", "high", dt)
        assert a != b

    def test_same_minute_same_id(self):
        dt1 = datetime(2026, 4, 4, 14, 45, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 4, 4, 14, 45, 59, tzinfo=timezone.utc)
        assert _alert_id("10.0.0.1", "high", dt1) == _alert_id("10.0.0.1", "high", dt2)


class TestBuildPayload:
    def test_has_required_keys(self):
        anomaly = {
            "source_ip": "203.0.113.45",
            "threat_level": "high",
            "anomaly_score": -0.42,
            "detected_at": datetime(2026, 4, 4, 14, 49, 30, tzinfo=timezone.utc),
            "total_requests": 3500,
            "error_rate": 0.87,
            "pipeline_mttd_ms": 150,
            "e2e_mttd_ms": 2500,
            "model_version": "20260404-v1",
            "model_type": "isolation_forest",
        }
        evidence = pd.DataFrame()
        payload = _build_payload(anomaly, evidence)

        assert "alert_id" in payload
        assert "team_id" in payload
        assert "source_ip" in payload
        assert "threat_level" in payload
        assert "evidence" in payload
        assert payload["source_ip"] == "203.0.113.45"
        assert payload["pipeline_mttd_ms"] == 150

    def test_evidence_sample_limited(self):
        anomaly = {
            "source_ip": "10.0.0.1",
            "threat_level": "medium",
            "detected_at": datetime(2026, 4, 4, 14, 0, tzinfo=timezone.utc),
        }
        evidence = pd.DataFrame([{"event_description": f"row-{i}"} for i in range(20)])
        payload = _build_payload(anomaly, evidence)
        assert len(payload["evidence"]["log_sample"]) <= 5
