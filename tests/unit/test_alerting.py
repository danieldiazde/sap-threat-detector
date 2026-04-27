"""Unit tests for src/alerting/sap_webhook.py — message format, alert_id."""

from __future__ import annotations

from datetime import UTC, datetime

import pandas as pd
from src.alerting.sap_webhook import (
    MESSAGE_MAX_CHARS,
    build_alert_id,
    format_alert_message,
)


class TestAlertId:
    def test_deterministic(self):
        dt = datetime(2026, 4, 4, 14, 45, 0, tzinfo=UTC)
        assert build_alert_id("10.0.0.1", "high", dt) == build_alert_id("10.0.0.1", "high", dt)

    def test_different_ips_differ(self):
        dt = datetime(2026, 4, 4, 14, 45, 0, tzinfo=UTC)
        assert build_alert_id("10.0.0.1", "high", dt) != build_alert_id("10.0.0.2", "high", dt)

    def test_same_minute_same_id(self):
        dt1 = datetime(2026, 4, 4, 14, 45, 0, tzinfo=UTC)
        dt2 = datetime(2026, 4, 4, 14, 45, 59, tzinfo=UTC)
        assert build_alert_id("10.0.0.1", "high", dt1) == build_alert_id("10.0.0.1", "high", dt2)


class TestFormatAlertMessage:
    def _anomaly(self, **overrides):
        base = {
            "source_ip": "203.0.113.45",
            "threat_level": "high",
            "anomaly_score": -0.42,
            "detected_at": datetime(2026, 4, 26, 17, 32, 0, tzinfo=UTC),
            "total_requests": 3500,
            "error_rate": 0.87,
            "denied_ratio": 0.6,
            "sql_injection_hits": 0,
            "brute_force_score": 0.0,
            "suspicious_path_ratio": 0.0,
        }
        base.update(overrides)
        return base

    def test_under_max_chars(self):
        msg = format_alert_message(self._anomaly(), pd.DataFrame())
        assert len(msg) <= MESSAGE_MAX_CHARS

    def test_contains_what_when_why(self):
        msg = format_alert_message(self._anomaly(), pd.DataFrame())
        assert msg.startswith("WHAT:")
        assert "WHEN:" in msg
        assert "WHY:" in msg

    def test_when_uses_iso_timestamp(self):
        msg = format_alert_message(self._anomaly(), pd.DataFrame())
        assert "2026-04-26T17:32:00" in msg

    def test_sql_injection_label(self):
        msg = format_alert_message(self._anomaly(sql_injection_hits=4), pd.DataFrame())
        assert "SQL injection" in msg
        assert "SQLi" in msg  # appears in WHY

    def test_brute_force_label(self):
        msg = format_alert_message(
            self._anomaly(brute_force_score=0.55, sql_injection_hits=0), pd.DataFrame()
        )
        assert "Brute-force" in msg
        assert "brute_score" in msg

    def test_target_uses_sap_application_when_present(self):
        msg = format_alert_message(
            self._anomaly(sap_application="SAP-ERP-01"), pd.DataFrame()
        )
        assert "SAP-ERP-01" in msg

    def test_truncates_pathologically_long_input(self):
        anomaly = self._anomaly(sap_application="X" * 500)
        msg = format_alert_message(anomaly, pd.DataFrame())
        assert len(msg) <= MESSAGE_MAX_CHARS
        assert msg.startswith("WHAT:")
        assert "WHEN:" in msg

    def test_evidence_window_appended_when_multi_row(self):
        evidence = pd.DataFrame(
            [
                {"datetime": "2026-04-26T17:30:00Z"},
                {"datetime": "2026-04-26T17:34:00Z"},
            ]
        )
        msg = format_alert_message(self._anomaly(), evidence)
        assert "within" in msg
