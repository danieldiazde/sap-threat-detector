"""Unit tests for src/alerting/incident_report.py."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from src.alerting.incident_report import build_incident_report, write_report


class TestBuildIncidentReport:
    def test_contains_summary_table(self):
        anomaly = {
            "source_ip": "203.0.113.45",
            "threat_level": "high",
            "anomaly_score": -0.42,
            "detected_at": datetime(2026, 4, 4, 14, 49, tzinfo=timezone.utc),
            "pipeline_mttd_ms": 150,
            "e2e_mttd_ms": 2500,
            "model_version": "v1",
        }
        evidence = pd.DataFrame([{
            "datetime": "2026-04-04 14:49:30",
            "source_ip": "203.0.113.45",
            "event_description": "Failed login",
            "status": "DENIED",
        }])
        report = build_incident_report(anomaly, evidence)
        assert "203.0.113.45" in report
        assert "HIGH" in report
        assert "Pipeline MTTD" in report

    def test_sql_injection_recommendation(self):
        anomaly = {
            "source_ip": "10.0.0.1",
            "threat_level": "high",
            "sql_injection_hits": 5,
            "detected_at": datetime(2026, 4, 4, 14, 0, tzinfo=timezone.utc),
        }
        report = build_incident_report(anomaly, pd.DataFrame())
        assert "SQL injection" in report

    def test_brute_force_recommendation(self):
        anomaly = {
            "source_ip": "10.0.0.1",
            "threat_level": "high",
            "brute_force_score": 0.5,
            "detected_at": datetime(2026, 4, 4, 14, 0, tzinfo=timezone.utc),
        }
        report = build_incident_report(anomaly, pd.DataFrame())
        assert "Brute-force" in report

    def test_empty_evidence(self):
        anomaly = {
            "source_ip": "10.0.0.1",
            "threat_level": "low",
            "detected_at": datetime(2026, 4, 4, 14, 0, tzinfo=timezone.utc),
        }
        report = build_incident_report(anomaly, pd.DataFrame())
        assert "No evidence rows" in report


class TestWriteReport:
    def test_writes_file(self, tmp_path: Path):
        report_md = "# Test Report\nSome content."
        path = write_report(report_md, "INC-TEST-001", directory=tmp_path)
        assert path.exists()
        assert path.read_text() == report_md
        assert path.name == "INC-TEST-001.md"
