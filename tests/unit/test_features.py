"""
test_features.py
----------------
Unit tests for feature engineering.
Owner: AI & Data Science Specialist
"""

import pytest
import pandas as pd
import numpy as np

from src.model.features import extract_features


SAMPLE_LOGS = pd.DataFrame([
    {"datetime": "2026-04-04 14:45:01", "source_ip": "192.168.1.105",
     "port_service": "TCP/22", "event_description": "Failed login attempt",
     "status": "DENIED", "log_type": "security"},
    {"datetime": "2026-04-04 14:45:05", "source_ip": "192.168.1.105",
     "port_service": "TCP/22", "event_description": "Failed login attempt",
     "status": "DENIED", "log_type": "security"},
    {"datetime": "2026-04-04 14:55:01", "source_ip": "10.10.1.1",
     "port_service": "TCP/80", "event_description": "GET /index.html HTTP/1.1",
     "status": "200", "log_type": "access"},
])


class TestExtractFeatures:
    def test_returns_dataframe(self):
        result = extract_features(SAMPLE_LOGS)
        assert isinstance(result, pd.DataFrame)

    def test_has_feature_columns(self):
        result = extract_features(SAMPLE_LOGS)
        expected = ["total_requests", "error_rate", "post_ratio"]
        for col in expected:
            assert col in result.columns, f"Missing feature column: {col}"

    def test_empty_input_returns_empty(self):
        result = extract_features(pd.DataFrame())
        assert result.empty

    def test_error_rate_between_0_and_1(self):
        result = extract_features(SAMPLE_LOGS)
        assert (result["error_rate"] >= 0).all()
        assert (result["error_rate"] <= 1).all()

    def test_groups_by_source_ip(self):
        result = extract_features(SAMPLE_LOGS)
        # 192.168.1.105 and 10.10.1.1 should be separate rows
        assert len(result) == 2
