"""
test_features.py
----------------
Unit tests for feature engineering — parametrized across edge cases.
"""

from __future__ import annotations

import pandas as pd
import pytest

from src.model.features import extract_features
from src.model.schema import FEATURE_COLUMNS


class TestExtractFeatures:
    def test_returns_dataframe(self, mixed_logs_df: pd.DataFrame):
        result = extract_features(mixed_logs_df)
        assert isinstance(result, pd.DataFrame)

    def test_has_all_feature_columns(self, mixed_logs_df: pd.DataFrame):
        result = extract_features(mixed_logs_df)
        for col in FEATURE_COLUMNS:
            assert col in result.columns, f"Missing feature column: {col}"

    def test_empty_input_returns_empty(self):
        result = extract_features(pd.DataFrame())
        assert result.empty
        for col in FEATURE_COLUMNS:
            assert col in result.columns

    def test_groups_by_source_ip(self, mixed_logs_df: pd.DataFrame):
        result = extract_features(mixed_logs_df)
        unique_ips = mixed_logs_df["source_ip"].nunique()
        assert len(result) == unique_ips

    def test_has_source_ip_column(self, mixed_logs_df: pd.DataFrame):
        result = extract_features(mixed_logs_df)
        assert "source_ip" in result.columns

    def test_error_rate_between_0_and_1(self, mixed_logs_df: pd.DataFrame):
        result = extract_features(mixed_logs_df)
        assert (result["error_rate"] >= 0).all()
        assert (result["error_rate"] <= 1).all()

    def test_denied_ratio_between_0_and_1(self, mixed_logs_df: pd.DataFrame):
        result = extract_features(mixed_logs_df)
        assert (result["denied_ratio"] >= 0).all()
        assert (result["denied_ratio"] <= 1).all()


class TestExtractFeaturesAllNormal:
    def test_low_error_rate(self, normal_logs_df: pd.DataFrame):
        result = extract_features(normal_logs_df)
        assert (result["error_rate"] == 0).all()

    def test_zero_denied_ratio(self, normal_logs_df: pd.DataFrame):
        result = extract_features(normal_logs_df)
        assert (result["denied_ratio"] == 0).all()


class TestExtractFeaturesAllAttack:
    def test_high_denied_ratio(self, attack_logs_df: pd.DataFrame):
        result = extract_features(attack_logs_df)
        assert (result["denied_ratio"] > 0).all()

    def test_brute_force_score(self, attack_logs_df: pd.DataFrame):
        result = extract_features(attack_logs_df)
        assert (result["brute_force_score"] > 0).all()


class TestExtractFeaturesTextStatus:
    def test_text_status_mapped(self):
        """Text statuses like 'DENIED' should map to 4xx for error counting."""
        df = pd.DataFrame([
            {
                "datetime": "2026-04-04 14:00:00",
                "source_ip": "10.0.0.1",
                "port_service": "TCP/22",
                "event_description": "Failed login",
                "status": "DENIED",
                "log_type": "security",
            },
            {
                "datetime": "2026-04-04 14:00:01",
                "source_ip": "10.0.0.1",
                "port_service": "TCP/22",
                "event_description": "Failed login",
                "status": "BLOCKED",
                "log_type": "security",
            },
        ])
        result = extract_features(df)
        row = result.iloc[0]
        assert row["error_rate"] > 0
        assert row["denied_ratio"] > 0
        assert row["status_4xx_count"] > 0
