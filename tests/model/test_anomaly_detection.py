"""
test_anomaly_detection.py
-------------------------
Model quality tests — precision, recall, MTTD.
These tests are critical: Operational Efficiency is 40% of the grade.

Owner: AI & Data Science Specialist

Run: make test-model
"""

import pytest
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.model.features import extract_features


# ─── Synthetic test data ───────────────────────────────────────────────────

def make_normal_logs(n=100) -> pd.DataFrame:
    """Simulate normal traffic — low volume, low error rate."""
    rows = []
    for i in range(n):
        rows.append({
            "datetime": f"2026-04-04 14:{i//60:02d}:{i%60:02d}",
            "source_ip": f"10.10.1.{(i % 50) + 1}",
            "port_service": "TCP/80",
            "event_description": "GET /index.html HTTP/1.1",
            "status": "200",
            "log_type": "access",
        })
    return pd.DataFrame(rows)


def make_attack_logs(attacker_ip="203.0.113.99", n=500) -> pd.DataFrame:
    """Simulate a brute-force attack — high volume, high error rate from one IP."""
    rows = []
    for i in range(n):
        rows.append({
            "datetime": f"2026-04-04 15:00:{i%60:02d}",
            "source_ip": attacker_ip,
            "port_service": "TCP/22",
            "event_description": "Failed login attempt: user 'root'",
            "status": "DENIED",
            "log_type": "security",
        })
    return pd.DataFrame(rows)


# ─── Tests ─────────────────────────────────────────────────────────────────

class TestAnomalyDetection:
    @pytest.fixture
    def trained_model(self):
        """Train a fresh model on normal + attack data."""
        normal  = make_normal_logs(200)
        attack  = make_attack_logs(n=50)
        all_logs = pd.concat([normal, attack], ignore_index=True)

        features = extract_features(all_logs)
        X = features[["total_requests", "error_rate", "post_ratio",
                       "unique_paths", "status_4xx_count", "status_5xx_count",
                       "request_rate_zscore"]].fillna(0).values

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X_scaled)
        return model, scaler, features

    def test_attacker_ip_gets_lower_score(self, trained_model):
        """The attacking IP should have a lower anomaly score than normal IPs."""
        model, scaler, features = trained_model

        X = features[["total_requests", "error_rate", "post_ratio",
                       "unique_paths", "status_4xx_count", "status_5xx_count",
                       "request_rate_zscore"]].fillna(0).values
        X_scaled = scaler.transform(X)
        scores = model.decision_function(X_scaled)
        features = features.copy()
        features["score"] = scores

        attacker_scores = features[features["source_ip"] == "203.0.113.99"]["score"]
        normal_scores   = features[features["source_ip"] != "203.0.113.99"]["score"]

        if len(attacker_scores) > 0 and len(normal_scores) > 0:
            assert attacker_scores.mean() < normal_scores.mean(), \
                "Attacker IP should have lower anomaly score than normal IPs"

    def test_model_detects_high_volume_ip(self, trained_model):
        """An IP with 10x normal request volume should be flagged."""
        model, scaler, _ = trained_model

        # Simulate a high-volume IP
        spike_features = pd.DataFrame([{
            "total_requests": 5000,
            "error_rate": 0.9,
            "post_ratio": 0.1,
            "unique_paths": 2,
            "status_4xx_count": 4500,
            "status_5xx_count": 0,
            "request_rate_zscore": 8.0,
        }])

        X_scaled = scaler.transform(spike_features.values)
        score = model.decision_function(X_scaled)[0]
        assert score < 0, f"Spike IP should be anomalous, got score={score:.3f}"

    # TODO: Add precision/recall test once labeled SAP data is available (April 13)
    # def test_precision_above_threshold(self): ...
    # def test_mean_time_to_detect(self): ...
