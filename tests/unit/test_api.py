"""Unit tests for src/api/main.py using FastAPI TestClient."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient


class TestHealthEndpoint:
    def test_health_returns_200(self):
        # Import inside test to avoid triggering lifespan pipeline start
        with patch("src.api.main.lifespan") as mock_lifespan:
            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def noop_lifespan(app):
                yield

            mock_lifespan.side_effect = noop_lifespan
            # Re-create app with mocked lifespan
            from src.api.main import app
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestMetricsEndpoint:
    def test_metrics_returns_200(self):
        from src.api.main import app
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "counters" in data
        assert "pipeline_mttd_ms" in data


class TestAnomaliesEndpoint:
    def test_negative_limit_is_clamped_before_repository_call(self):
        from src.api.main import app

        async def fake_recent_anomalies(limit: int):
            assert limit == 1
            return []

        client = TestClient(app, raise_server_exceptions=False)
        with patch("src.api.main.anomaly_repository.recent_anomalies", fake_recent_anomalies):
            response = client.get("/anomalies?limit=-10")

        assert response.status_code == 200
        assert response.json()["total"] == 0
