"""Unit tests for src/api/main.py using FastAPI TestClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
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
