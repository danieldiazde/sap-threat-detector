"""Unit tests for src/pipeline.py — run_once with mocked dependencies."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pandas as pd
import pytest

from src.pipeline import Pipeline


def _make_mock_logs() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "datetime": "2026-04-04 14:45:01",
            "source_ip": "10.0.0.1",
            "port_service": "TCP/80",
            "event_description": "GET /index.html",
            "status": "200",
            "log_type": "access",
        },
        {
            "datetime": "2026-04-04 14:45:02",
            "source_ip": "203.0.113.99",
            "port_service": "TCP/22",
            "event_description": "Failed login attempt: user 'root'",
            "status": "DENIED",
            "log_type": "security",
        },
    ])


class TestPipelineRunOnce:
    @pytest.mark.asyncio
    async def test_run_once_no_data(self):
        pipeline = Pipeline()
        with patch("src.pipeline.fetch_all_logs", new_callable=AsyncMock, return_value=pd.DataFrame()):
            result = await pipeline.run_once()
        assert result["status"] == "no_data"

    @pytest.mark.asyncio
    async def test_run_once_processes_logs(self):
        pipeline = Pipeline()
        mock_logs = _make_mock_logs()

        with (
            patch("src.pipeline.fetch_all_logs", new_callable=AsyncMock, return_value=mock_logs),
            patch("src.pipeline.log_repository") as mock_log_repo,
            patch("src.pipeline.anomaly_repository") as mock_anomaly_repo,
            patch("src.pipeline.send_alert", new_callable=AsyncMock, return_value=True),
        ):
            mock_log_repo.insert_logs = AsyncMock(return_value=len(mock_logs))
            mock_anomaly_repo.insert_anomaly = AsyncMock()

            # This will fail if no model is trained, so we mock predict too
            with patch("src.pipeline.predict") as mock_predict, \
                 patch("src.pipeline.anomalies_only") as mock_anomalies_only:
                scored = mock_logs.copy()
                scored["is_anomaly"] = False
                scored["pipeline_mttd_ms"] = 100
                scored["anomaly_score"] = 0.1
                scored["threat_level"] = "low"
                mock_predict.return_value = scored
                mock_anomalies_only.return_value = scored[scored["is_anomaly"]]

                result = await pipeline.run_once()

        assert result["status"] == "ok"
        assert result["logs"] == 2

    @pytest.mark.asyncio
    async def test_run_once_stamps_mttd(self):
        """Pipeline must pass ingested_at to predict for MTTD calculation."""
        pipeline = Pipeline()
        mock_logs = _make_mock_logs()

        with (
            patch("src.pipeline.fetch_all_logs", new_callable=AsyncMock, return_value=mock_logs),
            patch("src.pipeline.log_repository") as mock_log_repo,
            patch("src.pipeline.anomaly_repository"),
            patch("src.pipeline.send_alert", new_callable=AsyncMock, return_value=True),
            patch("src.pipeline.predict") as mock_predict,
            patch("src.pipeline.anomalies_only") as mock_anomalies_only,
        ):
            mock_log_repo.insert_logs = AsyncMock(return_value=2)
            scored = mock_logs.copy()
            scored["is_anomaly"] = False
            scored["pipeline_mttd_ms"] = 50
            scored["anomaly_score"] = 0.1
            scored["threat_level"] = "low"
            mock_predict.return_value = scored
            mock_anomalies_only.return_value = scored[scored["is_anomaly"]]

            await pipeline.run_once()

            # Verify predict was called with ingested_at kwarg
            call_kwargs = mock_predict.call_args
            assert "ingested_at" in call_kwargs.kwargs
            assert isinstance(call_kwargs.kwargs["ingested_at"], datetime)
