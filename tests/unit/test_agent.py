"""Unit tests for the agent tool surface and supporting infrastructure.

Covers the surfaces still in use after the v1 orchestrator was retired
(the v2 orchestrator and its tests live alongside in ``tests/unit/agent/``):

- ``post_alert_message`` length validation (empty / >300 / valid in mock mode)
- repository read methods in mock mode (count_since, top_source_ips,
  query_anomalies, mttd_percentiles, model_version.latest)
- ``src/agent/tools.py`` dispatch contract (registry/schema parity,
  unknown-tool envelope, bad-args envelope)
- the FastAPI ``/agent/tool`` and ``/agent/post_alert`` routes via
  ``TestClient``
- ``submit_alert`` preview-only invariant (no real send)
- ``trim_history`` cap

These tests run against the in-memory mock backends — no real HANA, no
SAP API, no Anthropic. They monkeypatch ``settings.mock_hana`` /
``mock_webhook`` / ``mock_api`` to True so the repository / fetcher /
webhook code paths flip to their in-memory branches.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from src.agent.schemas import TOOL_SCHEMAS
from src.agent.tools import TOOL_REGISTRY, dispatch
from src.alerting.sap_webhook import MESSAGE_MAX_CHARS, post_alert_message
from src.storage.repositories import (
    AnomalyRepository,
    LogRepository,
    ModelVersionRepository,
    _percentiles,
)

# ─── Helpers ───────────────────────────────────────────────────────────────


def _now():
    return datetime.now(UTC)


@pytest.fixture
def mock_hana():
    """Force settings.mock_hana → True for the duration of the test."""
    with patch("src.storage.repositories.settings") as s:
        s.mock_hana = True
        yield


@pytest.fixture
def mock_webhook():
    with patch("src.alerting.sap_webhook.settings") as s:
        s.mock_webhook = True
        s.sap_api_url = ""
        s.sap_api_key = ""
        yield


# ─── post_alert_message validation ─────────────────────────────────────────


def test_post_alert_message_empty(mock_webhook):
    result = asyncio.run(post_alert_message(""))
    assert result == {"ok": False, "status": "empty", "message_len": 0}


def test_post_alert_message_too_long(mock_webhook):
    msg = "A" * (MESSAGE_MAX_CHARS + 1)
    result = asyncio.run(post_alert_message(msg))
    assert result["ok"] is False
    assert result["status"] == "too_long"
    assert result["message_len"] == MESSAGE_MAX_CHARS + 1


def test_post_alert_message_mock_send(mock_webhook):
    msg = "WHAT: brute force WHEN: now WHY: 50 fails"
    result = asyncio.run(post_alert_message(msg))
    assert result["ok"] is True
    assert result["status"] == "mock"
    assert result["message_len"] == len(msg)


def test_post_alert_message_strips_whitespace(mock_webhook):
    result = asyncio.run(post_alert_message("   "))
    assert result == {"ok": False, "status": "empty", "message_len": 0}


# ─── _percentiles helper ───────────────────────────────────────────────────


def test_percentiles_empty():
    assert _percentiles([]) == {"p50_ms": None, "p95_ms": None, "sample_count": 0}


def test_percentiles_single():
    assert _percentiles([42]) == {"p50_ms": 42, "p95_ms": 42, "sample_count": 1}


def test_percentiles_known_distribution():
    # 100..1000 step 100. Median = 550, p95 = 955.
    samples = list(range(100, 1001, 100))
    result = _percentiles(samples)
    assert result["sample_count"] == 10
    assert 500 <= result["p50_ms"] <= 600  # interp between 500 and 600
    assert 900 <= result["p95_ms"] <= 1000


# ─── Repository methods (mock-mode branches) ───────────────────────────────


@pytest.mark.asyncio
async def test_log_repo_count_since(mock_hana):
    repo = LogRepository()
    now = _now()
    repo._memory = [
        {"ingested_at": now - timedelta(minutes=10), "source_ip": "1.1.1.1"},
        {"ingested_at": now - timedelta(minutes=30), "source_ip": "2.2.2.2"},
        {"ingested_at": now - timedelta(hours=2), "source_ip": "3.3.3.3"},
    ]
    assert await repo.count_since(1) == 2
    assert await repo.count_since(24) == 3


@pytest.mark.asyncio
async def test_anomaly_repo_count_since(mock_hana):
    repo = AnomalyRepository()
    now = _now()
    repo._memory = [
        {"detected_at": now - timedelta(minutes=5), "source_ip": "1.1.1.1"},
        {"detected_at": now - timedelta(hours=2), "source_ip": "2.2.2.2"},
    ]
    assert await repo.count_since(1) == 1
    assert await repo.count_since(24) == 2


@pytest.mark.asyncio
async def test_anomaly_repo_top_source_ips_min_score_convention(mock_hana):
    """min_score must be the most-negative score per IP."""
    repo = AnomalyRepository()
    now = _now()
    repo._memory = [
        {"detected_at": now - timedelta(minutes=1), "source_ip": "10.0.0.1",
         "anomaly_score": -0.4},
        {"detected_at": now - timedelta(minutes=2), "source_ip": "10.0.0.1",
         "anomaly_score": -0.8},  # most-negative for 10.0.0.1
        {"detected_at": now - timedelta(minutes=3), "source_ip": "10.0.0.2",
         "anomaly_score": -0.3},
    ]
    rows = await repo.top_source_ips(hours=24, limit=5)
    by_ip = {r["source_ip"]: r for r in rows}
    assert by_ip["10.0.0.1"]["count"] == 2
    assert by_ip["10.0.0.1"]["min_score"] == -0.8  # not -0.4
    assert by_ip["10.0.0.2"]["min_score"] == -0.3
    # Sorted by count desc
    assert rows[0]["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_anomaly_repo_query_anomalies_threat_filter(mock_hana):
    repo = AnomalyRepository()
    now = _now()
    repo._memory = [
        {"detected_at": now, "threat_level": "HIGH", "source_ip": "1.1.1.1"},
        {"detected_at": now, "threat_level": "MEDIUM", "source_ip": "2.2.2.2"},
        {"detected_at": now, "threat_level": "high", "source_ip": "3.3.3.3"},
    ]
    rows = await repo.query_anomalies(threat_level="HIGH")
    ips = {r["source_ip"] for r in rows}
    assert ips == {"1.1.1.1", "3.3.3.3"}  # case-insensitive


@pytest.mark.asyncio
async def test_anomaly_repo_query_anomalies_invalid_threat_silently_empty(mock_hana):
    repo = AnomalyRepository()
    repo._memory = [{"detected_at": _now(), "threat_level": "HIGH"}]
    assert await repo.query_anomalies(threat_level="bogus") == []


@pytest.mark.asyncio
async def test_anomaly_repo_mttd_percentiles_mock(mock_hana):
    repo = AnomalyRepository()
    now = _now()
    repo._memory = [
        {"detected_at": now - timedelta(minutes=i), "pipeline_mttd_ms": ms}
        for i, ms in enumerate([100, 200, 300, 400, 500], start=1)
    ]
    stats = await repo.mttd_percentiles(hours=24)
    assert stats["sample_count"] == 5
    assert stats["p50_ms"] == 300


@pytest.mark.asyncio
async def test_model_version_latest_mock(mock_hana):
    repo = ModelVersionRepository()
    repo._memory = [
        {"version_tag": "v1", "model_type": "isolation_forest"},
        {"version_tag": "v2", "model_type": "isolation_forest"},
    ]
    latest = await repo.latest()
    assert latest["version_tag"] == "v2"


@pytest.mark.asyncio
async def test_model_version_latest_empty(mock_hana):
    repo = ModelVersionRepository()
    repo._memory = []
    assert await repo.latest() is None


# ─── tools.dispatch contract ───────────────────────────────────────────────


def test_registry_and_schema_names_match():
    registry_names = set(TOOL_REGISTRY)
    schema_names = {t["name"] for t in TOOL_SCHEMAS}
    assert registry_names == schema_names


def test_dispatch_unknown_tool_returns_envelope():
    result = asyncio.run(dispatch("nope", {}))
    assert "error" in result
    assert "unknown_tool" in result["error"]


def test_dispatch_bad_args_returns_envelope():
    result = asyncio.run(dispatch("get_anomaly_count", {"bogus": 1}))
    assert "error" in result
    assert "bad_args" in result["error"]


def test_submit_alert_does_not_send():
    """submit_alert is preview-only — no I/O, returns requires_confirmation."""
    result = asyncio.run(dispatch(
        "submit_alert",
        {"what": "Brute force", "when": "2026-04-29T10:00Z", "why": "50 fails"},
    ))
    assert result["requires_confirmation"] is True
    assert "preview" in result
    assert result["message_len"] <= MESSAGE_MAX_CHARS


def test_submit_alert_truncates_long_why():
    why = "X" * 1000
    result = asyncio.run(dispatch(
        "submit_alert",
        {"what": "BF", "when": "now", "why": why},
    ))
    assert result["message_len"] <= MESSAGE_MAX_CHARS
    assert result["preview"].startswith("WHAT: BF WHEN: now WHY: ")


# ─── FastAPI routes ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def client():
    """TestClient against the FastAPI app, without entering its lifespan
    (the pipeline / signal handlers are not relevant to route-level
    tests and tearing them down in a thread fails)."""
    from src.api.main import app

    return TestClient(app)


def test_route_tool_dispatch_submit_alert(client):
    r = client.post(
        "/agent/tool",
        json={"name": "submit_alert",
              "args": {"what": "x", "when": "y", "why": "z"}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["result"]["requires_confirmation"] is True


def test_route_tool_dispatch_unknown(client):
    r = client.post("/agent/tool", json={"name": "nope", "args": {}})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "error" in body["result"]


def test_route_tool_dispatch_validation(client):
    """Missing 'name' field must 422."""
    r = client.post("/agent/tool", json={"args": {}})
    assert r.status_code == 422


def test_route_post_alert_validation(client):
    r = client.post("/agent/post_alert", json={})
    assert r.status_code == 422


# ─── trim_history ──────────────────────────────────────────────────────────


def test_trim_history_under_cap():
    from src.agent.agent import trim_history

    msgs = [{"role": "user", "content": str(i)} for i in range(10)]
    assert len(trim_history(msgs)) == 10


def test_trim_history_over_cap():
    from src.agent.agent import MAX_HISTORY_ROUNDS, trim_history

    cap = MAX_HISTORY_ROUNDS * 2
    msgs = [{"role": "user", "content": str(i)} for i in range(cap + 5)]
    trimmed = trim_history(msgs)
    assert len(trimmed) == cap
    # Most-recent kept
    assert trimmed[-1]["content"] == str(cap + 4)
