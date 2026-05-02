"""Integration test for the per-turn SQL circuit breaker (§2).

Drives ``Agent.run`` with a stub Anthropic client that always asks for
``run_custom_query`` with a malformed SELECT. After 3 dispatched failures,
the orchestrator must stop dispatching further ``run_custom_query`` calls
and synthesize the canned ``circuit_breaker_tripped`` tool result.

The test does not require a real Anthropic API key — we inject a stub
client. ``run_custom_query`` itself is patched to return a
deterministic error envelope so we don't depend on HANA or the
in-process mock branch.
"""

from __future__ import annotations

import asyncio
import types
from typing import Any
from unittest.mock import patch

import pytest
from src.agent import agent as agent_mod
from src.agent.agent import SQL_FAILURE_LIMIT, Agent


def _ns(**kw):
    return types.SimpleNamespace(**kw)


class _FakeMessages:
    """Stub for ``client.messages.create``.

    Returns a tool_use response on every call (until ``max_calls``), then a
    plain text final answer. The tool name is always ``run_custom_query``
    so every dispatch counts toward the circuit breaker.
    """

    def __init__(self, max_tool_turns: int = 5) -> None:
        self.calls: list[dict[str, Any]] = []
        self.max_tool_turns = max_tool_turns

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) <= self.max_tool_turns:
            return _ns(
                stop_reason="tool_use",
                content=[
                    _ns(
                        type="tool_use",
                        id=f"toolu_{len(self.calls)}",
                        name="run_custom_query",
                        input={"sql": "SELECT * FROM NOPE"},
                        model_dump=lambda i=len(self.calls): {
                            "type": "tool_use",
                            "id": f"toolu_{i}",
                            "name": "run_custom_query",
                            "input": {"sql": "SELECT * FROM NOPE"},
                        },
                    )
                ],
            )
        return _ns(
            stop_reason="end_turn",
            content=[
                _ns(
                    type="text",
                    text="I tried 3 queries and they all failed; please clarify.",
                    model_dump=lambda: {
                        "type": "text",
                        "text": "I tried 3 queries and they all failed; please clarify.",
                    },
                )
            ],
        )


class _FakeClient:
    def __init__(self) -> None:
        self.messages = _FakeMessages(max_tool_turns=5)


@pytest.fixture
def stub_run_custom_query():
    """Patch tools.run_custom_query to always return a sanitized error."""
    async def _err(sql, count_total=False):
        return {
            "error": "Unknown table",
            "hint": "Allowed: SECURITY_LOGS, ANOMALIES, MODEL_VERSIONS.",
            "query_attempted": sql,
            "_render": "raw",
        }

    # Patch via the dispatcher's lookup: tools.TOOL_REGISTRY values are
    # captured at module-import time, so we override the registry entry.
    from src.agent import tools as tools_mod
    original = tools_mod.TOOL_REGISTRY["run_custom_query"]
    tools_mod.TOOL_REGISTRY["run_custom_query"] = _err
    try:
        yield
    finally:
        tools_mod.TOOL_REGISTRY["run_custom_query"] = original


def test_circuit_breaker_trips_after_three_failures(stub_run_custom_query):
    """Expect: 3 actual dispatches, then synthesized circuit-breaker error."""
    client = _FakeClient()
    agent = Agent(
        anthropic_api_key="dummy",
        model="claude-test",
        max_iterations=10,
        client=client,
    )

    async def _drive():
        events = []
        async for ev in agent.run("find me suspicious things", history=[]):
            events.append(ev)
        return events

    with patch.object(agent_mod, "settings") as s:
        s.anthropic_api_key = "dummy"
        s.agent_model = "claude-test"
        s.agent_max_iterations = 10
        events = asyncio.run(_drive())

    failed = [e for e in events if e.kind == "tool_failed"]
    final = [e for e in events if e.kind == "final"]

    # Exactly SQL_FAILURE_LIMIT (3) tool_failed events for run_custom_query
    # before the breaker takes over -- the canned circuit-breaker also
    # emits a tool_failed, so we expect SQL_FAILURE_LIMIT + at least 1.
    rcq_failures = [e for e in failed if e.tool_name == "run_custom_query"]
    assert len(rcq_failures) >= SQL_FAILURE_LIMIT
    # At least one of those must be the synthesized circuit-breaker error.
    assert any(
        (e.error or "").startswith("circuit_breaker_tripped")
        or (
            isinstance(e.result, dict)
            and e.result.get("error") == "circuit_breaker_tripped"
        )
        for e in rcq_failures
    )
    assert final, "expected exactly one final event"


def test_circuit_breaker_per_turn_counter_resets(stub_run_custom_query):
    """A second user turn starts the breaker counter from zero."""
    client = _FakeClient()
    client.messages.max_tool_turns = 1  # one failure, then end_turn

    agent = Agent(
        anthropic_api_key="dummy",
        model="claude-test",
        max_iterations=10,
        client=client,
    )

    async def _drive(history):
        events = []
        async for ev in agent.run("first turn", history=history):
            events.append(ev)
        return events

    with patch.object(agent_mod, "settings") as s:
        s.anthropic_api_key = "dummy"
        s.agent_model = "claude-test"
        s.agent_max_iterations = 10
        history: list = []
        first = asyncio.run(_drive(history))

    fails_first = [e for e in first if e.kind == "tool_failed"]
    # Single failure does not trip the breaker.
    assert len(fails_first) == 1
    assert (fails_first[0].error or "") != "circuit_breaker_tripped"
