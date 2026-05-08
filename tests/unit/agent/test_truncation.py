"""Unit tests for ``src.agent.truncation`` (CONVERSATIONAL_AGENT.md §4)."""

from __future__ import annotations

import json

from src.agent.truncation import (
    LIST_CAP,
    STRING_CAP,
    STRING_HEAD,
    STRING_TAIL,
    compact_old_observations,
    summarize_for_event,
    truncate_for_llm,
)

# ─── Layer A: truncate_for_llm ─────────────────────────────────────────────


def test_truncate_short_string_passthrough():
    s = "hello world"
    assert truncate_for_llm(s) == s


def test_truncate_long_string_head_tail():
    s = "A" * 5000
    out = truncate_for_llm(s)
    assert isinstance(out, str)
    assert out.startswith("A" * STRING_HEAD)
    assert out.endswith("A" * STRING_TAIL)
    assert "[TRUNCATED" in out
    assert len(out) < len(s)


def test_truncate_string_at_threshold_unchanged():
    s = "X" * STRING_CAP
    assert truncate_for_llm(s) == s


def test_truncate_list_cap_with_placeholder():
    payload = list(range(100))
    out = truncate_for_llm(payload)
    assert len(out) == LIST_CAP + 1
    assert out[:LIST_CAP] == list(range(LIST_CAP))
    assert "more truncated" in out[-1]


def test_truncate_list_under_cap_passthrough():
    payload = [1, 2, 3]
    assert truncate_for_llm(payload) == [1, 2, 3]


def test_truncate_recurses_into_dicts():
    payload = {"big": "Z" * 4000, "small": "ok", "nested": {"buf": "Q" * 4000}}
    out = truncate_for_llm(payload)
    assert out["small"] == "ok"
    assert "[TRUNCATED" in out["big"]
    assert "[TRUNCATED" in out["nested"]["buf"]


def test_truncate_recurses_into_list_of_dicts():
    payload = [{"buf": "M" * 3000} for _ in range(50)]
    out = truncate_for_llm(payload)
    assert len(out) == LIST_CAP + 1
    for item in out[:LIST_CAP]:
        assert "[TRUNCATED" in item["buf"]


def test_truncate_does_not_mutate_input():
    payload = {"items": list(range(50))}
    snapshot = json.dumps(payload)
    truncate_for_llm(payload)
    assert json.dumps(payload) == snapshot


def test_truncate_passthrough_scalars():
    assert truncate_for_llm(42) == 42
    assert truncate_for_llm(3.14) == 3.14
    assert truncate_for_llm(True) is True
    assert truncate_for_llm(None) is None


# ─── summarize_for_event ───────────────────────────────────────────────────


def test_summary_error_wins():
    assert summarize_for_event({"error": "boom", "rows": [1, 2]}) == {"error": "boom"}


def test_summary_tabular_recap():
    payload = {
        "rows": [{"ip": "1.1.1.1", "n": 5}, {"ip": "2.2.2.2", "n": 3}],
        "truncated": False,
    }
    out = summarize_for_event(payload)
    assert out["rows"] == 2
    assert out["columns"] == ["ip", "n"]
    assert out["first_row"] == {"ip": "1.1.1.1", "n": 5}
    assert out["truncated"] is False


def test_summary_scalar_keeps_small_values():
    out = summarize_for_event({"total": 42, "elapsed_ms": 7})
    assert out == {"total": 42, "elapsed_ms": 7}


def test_summary_collapses_heavy_string():
    out = summarize_for_event({"blob": "X" * 5000})
    assert out["blob"].endswith("...")
    assert len(out["blob"]) <= 203


# ─── Layer B: compact_old_observations ─────────────────────────────────────


def _tool_result_msg(content) -> dict:
    return {
        "role": "user",
        "content": [
            {"type": "tool_result", "tool_use_id": "abc", "content": content}
        ],
    }


def test_compact_keeps_short_history_unchanged():
    msgs = [{"role": "user", "content": "hi"}]
    out = compact_old_observations(msgs, age_threshold=3)
    assert out == msgs


def test_compact_replaces_heavy_old_tool_result():
    big_payload = {"rows": [{"k": i} for i in range(50)], "blob": "Z" * 5000}
    msgs = [
        _tool_result_msg(big_payload),  # old
        {"role": "assistant", "content": "thinking..."},
        {"role": "user", "content": "next"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "next2"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "now"},
        {"role": "assistant", "content": "..."},
    ]
    out = compact_old_observations(msgs, age_threshold=3)
    first = out[0]["content"][0]
    assert isinstance(first["content"], str)
    assert "Turn 0" in first["content"]
    assert "Full output omitted" in first["content"]


def test_compact_keeps_small_tool_result_verbatim():
    small_payload = {"rows": [{"a": 1}]}
    msgs = [
        _tool_result_msg(small_payload),
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "x"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "y"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "z"},
        {"role": "assistant", "content": "..."},
    ]
    out = compact_old_observations(msgs, age_threshold=3)
    assert out[0]["content"][0]["content"] == small_payload


def test_compact_does_not_mutate_input():
    big = {"rows": [{"k": "v" * 200} for _ in range(20)]}
    msgs = [
        _tool_result_msg(big),
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "x"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "y"},
        {"role": "assistant", "content": "..."},
        {"role": "user", "content": "z"},
        {"role": "assistant", "content": "..."},
    ]
    snapshot = json.dumps(msgs, default=str)
    compact_old_observations(msgs, age_threshold=3)
    assert json.dumps(msgs, default=str) == snapshot
