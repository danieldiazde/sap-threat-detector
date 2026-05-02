"""
truncation.py
-------------
Two helpers protecting the agent's context window (v2 plan §4):

- ``truncate_for_llm(payload)``: Layer A — applied at the tool boundary,
  before any tool result enters the conversation. Caps lists at 20
  items, head/tail-cuts strings >1500 chars, recurses into dicts.
  This is the most important of the two layers.
- ``compact_old_observations(messages, age_threshold)``: Layer B —
  walks the message history and replaces ``tool_result`` blocks older
  than ``age_threshold`` *agent iterations* with a deterministic synopsis
  whenever the serialized payload exceeds 1KB. Small results stay
  verbatim under prompt cache; only the heavy ones get summarized.
- ``summarize_for_event(payload)``: tiny one-line recap used in
  ``AgentEvent.tool_finished.summary`` so the UI's ``st.status`` panel
  can show a useful headline without rendering the full payload.

Pure functions, no I/O — easy to unit test.
"""

from __future__ import annotations

import json
from typing import Any

LIST_CAP: int = 20
STRING_CAP: int = 1500
STRING_HEAD: int = 500
STRING_TAIL: int = 500
COMPACT_THRESHOLD_BYTES: int = 1024  # Layer B trigger


def _truncate_string(s: str) -> str:
    if len(s) <= STRING_CAP:
        return s
    cut = len(s) - STRING_HEAD - STRING_TAIL
    return f"{s[:STRING_HEAD]}...[TRUNCATED {cut} chars]...{s[-STRING_TAIL:]}"


def truncate_for_llm(payload: Any) -> Any:
    """Recursively cap lists and head/tail-cut long strings.

    Returns a new structure; does not mutate the input.
    """
    if isinstance(payload, str):
        return _truncate_string(payload)
    if isinstance(payload, list):
        n = len(payload)
        if n > LIST_CAP:
            kept = [truncate_for_llm(item) for item in payload[:LIST_CAP]]
            kept.append(f"...({n - LIST_CAP} more truncated)")
            return kept
        return [truncate_for_llm(item) for item in payload]
    if isinstance(payload, dict):
        return {k: truncate_for_llm(v) for k, v in payload.items()}
    return payload


def summarize_for_event(payload: Any) -> dict[str, Any]:
    """One-line recap of a tool result, for st.status headlines.

    Deterministic: no LLM call. For tabular results returns row count
    plus the first row's keys; for scalars returns them verbatim;
    for errors returns the error string verbatim.
    """
    if not isinstance(payload, dict):
        return {"value": payload}
    if "error" in payload:
        return {"error": str(payload["error"])[:200]}
    if isinstance(payload.get("rows"), list):
        rows = payload["rows"]
        recap: dict[str, Any] = {"rows": len(rows)}
        if rows and isinstance(rows[0], dict):
            recap["columns"] = list(rows[0].keys())
            recap["first_row"] = rows[0]
        if "truncated" in payload:
            recap["truncated"] = payload["truncated"]
        return recap
    # Scalar-ish payload: keep top-level scalar fields, drop heavy ones.
    out: dict[str, Any] = {}
    for k, v in payload.items():
        if isinstance(v, str) and len(v) > 200:
            out[k] = v[:200] + "..."
        elif isinstance(v, list | dict):
            out[k] = f"<{type(v).__name__} len={len(v)}>"
        else:
            out[k] = v
    return out


def _compact_synopsis(turn_idx: int, tool_name: str | None, content: Any) -> str:
    if isinstance(content, dict):
        if "error" in content:
            return f"[Turn {turn_idx} — {tool_name or 'tool'}: error={content['error']}]"
        rows = content.get("rows")
        if isinstance(rows, list):
            cols = list(rows[0].keys()) if rows and isinstance(rows[0], dict) else []
            first = rows[0] if rows and isinstance(rows[0], dict) else None
            head = (
                f"first row: {json.dumps(first, default=str)[:200]}" if first else ""
            )
            return (
                f"[Turn {turn_idx} — {tool_name or 'tool'}: returned {len(rows)} rows, "
                f"columns={cols}. {head}. Full output omitted to save context.]"
            )
    return (
        f"[Turn {turn_idx} — {tool_name or 'tool'}: payload omitted to save context.]"
    )


def compact_old_observations(
    messages: list[dict[str, Any]],
    age_threshold: int = 3,
) -> list[dict[str, Any]]:
    """Replace large tool_result blocks older than ``age_threshold`` agent
    rounds with a one-line synopsis.

    Operates on Anthropic-format messages. A ``tool_result`` block is a
    content item ``{"type": "tool_result", "tool_use_id": ..., "content": ...}``.
    We treat each user/assistant pair past the threshold as old; in the
    Anthropic schema tool_result blocks live inside user messages as
    follow-ups to a prior tool_use. Returns a new list — never mutates.

    Implementation detail: we don't try to track tool_name across the
    pairing because the Anthropic schema doesn't carry it on the
    tool_result block. We pass ``None`` and let the synopsis still be
    informative via the row-count + columns recap.
    """
    if age_threshold <= 0 or len(messages) <= age_threshold * 2:
        return [dict(m) for m in messages]

    keep_from = len(messages) - age_threshold * 2
    out: list[dict[str, Any]] = []
    for idx, msg in enumerate(messages):
        if idx >= keep_from:
            out.append(dict(msg))
            continue
        new_content = msg.get("content")
        if isinstance(new_content, list):
            replaced: list[Any] = []
            for block in new_content:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_result"
                    and _byte_size(block.get("content")) > COMPACT_THRESHOLD_BYTES
                ):
                    synopsis = _compact_synopsis(idx, None, block.get("content"))
                    replaced.append({**block, "content": synopsis})
                else:
                    replaced.append(block)
            out.append({**msg, "content": replaced})
        else:
            out.append(dict(msg))
    return out


def _byte_size(payload: Any) -> int:
    try:
        return len(json.dumps(payload, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return len(str(payload).encode("utf-8"))
