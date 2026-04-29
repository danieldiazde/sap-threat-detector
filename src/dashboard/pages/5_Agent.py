"""
pages/5_Agent.py
----------------
Conversational SOC agent — chat with the SAP AI Security data.

The page hosts a Claude tool-use loop (see ``src/agent/agent.py``) wired
to the FastAPI dispatcher (``src/api/agent_routes.py``). Quick-action
buttons in the sidebar inject canned questions; the chat input takes
free-form ones. ``submit_alert`` produces a preview the analyst must
explicitly approve before any HTTP request reaches ``/alert``.

See ``docs/agent_plan.md`` for the v1 design (alert state machine,
20-round history cap, FastAPI routing decision).
"""

from __future__ import annotations

import json
from typing import Any

import pandas as pd
import streamlit as st
from src.common.config import settings
from src.dashboard._api import (
    dashboard_autorefresh,
    inject_sidebar_css,
    sidebar_brand,
)

st.set_page_config(
    page_title="Agent - SAP AI Security",
    page_icon="\U0001f916",
    layout="wide",
)
inject_sidebar_css()
dashboard_autorefresh(key="agent_autorefresh")


# ─── Session-state init ────────────────────────────────────────────────────

if "agent_messages" not in st.session_state:
    # Anthropic-format conversation history (the agent reads/writes this).
    st.session_state.agent_messages: list[dict[str, Any]] = []  # type: ignore[attr-defined]

if "agent_chat_log" not in st.session_state:
    # UI-side chat log: list of {role, text, tool_calls, pending_alert}.
    # Kept separate from agent_messages because the latter is verbatim
    # Anthropic blocks (text + tool_use + tool_result), which don't
    # render cleanly in st.chat_message.
    st.session_state.agent_chat_log: list[dict[str, Any]] = []  # type: ignore[attr-defined]

if "pending_alert" not in st.session_state:
    st.session_state.pending_alert = None  # {message, status, source_idx}

if "agent_instance" not in st.session_state:
    st.session_state.agent_instance = None


# ─── Sidebar ───────────────────────────────────────────────────────────────

with st.sidebar:
    sidebar_brand("AGENT")

    st.markdown("### Quick actions")
    quick_action = None
    if st.button("\U0001f4ca Current window status", use_container_width=True):
        quick_action = "What does the current 30-minute window look like? Any threats I should know about?"
    if st.button("\U0001f6a8 Top 5 suspicious IPs (1h)", use_container_width=True):
        quick_action = "Show me the top 5 most suspicious IPs in the last hour."
    if st.button("⚡ MTTD summary (24h)", use_container_width=True):
        quick_action = "What's our MTTD over the last 24 hours? Give me the p50 and p95."
    if st.button("\U0001f50d Recent HIGH anomalies", use_container_width=True):
        quick_action = "Show me the most recent HIGH severity anomalies."

    st.markdown("---")
    if st.button("\U0001f5d1 Clear conversation", use_container_width=True):
        st.session_state.agent_messages = []
        st.session_state.agent_chat_log = []
        st.session_state.pending_alert = None
        st.rerun()

    st.markdown("---")
    st.caption(f"Model: `{settings.agent_model}`")
    st.caption(f"Max iterations / turn: `{settings.agent_max_iterations}`")
    api_base = settings.api_base_url
    st.caption(f"Dispatcher: `{api_base}`")


# ─── Header ────────────────────────────────────────────────────────────────

st.title("\U0001f916 SAP Security Agent")
st.caption("Ask anything about your security data. The agent has read-only HANA access and can draft alerts for your approval.")

if not settings.anthropic_api_key:
    st.error(
        "ANTHROPIC_API_KEY is not set. Add it to `.env` and restart the dashboard "
        "(`make dashboard`). See `.env.example` for the template."
    )
    st.stop()


# ─── Agent factory ─────────────────────────────────────────────────────────


def _get_agent():
    """Lazily build the Agent on first use and stash it in session state."""
    if st.session_state.agent_instance is None:
        from src.agent.agent import Agent

        st.session_state.agent_instance = Agent()
    return st.session_state.agent_instance


# ─── Renderers ─────────────────────────────────────────────────────────────


def _render_tool_call(call: dict[str, Any]) -> None:
    """Render one tool call as a collapsed st.status / expander."""
    name = call["name"]
    args = call.get("args") or {}
    result = call.get("result") or {}
    ok = call.get("ok", False)

    icon = "✓" if ok else "⚠"
    label = f"{icon} {name}({_compact_args(args)})"
    with st.expander(label, expanded=False):
        if not ok:
            st.error(result.get("error", "tool error"))
            return
        render_hint = result.get("_render", "raw")
        if render_hint == "scalar":
            _render_scalar(name, result)
        elif render_hint == "table":
            _render_table(result)
        else:
            st.json({k: v for k, v in result.items() if not k.startswith("_")})


def _compact_args(args: dict[str, Any]) -> str:
    if not args:
        return ""
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


def _render_scalar(name: str, result: dict[str, Any]) -> None:
    """Render counters / percentile dicts as st.metric."""
    if name == "get_anomaly_count":
        st.metric("Anomalies", result.get("count", 0), help=f"Since {result.get('since')}")
    elif name == "get_log_volume":
        st.metric("Logs ingested", f"{result.get('count', 0):,}", help=f"Since {result.get('since')}")
    elif name == "get_mttd_stats":
        c1, c2, c3 = st.columns(3)
        c1.metric("p50 MTTD", f"{result.get('p50_ms') or '—'} ms")
        c2.metric("p95 MTTD", f"{result.get('p95_ms') or '—'} ms")
        c3.metric("samples", result.get("sample_count", 0))
    else:
        st.json({k: v for k, v in result.items() if not k.startswith("_")})


def _render_table(result: dict[str, Any]) -> None:
    rows = result.get("rows", [])
    if not rows:
        st.info("No rows.")
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ─── Chat log replay ───────────────────────────────────────────────────────

for idx, entry in enumerate(st.session_state.agent_chat_log):
    role = entry["role"]
    with st.chat_message(role):
        if entry.get("text"):
            st.markdown(entry["text"])
        for call in entry.get("tool_calls", []):
            _render_tool_call(call)

        # Alert-confirm UI is rendered inline in the assistant turn that
        # produced the preview, so the "Approve & send" button lives next
        # to the draft it would deliver.
        pending = st.session_state.pending_alert
        if (
            role == "assistant"
            and pending is not None
            and pending.get("status") == "pending"
            and pending.get("source_idx") == idx
        ):
            st.markdown("**Alert preview:**")
            st.code(pending["message"])
            col_ok, col_no = st.columns([1, 4])
            if col_ok.button("✅ Approve & send", key=f"approve_{idx}"):
                agent = _get_agent()
                resp = agent.post_alert(pending["message"])
                if resp.get("ok"):
                    st.session_state.pending_alert = {**pending, "status": "sent"}
                    st.toast("Alert delivered", icon="✅")
                    # Inject a synthetic user message so the agent can
                    # reference the send on subsequent turns.
                    st.session_state.agent_messages.append(
                        {"role": "user",
                         "content": f"[System: alert sent OK ({resp.get('status', 'sent')})]"}
                    )
                else:
                    st.error(f"Alert send failed: {resp.get('status')}")
                st.rerun()
            if col_no.button("Discard preview", key=f"discard_{idx}"):
                st.session_state.pending_alert = {**pending, "status": "dropped"}
                st.rerun()


# ─── Input handling ────────────────────────────────────────────────────────


def _submit_user_turn(user_text: str) -> None:
    """Run the agent and append the result to both message logs."""
    # If a draft was pending, mark it dropped — analyst moved on.
    pending = st.session_state.pending_alert
    if pending is not None and pending.get("status") == "pending":
        st.session_state.pending_alert = {**pending, "status": "dropped"}

    agent = _get_agent()
    st.session_state.agent_chat_log.append(
        {"role": "user", "text": user_text, "tool_calls": []}
    )

    with st.spinner("Thinking..."):
        try:
            result = agent.run(
                user_text, history=st.session_state.agent_messages
            )
        except Exception as exc:
            st.session_state.agent_chat_log.append(
                {"role": "assistant",
                 "text": f"⚠ Agent error: `{type(exc).__name__}: {exc}`",
                 "tool_calls": []}
            )
            return

    assistant_idx = len(st.session_state.agent_chat_log)
    st.session_state.agent_chat_log.append(
        {"role": "assistant",
         "text": result.assistant_text or "_(no text)_",
         "tool_calls": [_trace_to_dict(t) for t in result.tool_calls],
         "iterations": result.iterations}
    )

    if result.pending_alert_preview:
        st.session_state.pending_alert = {
            "message": result.pending_alert_preview,
            "status": "pending",
            "source_idx": assistant_idx,
        }


def _trace_to_dict(trace) -> dict[str, Any]:
    """Convert an agent ToolCallTrace dataclass to a dict for chat-log JSON."""
    return {
        "name": trace.name,
        "args": trace.args,
        "result": trace.result,
        "ok": trace.ok,
    }


# Run quick action if one was clicked in the sidebar this turn.
quick_action_locals = locals().get("quick_action")
user_input = st.chat_input("Ask about anomalies, MTTD, current window, or draft an alert...")

if user_input:
    _submit_user_turn(user_input)
    st.rerun()
elif quick_action_locals:
    _submit_user_turn(quick_action_locals)
    st.rerun()


# Suppress "unused" — referenced via locals() above.
_ = json
