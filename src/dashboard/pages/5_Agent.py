"""
pages/5_Agent.py
----------------
Conversational SOC agent — chat with the SAP AI Security data.

Hosts a Claude tool-use loop (``src/agent/agent.py::Agent``) wired
directly to the in-process tool dispatcher (no FastAPI hop). The page
drives an async generator that yields ``AgentEvent`` records:
``tool_started`` opens an ``st.status``, ``tool_finished``/``tool_failed``
update it, ``text_delta`` streams into the assistant message, ``final``
terminates the turn.

``submit_alert`` produces a preview the analyst must explicitly approve
before any HTTP request reaches ``/alert`` — see the alert state machine
below (``alert_drafts`` session list).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pandas as pd
import streamlit as st
from src.agent.events import AgentEvent
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
    st.session_state.agent_messages = []  # type: ignore[attr-defined]

if "agent_chat_log" not in st.session_state:
    # UI-side chat log: list of {role, text, tool_calls, ...}. Kept
    # separate from agent_messages because the latter is verbatim
    # Anthropic blocks (text + tool_use + tool_result) and doesn't
    # render cleanly in st.chat_message.
    st.session_state.agent_chat_log = []  # type: ignore[attr-defined]

if "alert_drafts" not in st.session_state:
    # Audit trail of every alert preview the agent has produced.
    # status ∈ {"pending", "sent", "superseded", "dropped"}
    st.session_state.alert_drafts = []  # type: ignore[attr-defined]

if "agent_instance" not in st.session_state:
    st.session_state.agent_instance = None


# ─── Sidebar ───────────────────────────────────────────────────────────────

with st.sidebar:
    sidebar_brand("AGENT")

    st.markdown("### Quick actions")
    quick_action: str | None = None
    if st.button("\U0001f4ca Current window status", use_container_width=True):
        quick_action = (
            "What does the current 30-minute window look like? "
            "Any threats I should know about?"
        )
    if st.button("\U0001f6a8 Top 5 suspicious IPs (1h)", use_container_width=True):
        quick_action = "Show me the top 5 most suspicious IPs in the last hour."
    if st.button("⚡ MTTD summary (24h)", use_container_width=True):
        quick_action = "What's our MTTD over the last 24 hours? Give me the p50 and p95."
    if st.button("\U0001f50d Recent HIGH anomalies", use_container_width=True):
        quick_action = "Show me the most recent HIGH severity anomalies."
    if st.button("\U0001f4c8 Anomaly trend (24h)", use_container_width=True):
        quick_action = "Plot the anomaly count per hour over the last 24 hours."
    if st.button("\U0001f30d Top regions by log volume", use_container_width=True):
        quick_action = "Break down log volume by region over the last 24 hours."

    st.markdown("---")
    if st.button("\U0001f5d1 Clear conversation", use_container_width=True):
        st.session_state.agent_messages = []
        st.session_state.agent_chat_log = []
        st.session_state.alert_drafts = []
        st.rerun()

    st.markdown("---")
    st.caption(f"Model: `{settings.agent_model}`")
    st.caption(f"Max iterations / turn: `{settings.agent_max_iterations}`")


# ─── Header ────────────────────────────────────────────────────────────────

st.title("\U0001f916 SAP Security Agent")
st.caption(
    "Ask anything about your security data. Read-only HANA access, "
    "live SAP API probes, and analyst-approved alert delivery."
)

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


# ─── Result renderers ──────────────────────────────────────────────────────


def _compact_args(args: dict[str, Any]) -> str:
    if not args:
        return ""
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


def _render_result(name: str, result: dict[str, Any]) -> None:
    """Render a tool result inside an st.status or expander.

    Picks a widget based on the ``_render`` hint set by each tool:
    ``scalar`` / ``table`` / ``bar_chart`` / ``line_chart`` / ``raw``.
    """
    if not isinstance(result, dict) or not result:
        st.write("(empty result)")
        return
    if "error" in result:
        st.error(result["error"])
        if hint := result.get("hint"):
            st.caption(f"Hint: {hint}")
        if qa := result.get("query_attempted"):
            st.code(qa, language="sql")
        return

    hint = result.get("_render", "raw")
    if hint == "scalar":
        _render_scalar(name, result)
    elif hint == "table":
        _render_table(result)
    elif hint == "bar_chart":
        _render_bar_chart(result)
    elif hint == "line_chart":
        _render_line_chart(result)
    else:
        st.json({k: v for k, v in result.items() if not k.startswith("_")})

    # Always show the executed SQL for run_custom_query so the analyst
    # can audit what the agent actually ran.
    if name == "run_custom_query" and (qe := result.get("query_executed")):
        st.caption(f"`{qe}`")


def _render_scalar(name: str, result: dict[str, Any]) -> None:
    if name == "get_anomaly_count":
        st.metric("Anomalies", result.get("count", 0),
                  help=f"Since {result.get('since')}")
    elif name == "get_log_volume":
        st.metric("Logs ingested", f"{result.get('count', 0):,}",
                  help=f"Since {result.get('since')}")
    elif name == "get_mttd_stats":
        c1, c2, c3 = st.columns(3)
        c1.metric("p50 MTTD", f"{result.get('p50_ms') or '—'} ms")
        c2.metric("p95 MTTD", f"{result.get('p95_ms') or '—'} ms")
        c3.metric("samples", result.get("sample_count", 0))
    elif name == "compare_windows":
        wa = result.get("window_a", {})
        wb = result.get("window_b", {})
        delta_pct = result.get("delta_pct")
        c1, c2, c3 = st.columns(3)
        c1.metric(f"Last {wa.get('hours','?')}h", wa.get("value", 0))
        c2.metric(f"Prior {wb.get('hours','?')}h", wb.get("value", 0))
        delta_lbl = (
            f"{delta_pct:+.1f}%" if isinstance(delta_pct, int | float)
            else "n/a"
        )
        c3.metric("Δ", result.get("delta_abs", 0), delta_lbl)
    else:
        st.json({k: v for k, v in result.items() if not k.startswith("_")})


def _render_table(result: dict[str, Any]) -> None:
    rows = result.get("rows", [])
    if not rows:
        st.info("No rows.")
        return
    # Filter out the placeholder string truncate_for_llm appends.
    rows_clean = [r for r in rows if isinstance(r, dict)]
    df = pd.DataFrame(rows_clean)
    st.dataframe(df, use_container_width=True, hide_index=True)
    if result.get("truncated"):
        st.caption("⚠ Truncated to 20 rows. Ask for an aggregation if you need more.")


def _render_bar_chart(result: dict[str, Any]) -> None:
    rows = [r for r in result.get("rows", []) if isinstance(r, dict)]
    if not rows:
        st.info("No rows.")
        return
    df = pd.DataFrame(rows)
    if "dim" in df.columns and "metric_value" in df.columns:
        chart_df = df.set_index("dim")[["metric_value"]]
        chart_df.columns = [result.get("metric", "value")]
        st.bar_chart(chart_df)
    st.dataframe(df, use_container_width=True, hide_index=True)


def _render_line_chart(result: dict[str, Any]) -> None:
    rows = [r for r in result.get("rows", []) if isinstance(r, dict)]
    if not rows:
        st.info("No rows.")
        return
    df = pd.DataFrame(rows)
    if "bucket" in df.columns and "metric_value" in df.columns:
        df = df.copy()
        df["bucket"] = pd.to_datetime(df["bucket"], errors="coerce")
        chart_df = df.set_index("bucket")[["metric_value"]]
        chart_df.columns = [result.get("metric", "value")]
        st.line_chart(chart_df)
    st.dataframe(df, use_container_width=True, hide_index=True)


# ─── Replay of past chat turns ─────────────────────────────────────────────


def _render_tool_call(call: dict[str, Any]) -> None:
    """Render one persisted tool call from the chat log."""
    name = call["name"]
    args = call.get("args") or {}
    result = call.get("result") or {}
    ok = call.get("ok", False)
    icon = "✓" if ok else "⚠"
    label = f"{icon} {name}({_compact_args(args)})"
    with st.expander(label, expanded=False):
        _render_result(name, result)


for idx, entry in enumerate(st.session_state.agent_chat_log):
    role = entry["role"]
    with st.chat_message(role):
        if entry.get("text"):
            st.markdown(entry["text"])
        for call in entry.get("tool_calls", []):
            _render_tool_call(call)

        # Alert-confirm UI: rendered in the assistant turn that produced
        # the preview so "Approve & send" sits next to the draft. Multiple
        # drafts can attach to different assistant turns; pick the one
        # whose source_idx matches.
        if role == "assistant":
            for d_idx, draft in enumerate(st.session_state.alert_drafts):
                if draft.get("source_idx") != idx:
                    continue
                status = draft.get("status", "pending")
                st.markdown("**Alert preview:**")
                st.code(draft["message"])
                if status == "pending":
                    col_ok, col_no = st.columns([1, 4])
                    if col_ok.button("✅ Approve & send",
                                     key=f"approve_{idx}_{d_idx}"):
                        agent = _get_agent()
                        resp = asyncio.run(agent.post_alert(draft["message"]))
                        if resp.get("ok"):
                            st.session_state.alert_drafts[d_idx] = {
                                **draft, "status": "sent",
                            }
                            st.toast("Alert delivered", icon="✅")
                            st.session_state.agent_messages.append({
                                "role": "user",
                                "content": (
                                    f"[System: alert sent OK "
                                    f"({resp.get('status', 'sent')})]"
                                ),
                            })
                        else:
                            st.error(f"Alert send failed: {resp.get('status')}")
                        st.rerun()
                    if col_no.button("Discard preview",
                                     key=f"discard_{idx}_{d_idx}"):
                        st.session_state.alert_drafts[d_idx] = {
                            **draft, "status": "dropped",
                        }
                        st.rerun()
                elif status == "superseded":
                    st.caption("↪ Superseded by a later draft.")
                elif status == "sent":
                    st.caption("✅ Sent.")
                elif status == "dropped":
                    st.caption("✗ Discarded.")


# ─── Live event-stream renderer ────────────────────────────────────────────


def _drive_generator(gen):
    """Synchronously iterate an async generator on a private event loop.

    Streamlit page bodies are sync; the agent is async. We open a fresh
    loop for the duration of one user turn and pump events out.
    """
    loop = asyncio.new_event_loop()
    try:
        while True:
            try:
                yield loop.run_until_complete(gen.__anext__())
            except StopAsyncIteration:
                return
    finally:
        loop.close()


def _stream_assistant_turn(user_text: str) -> dict[str, Any]:
    """Render the assistant message live; return a dict ready to persist
    into ``agent_chat_log`` (text + tool_calls + iteration count + any
    pending alert preview).
    """
    agent = _get_agent()
    gen = agent.run(user_text, history=st.session_state.agent_messages)

    text_so_far = ""
    text_placeholder = st.empty()
    tool_calls: list[dict[str, Any]] = []
    open_status: Any = None
    open_label: str | None = None
    pending_preview: str | None = None

    for ev in _drive_generator(gen):
        if ev.kind == "tool_started":
            tool_calls.append({
                "name": ev.tool_name, "args": ev.args or {},
                "result": {}, "ok": True,
            })
            open_status = st.status(
                f"\U0001f50d {ev.human_label}", expanded=False,
            )
            open_label = ev.human_label
            open_status.write({"args": ev.args or {}})

        elif ev.kind == "tool_finished":
            full = ev.result or {}
            if tool_calls:
                tool_calls[-1]["result"] = full
                tool_calls[-1]["ok"] = True
            if open_status is not None:
                open_status.update(label=f"✓ {open_label or ev.human_label}",
                                   state="complete", expanded=False)
                with open_status:
                    _render_result(ev.tool_name or "", full)
            open_status = None

        elif ev.kind == "tool_failed":
            full = ev.result or {"error": ev.error}
            if tool_calls and tool_calls[-1].get("name") == ev.tool_name:
                tool_calls[-1]["result"] = full
                tool_calls[-1]["ok"] = False
            else:
                # Synthetic event from the circuit breaker (no preceding
                # tool_started). Still persist it so the audit trail shows
                # what happened.
                tool_calls.append({
                    "name": ev.tool_name, "args": {},
                    "result": full, "ok": False,
                })
            if open_status is not None:
                lbl = (f"⚠ {open_label or ev.human_label} "
                       f"(retry {ev.retry_n})")
                open_status.update(label=lbl, state="error", expanded=True)
                with open_status:
                    _render_result(ev.tool_name or "", full)
                open_status = None
            else:
                # Render the synthetic circuit-breaker event inline.
                with st.status(f"⚠ {ev.human_label}",
                               state="error", expanded=True) as new_st:
                    _render_result(ev.tool_name or "", full)
                _ = new_st  # keep ref so type checker is happy

        elif ev.kind == "text_delta":
            text_so_far += ev.chunk or ""
            text_placeholder.markdown(text_so_far)

        elif ev.kind == "final":
            payload = ev.payload or {}
            final_text = payload.get("text") or text_so_far or "_(no text)_"
            text_placeholder.markdown(final_text)
            pending_preview = payload.get("pending_alert_preview")
            text_so_far = final_text

    return {
        "role": "assistant",
        "text": text_so_far,
        "tool_calls": tool_calls,
        "pending_alert_preview": pending_preview,
    }


# ─── Input handling ────────────────────────────────────────────────────────


def _submit_user_turn(user_text: str) -> None:
    """Append the user's message, stream the assistant response live,
    persist both to the chat log, and rerun for clean replay."""
    # Any pending draft the analyst didn't act on is now obsolete.
    for d_idx, draft in enumerate(st.session_state.alert_drafts):
        if draft.get("status") == "pending":
            st.session_state.alert_drafts[d_idx] = {**draft, "status": "dropped"}

    st.session_state.agent_chat_log.append(
        {"role": "user", "text": user_text, "tool_calls": []}
    )
    with st.chat_message("user"):
        st.markdown(user_text)

    with st.chat_message("assistant"):
        try:
            assistant_entry = _stream_assistant_turn(user_text)
        except Exception as exc:
            st.error(f"Agent error: `{type(exc).__name__}: {exc}`")
            st.session_state.agent_chat_log.append({
                "role": "assistant",
                "text": f"⚠ Agent error: `{type(exc).__name__}: {exc}`",
                "tool_calls": [],
            })
            return

    assistant_idx = len(st.session_state.agent_chat_log)
    st.session_state.agent_chat_log.append(assistant_entry)

    if preview := assistant_entry.get("pending_alert_preview"):
        # Mark any earlier-pending draft as superseded — the agent has
        # produced a new one before the analyst acted on the old.
        for d_idx, draft in enumerate(st.session_state.alert_drafts):
            if draft.get("status") == "pending":
                st.session_state.alert_drafts[d_idx] = {
                    **draft, "status": "superseded",
                }
        st.session_state.alert_drafts.append({
            "message": preview,
            "status": "pending",
            "source_idx": assistant_idx,
            "drafted_at": datetime.now(UTC).isoformat(),
        })


# Run quick action if one was clicked in the sidebar this turn.
quick_action_locals = locals().get("quick_action")
user_input = st.chat_input(
    "Ask about anomalies, MTTD, current window, or draft an alert..."
)

if user_input:
    _submit_user_turn(user_input)
    st.rerun()
elif quick_action_locals:
    _submit_user_turn(quick_action_locals)
    st.rerun()


# Suppress "unused" — referenced via the AgentEvent type in renderers.
_ = AgentEvent
