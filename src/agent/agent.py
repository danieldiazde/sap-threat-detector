"""
agent.py
--------
v1 conversational-agent orchestrator.

Synchronous, single-pass: takes a user message + prior history, runs an
Anthropic tool-use loop (capped at ``settings.agent_max_iterations``),
dispatches each ``tool_use`` block via ``POST /agent/tool``, and returns
the final assistant text along with the recorded tool-call trace for
the Streamlit page to render.

Async event-streaming and the §5 tracing pattern from
``docs/agent_plan_v2_insights.md`` are v2 work — they are not blockers
for the v1 acceptance conversations.

A note on ``_render`` hints: tool results carry a ``_render`` field
intended for the UI, not the LLM. We pass results through to Claude
unmodified anyway — the field is small enough not to matter, and
removing it would require the schema-aware bookkeeping that v2 is
already going to add.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from src.agent.schemas import TOOL_SCHEMAS
from src.common.config import settings
from src.common.logging import get_logger

logger = get_logger(__name__)

# Conversation history hard cap (per docs/agent_plan.md). Old turns are
# dropped beyond this; system prompt is unaffected.
MAX_HISTORY_ROUNDS: int = 20

DISPATCHER_TIMEOUT_S: float = 15.0
ALERT_TIMEOUT_S: float = 15.0


SYSTEM_PROMPT = """You are the SAP SOC security analyst assistant for the TEC x SAP \
hackathon detector. You have read-only access to live SAP HANA data and the SAP \
SOC API through a small set of tools.

# Style
- Be concise. Lead with the answer; back it up with concrete numbers.
- When you flag a threat, name the IP / app / region and the score.
- Don't restate the user's question.

# Important conventions
- ANOMALY_SCORE is from an isolation forest. Scores are NEGATIVE and \
LOWER = more anomalous. The `min_score` field returned by \
`get_top_suspicious_ips` is the worst (most-negative) score we saw for \
that IP.
- THREAT_LEVEL is one of HIGH, MEDIUM, LOW.
- MTTD = milliseconds between log ingestion and detection. Lower is better.

# Alerting flow
- `submit_alert` only DRAFTS a preview. It does not send. The user must \
click "Approve & send" in the UI before delivery. When you call it, \
tell the user the preview is ready for their approval.
- Never claim an alert was sent unless you have observed a confirmation \
from the user in the conversation history.

# Tool selection
- For counts and top-N questions, use the dedicated tools (faster than \
fetching rows and counting).
- For "what does the current window look like" use `get_current_window_info`.
- Use `get_current_logs_sample` sparingly — it hits the live SAP API.

# Honesty
- If a tool returns `{"error": ...}`, say so plainly. Don't invent numbers.
"""


@dataclass
class ToolCallTrace:
    """One tool invocation, captured for UI rendering."""

    name: str
    args: dict[str, Any]
    result: dict[str, Any]
    ok: bool


@dataclass
class AgentRunResult:
    """Result of one user turn."""

    assistant_text: str
    tool_calls: list[ToolCallTrace] = field(default_factory=list)
    iterations: int = 0
    pending_alert_preview: str | None = None
    stop_reason: str | None = None
    error: str | None = None


def trim_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cap conversation history at MAX_HISTORY_ROUNDS user/assistant pairs.

    Anthropic messages alternate user/assistant; one "round" is two
    entries. We trim from the front so the most recent context is kept.
    Tool-result messages count toward the cap because they live in the
    same list.
    """
    cap = MAX_HISTORY_ROUNDS * 2
    if len(history) <= cap:
        return history
    return history[-cap:]


class Agent:
    """Synchronous Claude tool-use loop wired to the FastAPI dispatcher."""

    def __init__(
        self,
        api_base_url: str | None = None,
        anthropic_api_key: str | None = None,
        model: str | None = None,
        max_iterations: int | None = None,
    ) -> None:
        # Late import so tests / dashboards that never instantiate Agent
        # don't pay the import cost (and don't fail if anthropic isn't
        # installed in some minimal env).
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "anthropic package not installed; pip install anthropic"
            ) from exc

        from anthropic import Anthropic

        self._api_base_url = (api_base_url or settings.api_base_url).rstrip("/")
        self._key = anthropic_api_key or settings.anthropic_api_key
        if not self._key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._model = model or settings.agent_model
        self._max_iter = max_iterations or settings.agent_max_iterations
        self._client = Anthropic(api_key=self._key)
        self._http = httpx.Client(timeout=DISPATCHER_TIMEOUT_S)

    # ─── Public ────────────────────────────────────────────────────────

    def run(
        self,
        user_message: str,
        history: list[dict[str, Any]] | None = None,
    ) -> AgentRunResult:
        """Run one user turn through the tool-use loop.

        ``history`` is the in-memory conversation (Anthropic message
        format). Returns an :class:`AgentRunResult` with the final
        assistant text, the tool-call trace for UI rendering, and any
        pending alert preview the LLM produced.
        """
        msgs: list[dict[str, Any]] = list(history or [])
        msgs.append({"role": "user", "content": user_message})

        traces: list[ToolCallTrace] = []
        pending_preview: str | None = None
        stop_reason: str | None = None

        iteration = 0
        for iteration in range(self._max_iter):  # noqa: B007 — kept for else-branch  reporting
            response = self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,  # type: ignore[arg-type]
                messages=trim_history(msgs),
            )
            stop_reason = response.stop_reason

            # Append the assistant response (text + tool_use blocks) verbatim.
            assistant_blocks = [b.model_dump() for b in response.content]
            msgs.append({"role": "assistant", "content": assistant_blocks})

            # Find any tool_use blocks; if none, we're done.
            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                break

            # Dispatch each tool, append a single user message containing
            # tool_result blocks (Anthropic expects them grouped).
            tool_result_blocks: list[dict[str, Any]] = []
            for block in tool_uses:
                args = dict(block.input) if block.input else {}
                trace_result = self._call_tool(block.name, args)
                traces.append(
                    ToolCallTrace(
                        name=block.name,
                        args=args,
                        result=trace_result["result"],
                        ok=trace_result["ok"],
                    )
                )

                # Track the most recent submit_alert preview so the page
                # can render the Approve & send button.
                if (
                    block.name == "submit_alert"
                    and trace_result["ok"]
                    and trace_result["result"].get("preview")
                ):
                    pending_preview = trace_result["result"]["preview"]

                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(trace_result["result"], default=str),
                    "is_error": not trace_result["ok"],
                })

            msgs.append({"role": "user", "content": tool_result_blocks})

        else:
            # Loop hit max_iter without an end_turn.
            iteration = self._max_iter
            stop_reason = "max_iterations"

        assistant_text = _extract_text(msgs)
        # Persist the trimmed history back so callers don't grow unbounded.
        history_out = trim_history(msgs)
        # Mutate in place so the caller's list is in sync (Streamlit holds
        # the reference in st.session_state).
        if history is not None:
            history.clear()
            history.extend(history_out)

        return AgentRunResult(
            assistant_text=assistant_text,
            tool_calls=traces,
            iterations=iteration + 1 if traces else 1,
            pending_alert_preview=pending_preview,
            stop_reason=stop_reason,
        )

    def post_alert(self, message: str) -> dict[str, Any]:
        """Send a pre-formatted alert via /agent/post_alert. UI-only."""
        try:
            resp = self._http.post(
                f"{self._api_base_url}/agent/post_alert",
                json={"message": message},
                timeout=ALERT_TIMEOUT_S,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            logger.error("agent.post_alert.http_error", extra={"error": str(exc)})
            return {"ok": False, "status": "transport_error", "error": str(exc)}

    # ─── Internal ──────────────────────────────────────────────────────

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """POST /agent/tool and return the dispatcher envelope."""
        try:
            resp = self._http.post(
                f"{self._api_base_url}/agent/tool",
                json={"name": name, "args": args},
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            logger.error(
                "agent.tool.http_error",
                extra={"tool": name, "error": str(exc)},
            )
            return {
                "ok": False,
                "result": {
                    "error": f"dispatcher_unreachable: {exc}",
                    "_render": "raw",
                },
            }


def _extract_text(messages: list[dict[str, Any]]) -> str:
    """Pull the assistant text out of the most recent assistant message."""
    for msg in reversed(messages):
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", [])
        if isinstance(content, str):
            return content
        chunks: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                chunks.append(block.get("text", ""))
        if chunks:
            return "\n".join(chunks).strip()
    return ""
