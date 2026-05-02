"""
agent.py
--------
Conversational SOC agent — async-generator orchestrator.

``Agent.run(user_message, history=...)`` is an ``AsyncIterator[AgentEvent]``.
The Streamlit page (``src/dashboard/pages/5_Agent.py``) drives it
synchronously and renders each event into a UI primitive
(``st.status`` per tool, streamed text, terminal ``final`` event).

Design (see ``docs/CONVERSATIONAL_AGENT.md``):

  §1   ``run_custom_query`` row-cap is enforced inside ``tools.py``.
  §2   Circuit breaker: 3 ``run_custom_query`` failures per turn halt
       further dynamic-SQL dispatches and force a final natural-language
       reply.
  §3   The DDL block from ``semantic_loader`` is injected into the
       system prompt so the model has schema knowledge without a tool
       round-trip.
  §4   Layer A: every tool result passes through ``truncate_for_llm``
       at the tool boundary. Layer B: ``compact_old_observations``
       collapses heavy (>1KB) tool_results older than 3 iterations
       before each ``messages.create`` call.
  §5   ``AgentEvent`` is the unit of UI communication.
  §10b Anthropic prompt caching marks both the system prompt block and
       the tools array. Per-tool ``asyncio.wait_for`` timeout (10s).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from src.agent.events import AgentEvent, label_for
from src.agent.schemas import TOOL_SCHEMAS
from src.agent.semantic_loader import DDL_BLOCK
from src.agent.tools import dispatch as dispatch_tool
from src.agent.truncation import (
    compact_old_observations,
    summarize_for_event,
    truncate_for_llm,
)
from src.common.config import settings
from src.common.logging import get_logger

logger = get_logger(__name__)

# Conversation history hard cap. Old turns are dropped beyond this; the
# system prompt is unaffected.
MAX_HISTORY_ROUNDS: int = 20

# Per-tool outer timeout. ``run_custom_query`` has its own internal 10s
# cap; this is the guard for canned tools and helpers.
PER_TOOL_TIMEOUT_S: float = 10.0

# Circuit breaker: 3 SQL failures per turn halts further dispatches.
SQL_FAILURE_LIMIT: int = 3


SYSTEM_PROMPT = f"""You are the SAP SOC security analyst assistant. You have read-only \
access to live SAP HANA data and the SAP SOC API.

# Style
- Be concise. Lead with the answer; show numbers; flag threats clearly.
- Before issuing any tool call beyond a trivial counter, briefly state \
your hypothesis ("I expect X concentrated in Y because…"). After results \
land, say whether they matched.
- Don't restate the user's question.

# Important conventions
- ANOMALY_SCORE comes from an isolation forest. Scores are NEGATIVE and \
LOWER = more anomalous.
- THREAT_LEVEL is one of 'high', 'medium', 'low' (lowercase in HANA).
- MTTD = milliseconds between log ingestion and detection. Lower is better.

# Schema (always available — do NOT call describe_schema just to learn \
table or column names; only call it when you need the rich metadata, \
column meanings, or example queries)

```sql
{DDL_BLOCK}
```

# Tool selection rules
- For canned questions (counts, top-N, MTTD), prefer the named tools \
(get_anomaly_count, get_top_suspicious_ips, get_mttd_stats, get_log_volume, \
get_model_info, get_recent_anomalies).
- For "compare/breakdown/trend/correlate" questions, use the helpers \
(breakdown_by, compare_windows, time_series, correlate). These are \
parameterized and validated — they will reject unknown metric or \
dimension values immediately.
- For live SAP API data, use get_current_window_info / get_current_logs_sample.
- Use run_custom_query ONLY when no other tool fits. When you do:
    * NEVER fetch raw rows just to count them. Use SELECT COUNT(*).
    * NEVER fetch raw rows just to aggregate them. Use GROUP BY.
    * For JSON columns (RULE_IDS, *_JSON), use JSON_VALUE(col, '$.path').
    * Results are capped at 20 rows. truncated=True means **rewrite as an \
aggregation**, NOT "rerun with a bigger limit".
    * Use ADD_SECONDS(CURRENT_TIMESTAMP, -hours*3600) for time windows — \
this HANA install does not have ADD_HOURS.
    * On error, read the `error` and `hint` fields, optionally call \
describe_schema(table_name), then rewrite the query. You have at most \
2 retries before the system stops you.

# Iteration budget
- You have at most {{max_iterations}} tool-use rounds per user message. \
Prefer fewer.

# Alerting
- submit_alert returns a preview only. The user must click "Approve & \
send" in the UI before anything is delivered. Never claim an alert has \
been sent until you observe a confirmation in conversation history.

# Honesty
- If a tool returns {{"error": ...}} beyond your retry budget, say so \
plainly. Do not invent numbers.
"""


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


def _render_system_prompt(max_iterations: int) -> str:
    return SYSTEM_PROMPT.replace("{max_iterations}", str(max_iterations))


def _tools_with_cache() -> list[dict[str, Any]]:
    """Return TOOL_SCHEMAS with cache_control on the last tool.

    Anthropic prompt caching keys off ``cache_control`` breakpoints —
    putting it on the last tool caches the entire tools array as one
    block.
    """
    tools = [dict(t) for t in TOOL_SCHEMAS]
    if tools:
        tools[-1] = {**tools[-1], "cache_control": {"type": "ephemeral"}}
    return tools


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


class Agent:
    """Async-generator orchestrator.

    Usage:

        async for event in agent.run(user_msg, history=msgs):
            # update UI per event.kind
            ...

    ``history`` is the Anthropic-format conversation. We mutate it in
    place so the caller (Streamlit page) holds a single source of truth.
    """

    def __init__(
        self,
        anthropic_api_key: str | None = None,
        model: str | None = None,
        max_iterations: int | None = None,
        client: Any | None = None,
    ) -> None:
        self._key = anthropic_api_key or settings.anthropic_api_key
        if client is None and not self._key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._model = model or settings.agent_model
        self._max_iter = max_iterations or settings.agent_max_iterations
        if client is not None:
            # Test injection: a stub with the same .messages.create() shape.
            self._client = client
        else:
            try:
                from anthropic import AsyncAnthropic
            except ImportError as exc:
                raise RuntimeError(
                    "anthropic package not installed; pip install anthropic"
                ) from exc
            self._client = AsyncAnthropic(api_key=self._key)

    async def run(
        self,
        user_message: str,
        history: list[dict[str, Any]] | None = None,
    ) -> AsyncIterator[AgentEvent]:
        msgs: list[dict[str, Any]] = list(history or [])
        msgs.append({"role": "user", "content": user_message})

        system_blocks = [
            {
                "type": "text",
                "text": _render_system_prompt(self._max_iter),
                "cache_control": {"type": "ephemeral"},
            }
        ]
        tools = _tools_with_cache()

        sql_failures = 0
        circuit_tripped = False
        pending_preview: str | None = None

        for iteration in range(self._max_iter):
            # Layer B compaction before sending.
            api_msgs = compact_old_observations(trim_history(msgs), age_threshold=3)

            try:
                response = await self._client.messages.create(
                    model=self._model,
                    max_tokens=2048,
                    system=system_blocks,
                    tools=tools,
                    messages=api_msgs,
                )
            except Exception as exc:
                logger.exception("agent.api_error")
                yield AgentEvent.final({
                    "text": f"Sorry — the model API call failed ({exc}).",
                    "iterations": iteration,
                    "error": str(exc),
                })
                return

            assistant_blocks = [b.model_dump() for b in response.content]
            msgs.append({"role": "assistant", "content": assistant_blocks})

            for block in response.content:
                if block.type == "text" and block.text:
                    yield AgentEvent.text_delta(block.text)

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                # end_turn (or stop_sequence) — model is done.
                yield AgentEvent.final({
                    "text": _extract_text(msgs),
                    "iterations": iteration + 1,
                    "stop_reason": response.stop_reason,
                    "pending_alert_preview": pending_preview,
                })
                if history is not None:
                    history.clear()
                    history.extend(msgs)
                return

            tool_result_blocks: list[dict[str, Any]] = []
            for block in tool_uses:
                args = dict(block.input) if block.input else {}
                human_label = label_for(block.name)

                # Circuit breaker: skip further run_custom_query dispatches
                # once tripped. Synthesize the canned error so the agent
                # has something to react to in its next turn.
                if circuit_tripped and block.name == "run_custom_query":
                    result: dict[str, Any] = {
                        "error": "circuit_breaker_tripped",
                        "message": (
                            f"{SQL_FAILURE_LIMIT} SQL failures this turn — "
                            "the system stopped further run_custom_query calls. "
                            "Reply in natural language: explain what you tried "
                            "and ask the user for clarification."
                        ),
                        "_render": "raw",
                    }
                    yield AgentEvent.tool_failed(
                        block.name,
                        result["error"],
                        retry_n=sql_failures,
                        human_label=human_label,
                        result=result,
                    )
                else:
                    yield AgentEvent.tool_started(block.name, args, human_label)
                    result = await self._run_one_tool(block.name, args)
                    # Layer A truncation at the tool boundary.
                    result = truncate_for_llm(result)

                    res_dict = result if isinstance(result, dict) else {}
                    if block.name == "run_custom_query" and "error" in res_dict:
                        sql_failures += 1
                        yield AgentEvent.tool_failed(
                            block.name,
                            str(res_dict.get("error", "")),
                            retry_n=sql_failures,
                            human_label=human_label,
                            result=res_dict,
                        )
                        if sql_failures >= SQL_FAILURE_LIMIT:
                            circuit_tripped = True
                    elif "error" in res_dict:
                        yield AgentEvent.tool_failed(
                            block.name,
                            str(res_dict.get("error", "")),
                            retry_n=0,
                            human_label=human_label,
                            result=res_dict,
                        )
                    else:
                        yield AgentEvent.tool_finished(
                            block.name,
                            summarize_for_event(res_dict),
                            human_label,
                            result=res_dict,
                        )

                    if (
                        block.name == "submit_alert"
                        and isinstance(result, dict)
                        and result.get("preview")
                    ):
                        pending_preview = result["preview"]

                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result, default=str),
                    "is_error": isinstance(result, dict) and "error" in result,
                })

            msgs.append({"role": "user", "content": tool_result_blocks})

        # Hit max iterations without an end_turn.
        yield AgentEvent.final({
            "text": _extract_text(msgs) or "(iteration budget exhausted)",
            "iterations": self._max_iter,
            "stop_reason": "max_iterations",
            "pending_alert_preview": pending_preview,
        })
        if history is not None:
            history.clear()
            history.extend(msgs)

    async def post_alert(self, message: str) -> dict[str, Any]:
        """Send an analyst-approved alert via the SAP webhook (in-process).

        Calling ``post_alert_message`` directly avoids needing the FastAPI
        process running just so the dashboard can confirm a draft.
        """
        from src.alerting.sap_webhook import post_alert_message
        try:
            return await post_alert_message(message)
        except Exception as exc:
            logger.exception("agent.post_alert_failed")
            return {"ok": False, "status": "error", "error": str(exc)}

    async def _run_one_tool(
        self, name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Dispatch with an outer asyncio timeout. Never raises."""
        try:
            return await asyncio.wait_for(
                dispatch_tool(name, args),
                timeout=PER_TOOL_TIMEOUT_S,
            )
        except TimeoutError:
            return {
                "error": "tool_timeout",
                "elapsed_ms": int(PER_TOOL_TIMEOUT_S * 1000),
                "_render": "raw",
            }
        except Exception as exc:
            logger.exception("agent.tool_error", extra={"tool": name})
            return {"error": f"{type(exc).__name__}: {exc}"[:400], "_render": "raw"}
