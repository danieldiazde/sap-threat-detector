"""
events.py
---------
``AgentEvent`` is the unit of communication between the agent's async
generator (``Agent.run`` in v2) and the Streamlit page that renders the
chat. Each event maps to one UI primitive:

- ``tool_started`` / ``tool_finished`` / ``tool_failed`` → ``st.status``
  containers (which persist as the audit trail — see v2 plan §5).
- ``text_delta``    → fed into ``st.write_stream``.
- ``final``         → terminal event; carries the assistant's last
  message and the per-turn metadata (iteration count, pending alert
  preview if ``submit_alert`` ran).

Pure data class — no Streamlit, asyncio, or HTTP imports here so this
module stays test-friendly and importable in any context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

EventKind = Literal[
    "tool_started",
    "tool_finished",
    "tool_failed",
    "text_delta",
    "final",
]


@dataclass(frozen=True)
class AgentEvent:
    kind: EventKind
    # Tool-related events:
    tool_name: str | None = None
    human_label: str | None = None
    args: dict[str, Any] | None = None
    summary: dict[str, Any] | None = None
    # Full post-truncation tool result, attached to tool_finished/tool_failed
    # so the UI can render rows/charts (summary alone is too lossy).
    result: dict[str, Any] | None = None
    error: str | None = None
    retry_n: int | None = None
    # Text streaming:
    chunk: str | None = None
    # Terminal:
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def tool_started(
        cls, tool_name: str, args: dict[str, Any], human_label: str
    ) -> AgentEvent:
        return cls(
            kind="tool_started",
            tool_name=tool_name,
            human_label=human_label,
            args=dict(args or {}),
        )

    @classmethod
    def tool_finished(
        cls,
        tool_name: str,
        summary: dict[str, Any],
        human_label: str,
        result: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return cls(
            kind="tool_finished",
            tool_name=tool_name,
            human_label=human_label,
            summary=dict(summary or {}),
            result=dict(result) if result is not None else None,
        )

    @classmethod
    def tool_failed(
        cls,
        tool_name: str,
        error: str,
        retry_n: int,
        human_label: str,
        result: dict[str, Any] | None = None,
    ) -> AgentEvent:
        return cls(
            kind="tool_failed",
            tool_name=tool_name,
            human_label=human_label,
            error=error,
            retry_n=retry_n,
            result=dict(result) if result is not None else None,
        )

    @classmethod
    def text_delta(cls, chunk: str) -> AgentEvent:
        return cls(kind="text_delta", chunk=chunk)

    @classmethod
    def final(cls, payload: dict[str, Any]) -> AgentEvent:
        return cls(kind="final", payload=dict(payload or {}))


# Human labels for tool calls — used when the agent orchestrator yields
# tool_started/tool_finished events. Keep terse; the analyst sees them
# inline in chat.
TOOL_HUMAN_LABELS: dict[str, str] = {
    "get_anomaly_count": "Counting anomalies",
    "get_top_suspicious_ips": "Ranking suspicious IPs",
    "get_recent_anomalies": "Pulling recent anomalies",
    "get_mttd_stats": "Computing MTTD percentiles",
    "get_log_volume": "Counting logs",
    "get_model_info": "Reading active model card",
    "get_current_window_info": "Probing /info",
    "get_current_logs_sample": "Sampling /logs/current",
    "submit_alert": "Drafting alert preview",
    # v2 tools:
    "describe_schema": "Reading schema metadata",
    "sample_table": "Sampling table values",
    "breakdown_by": "Breaking down metric",
    "compare_windows": "Comparing time windows",
    "time_series": "Building time series",
    "correlate": "Computing co-occurrence",
    "run_custom_query": "Running custom SQL",
}


def label_for(tool_name: str) -> str:
    return TOOL_HUMAN_LABELS.get(tool_name, tool_name)
