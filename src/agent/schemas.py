"""
schemas.py
----------
Anthropic ``tools=[...]`` JSON-schema definitions for the v1 agent.

Kept separate from ``tools.py`` so the schema (which is what the LLM
sees) can be reviewed/diffed without scanning past Python implementations.

Tool order here is the order Anthropic sees them — keep frequent /
"first-resort" tools near the top.
"""

from __future__ import annotations

from typing import Any

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "get_anomaly_count",
        "description": (
            "Count anomalies detected in the last N hours. "
            "Use this for direct count questions like 'how many anomalies in the last 24 hours'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 720,
                    "default": 24,
                    "description": "Time window in hours (1-720).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_top_suspicious_ips",
        "description": (
            "Top N source IPs ranked by anomaly count within the last N hours. "
            "Returns each IP's count and min_score (the most-negative ANOMALY_SCORE "
            "observed for that IP — isolation-forest scores are negative, lower = "
            "more anomalous, so min_score is the worst score)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 10,
                },
                "hours": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 720,
                    "default": 1,
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_recent_anomalies",
        "description": (
            "Recent anomaly rows (newest first). Optional filters: threat_level "
            "(HIGH/MEDIUM/LOW) and hours window."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer", "minimum": 1, "maximum": 50, "default": 20,
                },
                "threat_level": {
                    "type": "string",
                    "enum": ["HIGH", "MEDIUM", "LOW"],
                    "description": "Filter to a specific threat level.",
                },
                "hours": {
                    "type": "integer", "minimum": 1, "maximum": 720,
                    "description": "Optional time window.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_mttd_stats",
        "description": (
            "Pipeline MTTD percentiles (p50, p95) over the last N hours. "
            "MTTD = milliseconds between log ingestion and anomaly detection."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer", "minimum": 1, "maximum": 720, "default": 24,
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_log_volume",
        "description": "Total number of security logs ingested in the last N hours.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer", "minimum": 1, "maximum": 720, "default": 24,
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_model_info",
        "description": (
            "Currently registered detection model — version tag, type, training "
            "date, contamination, training sample count, CV scores."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_current_window_info",
        "description": (
            "Live GET /info on the SAP SOC API. Returns the current 30-minute "
            "window's start/end timestamps, total record count and total page "
            "count. Use to answer 'what does the current window look like'."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_current_logs_sample",
        "description": (
            "First page of live /logs/current, projected to a small column set "
            "(source_ip, event_description, datetime, status, log_type) and "
            "capped at 10 rows. Use sparingly — this hits the live SAP API."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "max_rows": {
                    "type": "integer", "minimum": 1, "maximum": 10, "default": 10,
                },
            },
            "required": [],
        },
    },
    {
        "name": "submit_alert",
        "description": (
            "Draft an alert preview from WHAT/WHEN/WHY. **Does not send.** "
            "Returns a preview (max 300 chars) which the analyst must explicitly "
            "approve in the UI before delivery. Always tell the user that they "
            "need to click 'Approve & send' to actually deliver the alert."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "what": {
                    "type": "string",
                    "description": "What threat happened (kind + target).",
                },
                "when": {
                    "type": "string",
                    "description": "When it occurred (ISO timestamp or human description).",
                },
                "why": {
                    "type": "string",
                    "description": "Why it triggered (key indicators / scores).",
                },
            },
            "required": ["what", "when", "why"],
        },
    },
]
