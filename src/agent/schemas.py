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
        "name": "describe_schema",
        "description": (
            "Rich metadata for one table: every column's type, meaning, null "
            "semantics and common WHERE filters, plus example queries and "
            "named metric expressions. Call this when the bare DDL in the "
            "system prompt is not enough — typically before writing a custom "
            "SQL query against an unfamiliar column or after a SQL error."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "enum": ["SECURITY_LOGS", "ANOMALIES", "MODEL_VERSIONS"],
                },
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "sample_table",
        "description": (
            "Return the most recent N rows of a table (max 10). Use to see "
            "real example values when meanings/enums in describe_schema "
            "are not sufficient. Hits HANA — use sparingly."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "enum": ["SECURITY_LOGS", "ANOMALIES", "MODEL_VERSIONS"],
                },
                "n": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
            },
            "required": ["table"],
        },
    },
    {
        "name": "breakdown_by",
        "description": (
            "Group a metric by a dimension over the last N hours. "
            "Picks the right table automatically based on the metric. "
            "Returns up to top_n rows ranked by metric_value DESC. "
            "Use for 'top X by Y in the last Z hours' questions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "metric": {
                    "type": "string",
                    "enum": [
                        "anomaly_count", "log_volume", "mttd_p50", "mttd_p95",
                        "high_severity_count", "login_failure_count",
                        "llm_token_total", "llm_cost_total",
                    ],
                },
                "dimension": {
                    "type": "string",
                    "enum": [
                        "source_ip", "sap_application", "region_code",
                        "macro_region", "log_type", "http_method",
                        "threat_level", "llm_prompt_category", "sap_source_type",
                    ],
                },
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "top_n": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            },
            "required": ["metric", "dimension"],
        },
    },
    {
        "name": "compare_windows",
        "description": (
            "Compare a metric across two adjacent equal-length time windows. "
            "window_a is the recent window of length window_a_h hours ending "
            "now; window_b is the prior window of length window_b_h hours "
            "ending where window_a starts. Returns delta_abs and delta_pct."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "metric": {
                    "type": "string",
                    "enum": [
                        "anomaly_count", "log_volume", "mttd_p50", "mttd_p95",
                        "high_severity_count", "login_failure_count",
                        "llm_token_total", "llm_cost_total",
                    ],
                },
                "window_a_h": {"type": "integer", "minimum": 1, "maximum": 720, "default": 1},
                "window_b_h": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
            },
            "required": ["metric"],
        },
    },
    {
        "name": "time_series",
        "description": (
            "Bucketed time series of a metric over the last N hours. "
            "Returns rows of {bucket, metric_value}. The UI renders as a "
            "line chart automatically."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "metric": {
                    "type": "string",
                    "enum": [
                        "anomaly_count", "log_volume", "mttd_p50", "mttd_p95",
                        "high_severity_count", "login_failure_count",
                        "llm_token_total", "llm_cost_total",
                    ],
                },
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "bucket_minutes": {
                    "type": "integer",
                    "enum": [1, 5, 15, 30, 60, 240, 1440],
                    "default": 60,
                },
            },
            "required": ["metric"],
        },
    },
    {
        "name": "correlate",
        "description": (
            "Co-occurrence matrix for two SECURITY_LOGS dimensions over the "
            "last N hours. Returns the top_n (a, b) pairs by count. Use for "
            "'are X and Y happening together?' questions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dim_a": {
                    "type": "string",
                    "enum": [
                        "source_ip", "sap_application", "region_code",
                        "macro_region", "log_type", "http_method",
                        "llm_prompt_category", "sap_source_type",
                    ],
                },
                "dim_b": {
                    "type": "string",
                    "enum": [
                        "source_ip", "sap_application", "region_code",
                        "macro_region", "log_type", "http_method",
                        "llm_prompt_category", "sap_source_type",
                    ],
                },
                "hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
                "top_n": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
            },
            "required": ["dim_a", "dim_b"],
        },
    },
    {
        "name": "run_custom_query",
        "description": (
            "Run a read-only SQL SELECT against HANA (SECURITY_LOGS, "
            "ANOMALIES, MODEL_VERSIONS). Use ONLY when no other tool fits. "
            "Rules: (a) results are capped at 20 rows — if truncated=True, "
            "rewrite as an aggregation, do NOT 'rerun with bigger limit'. "
            "(b) For counts, write SELECT COUNT(*) — do NOT fetch rows to "
            "count them. (c) For top-N, use GROUP BY + ORDER BY. (d) For "
            "JSON columns (RULE_IDS, *_JSON), use JSON_VALUE(col, '$.path'). "
            "(e) On error, read the hint, optionally call describe_schema, "
            "and rewrite. You have 2 retries before the system stops you."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "A single SELECT statement. No semicolons separating multiple statements; no DML/DDL.",
                },
                "count_total": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, wrap the query in SELECT COUNT(*) FROM (...) and return only the total. Off by default.",
                },
            },
            "required": ["sql"],
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
