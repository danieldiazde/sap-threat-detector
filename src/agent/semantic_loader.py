"""
semantic_loader.py
------------------
Loads ``src/agent/semantic_model.yaml`` once at import and exposes:

- ``DDL_BLOCK``: a pre-rendered, terse table-and-column listing the system
  prompt embeds verbatim. Stable across the whole session, so it sits
  inside the cached system block (~700 tokens, free after the first call).
- ``describe_table(name)``: rich per-table metadata for the v2
  ``describe_schema`` tool. Returns ``None`` if the table is unknown.
- ``known_tables()``: set of canonical table names, for tool input
  validation.

The bare DDL block and the rich payload are derived from the same file —
single source of truth, per ``docs/CONVERSATIONAL_AGENT.md`` §3.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_YAML_PATH = Path(__file__).with_name("semantic_model.yaml")


@lru_cache(maxsize=1)
def _load() -> dict[str, Any]:
    with _YAML_PATH.open() as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "tables" not in data:
        raise ValueError(f"semantic_model.yaml malformed: {_YAML_PATH}")
    return data


def _format_ddl_line(col: dict[str, Any]) -> str:
    name = col["name"]
    type_ = col["type"]
    nullable = col.get("nullable", True)
    null_marker = "" if nullable else " NOT NULL"
    base = f"{name:<22} {type_}{null_marker}"
    note = col.get("null_semantics") or ""
    if note and not nullable:
        note = ""  # NOT NULL columns don't need a null comment
    if note:
        base = f"{base:<55} -- {note}"
    return base


def _build_ddl_block(model: dict[str, Any]) -> str:
    chunks: list[str] = []
    for table_name, table in model["tables"].items():
        desc = (table.get("description") or "").strip().replace("\n", " ")
        chunks.append(f"-- {table_name}  ({desc})")
        for col in table["columns"]:
            chunks.append(_format_ddl_line(col))
        chunks.append("")
    return "\n".join(chunks).strip()


def known_tables() -> set[str]:
    return set(_load()["tables"].keys())


def describe_table(name: str) -> dict[str, Any] | None:
    """Return the rich metadata for one table, or None if unknown.

    Shape matches what the v2 ``describe_schema`` tool returns to the LLM.
    """
    name_upper = name.upper().strip()
    table = _load()["tables"].get(name_upper)
    if table is None:
        return None
    return {
        "table": name_upper,
        "description": table.get("description", "").strip(),
        "columns": [dict(c) for c in table["columns"]],
        "metrics": dict(table.get("metrics", {})),
        "example_queries": list(table.get("example_queries", [])),
    }


DDL_BLOCK: str = _build_ddl_block(_load())
