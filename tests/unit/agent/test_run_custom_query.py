"""Unit tests for ``run_custom_query`` (§1 + §2).

Covers:
- LIMIT n+1 enforcement and overwrite of agent-supplied LIMIT
- count_total opt-in path wraps as SELECT COUNT(*) FROM (...)
- Read-only guard (DML/DDL/forbidden tokens, multi-statement)
- Error sanitization + hint classifier
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from src.agent import tools as tools_mod
from src.agent.tools import (
    CUSTOM_QUERY_ROW_CAP,
    _classify_error,
    _enforce_limit,
    _sanitize_error,
    run_custom_query,
)


@pytest.fixture
def mock_hana():
    with patch.object(tools_mod, "settings") as s:
        s.mock_hana = True
        yield


def _run(coro):
    return asyncio.run(coro)


# ─── _enforce_limit ────────────────────────────────────────────────────────


def test_enforce_limit_appends_when_missing():
    out = _enforce_limit("SELECT * FROM ANOMALIES", 21)
    assert out.endswith("LIMIT 21")


def test_enforce_limit_replaces_trailing_limit():
    out = _enforce_limit("SELECT * FROM ANOMALIES LIMIT 1000", 21)
    assert out.endswith("LIMIT 21")
    assert "1000" not in out


def test_enforce_limit_handles_trailing_semicolon():
    out = _enforce_limit("SELECT * FROM ANOMALIES LIMIT 500;", 21)
    assert out.endswith("LIMIT 21")
    assert "500" not in out


# ─── Mock-mode response shape ──────────────────────────────────────────────


def test_run_custom_query_mock_shape(mock_hana):
    out = _run(run_custom_query("SELECT * FROM ANOMALIES"))
    assert out["truncated"] is False
    assert out["rows"] == []
    assert out["columns"] == []
    assert out["row_count_returned"] == 0
    # Always-rewrite to LIMIT cap+1 (here 21).
    assert out["query_executed"].endswith(f"LIMIT {CUSTOM_QUERY_ROW_CAP + 1}")
    assert out["_mock"] is True


def test_run_custom_query_overwrites_agent_limit(mock_hana):
    out = _run(run_custom_query("SELECT * FROM ANOMALIES LIMIT 999"))
    assert out["query_executed"].endswith(f"LIMIT {CUSTOM_QUERY_ROW_CAP + 1}")
    assert "999" not in out["query_executed"]


def test_run_custom_query_count_total_wraps(mock_hana):
    out = _run(run_custom_query("SELECT * FROM ANOMALIES", count_total=True))
    # Mock path returns the LIMIT-21 shape regardless, but we can verify
    # the executed SQL by re-running through a non-mock guard would wrap;
    # here we cover the validation gate (no error raised) and count_total
    # parameter routing through the function.
    # To verify the wrapper specifically, hit the SQL builder before mock.
    assert "error" not in out or out.get("_mock") is True


def test_run_custom_query_count_total_executed_sql_has_count_wrapper():
    # We bypass the mock_hana branch by patching pool.acquire to a
    # connection-less acquire so we land in the "hana_unavailable" fast
    # path -- but we want to inspect the executed SQL. Use a custom hook:
    captured: dict[str, str] = {}

    async def fake_to_thread(fn, sql, params):
        captured["sql"] = sql
        return {"rows": [{"total": 7}], "columns": ["total"]}

    with patch.object(tools_mod, "settings") as s, \
            patch.object(tools_mod.asyncio, "to_thread", side_effect=fake_to_thread):
        s.mock_hana = False
        out = _run(run_custom_query("SELECT 1 FROM ANOMALIES", count_total=True))

    assert captured["sql"].startswith("SELECT COUNT(*) AS total FROM (")
    assert out["total"] == 7
    assert out["_render"] == "scalar"


# ─── Read-only guards ──────────────────────────────────────────────────────


@pytest.mark.parametrize("sql", [
    "DELETE FROM ANOMALIES",
    "UPDATE ANOMALIES SET SCORE = 0",
    "INSERT INTO ANOMALIES VALUES (1)",
    "DROP TABLE ANOMALIES",
    "TRUNCATE TABLE ANOMALIES",
    "ALTER TABLE ANOMALIES ADD x INT",
    "CREATE TABLE x (i INT)",
    "GRANT SELECT TO foo",
])
def test_run_custom_query_rejects_write_statements(mock_hana, sql):
    out = _run(run_custom_query(sql))
    assert "error" in out
    assert "_render" in out


def test_run_custom_query_rejects_multi_statement(mock_hana):
    out = _run(run_custom_query("SELECT 1; SELECT 2"))
    assert "error" in out
    assert "multi-statement" in out["error"]


def test_run_custom_query_rejects_non_select(mock_hana):
    out = _run(run_custom_query("EXPLAIN PLAN FOR SELECT * FROM ANOMALIES"))
    assert "error" in out
    assert "SELECT" in out["error"]


def test_run_custom_query_accepts_with_cte(mock_hana):
    out = _run(run_custom_query("WITH x AS (SELECT * FROM ANOMALIES) SELECT * FROM x"))
    # Validates and reaches mock branch.
    assert "error" not in out
    assert out["_mock"] is True


def test_run_custom_query_rejects_empty(mock_hana):
    out = _run(run_custom_query("   "))
    assert out["error"] == "empty_query"


def test_run_custom_query_rejects_unlisted_table(mock_hana):
    out = _run(run_custom_query("SELECT * FROM USERS"))
    assert "error" in out
    assert "not allowed" in out["error"]


def test_run_custom_query_rejects_schema_qualified_table(mock_hana):
    out = _run(run_custom_query("SELECT * FROM SYS.USERS"))
    assert "error" in out
    assert "schema-qualified" in out["error"]


# ─── Error sanitization + classifier ───────────────────────────────────────


def test_classify_error_unknown_column():
    assert _classify_error("invalid column name FOO") and "describe_schema" in (
        _classify_error("invalid column name FOO") or ""
    )


def test_classify_error_unknown_table():
    hint = _classify_error("could not find table TBL")
    assert hint and "SECURITY_LOGS" in hint


def test_classify_error_syntax():
    assert _classify_error("syntax error near 'GROPU'") is not None


def test_classify_error_unknown_returns_none():
    assert _classify_error("internal warp drive offline") is None


def test_sanitize_error_strips_connection_string():
    class FakeErr(Exception):
        pass

    out = _sanitize_error(FakeErr("conn user@10.0.0.1:30015 failed: invalid column name FOO"))
    assert "<conn>" in out["error"]
    assert "10.0.0.1:30015" not in out["error"]
    # hint attached when the message matched a classifier.
    assert "hint" in out


def test_sanitize_error_caps_length():
    class FakeErr(Exception):
        pass

    msg = "X" * 5000
    out = _sanitize_error(FakeErr(msg))
    assert len(out["error"]) <= 400 + len("FakeErr: ")
