# Conversational HANA + SAP API Agent — Plan (v1)

> Saved 2026-04-29. Working doc — supersede with v2 once the
> insight-drawing extension below is approved.

## Context
TEC × SAP Hackathon eliminatory phase is May 12–14. We are adding a new
Streamlit page (`5_Agent.py`) backed by a Claude tool-use loop so an analyst
can ask natural-language questions about the live SOC state and (with
explicit confirmation) push alerts to `/alert`. The agent must reuse the
repositories/fetchers/webhook we already have rather than re-implementing
HANA SQL or HTTP calls.

## Phase 1 audit — what exists vs. what's missing

### Already exists (reuse as-is)
- `src/storage/repositories.py`
  - `LogRepository.recent_logs(limit=50)` — newest logs, mock-aware.
  - `AnomalyRepository.recent_anomalies(limit=50)` — newest anomalies.
  - `AnomalyRepository.mttd_samples(window_minutes=60)` — list of `pipeline_mttd_ms` for charting.
- `src/storage/pool.py::HanaPool.acquire()` — async ctx mgr; yields `None` in mock mode. Use `asyncio.to_thread` for cursor work.
- `src/ingestion/sap_log_fetcher.py`
  - `fetch_logs(page=1)` — single page from `/logs/current`.
  - `fetch_all_logs()` — calls `/info` then loops pages (uses `/info` *internally*, doesn't return it).
- `src/alerting/sap_webhook.py`
  - `send_alert(anomaly_row, evidence_df)` — full pipeline path; **not** what the agent wants because it auto-builds WHAT/WHEN/WHY.
  - `format_alert_message(anomaly_row, evidence_df)` — useful for previewing.
- `src/dashboard/_api.py` — cached `fetch_metrics`, `fetch_anomalies`, `sidebar_brand`, `inject_sidebar_css`, `dashboard_autorefresh`. Reuse for the agent-page chrome.
- `src/common/config.py::settings` — frozen dataclass; mock_hana / mock_api / mock_webhook properties.

### Missing / must add
- **Repository read methods** the agent tools depend on:
  - `AnomalyRepository.count_since(hours)` → int
  - `AnomalyRepository.top_source_ips(hours, limit)` → list[{source_ip, count, max_score}]
  - `AnomalyRepository.recent(limit, severity=None, hours=None)` (extends `recent_anomalies`)
  - `AnomalyRepository.mttd_percentiles(hours)` → {p50, p95, count}
  - `LogRepository.count_since(hours)` → int
  - `ModelVersionRepository.latest()` → dict (currently write-only).
  All must honour `settings.mock_hana` and use `asyncio.to_thread` around hdbcli cursors, matching `recent_anomalies`/`recent_logs`.
- **`/info` exposure** in `sap_log_fetcher.py`: extract `async def fetch_info() -> dict` from the inline call; have `fetch_all_logs()` use it.
- **Free-form alert helper** in `sap_webhook.py`: `async def post_alert_message(message: str) -> dict` (validates `<=300` chars, posts `{"message": ...}` to `/alert`, reuses auth/retry).
- **Settings:** `anthropic_api_key`, `agent_model`, `agent_max_iterations` + `.env.example`.
- **`anthropic>=0.40,<1`** in `requirements.txt`.

## Tool list (v1 — the canned set)

All in `src/agent/tools.py`, JSON-serialisable returns, `{"error": "..."}` on failure.

### HANA
1. `get_anomaly_count(hours=24)`
2. `get_top_suspicious_ips(limit=10, hours=1)` → `[{source_ip, count, min_score}]`. **Sign convention: isolation-forest scores are negative, lower = more anomalous, so `min_score` (the most-negative observed) is what we sort by.** Documented in every tool description and in the system prompt.
3. `get_recent_anomalies(limit=20, threat_level=None, hours=None)` — `threat_level ∈ {HIGH, MEDIUM, LOW}`, matches the `THREAT_LEVEL` column. (Renamed from `severity` — the column was never called severity.)
4. `get_mttd_stats(hours=24)` → `{p50_ms, p95_ms, sample_count}`
5. `get_log_volume(hours=24)`
6. `get_model_info()`

`run_custom_query` is **deferred to v2** — see `docs/agent_plan_v2_insights.md` §1. v1 ships canned tools only. None of the v1 acceptance conversations need dynamic SQL.

### SAP API
7. `get_current_window_info()` — wraps `fetch_info()`.
8. `get_current_logs_sample(max_rows=10)` — first page of live `/logs/current`. **Hard cap = 10**, projected to `(SOURCE_IP, EVENT_DESCRIPTION, DATETIME, STATUS, LOG_TYPE)` only. Drops LLM_*/JSON columns to prevent context blowout (v2 will add structural smart truncation; v1 prevents the issue by projection).
9. `submit_alert(what, when, why)` — formats + validates + returns preview only. Real send happens from the Streamlit page after the analyst clicks **Approve & send**, which calls `post_alert_message`. State model in §"Alert state machine" below.

## HANA access path — via FastAPI dispatcher

**Decision (2026-04-29):** agent tools call into FastAPI rather than opening a
second HanaPool inside the Streamlit process. Today no Streamlit page owns a
HANA connection — they all hit FastAPI. We keep that pattern.

- New endpoint `POST /agent/tool` in `src/api/main.py` (or a new
  `src/api/agent_routes.py` mounted under `/agent`).
- Body: `{"name": "<tool_name>", "args": {...}}`. Response:
  `{"ok": true, "result": <json>}` or `{"ok": false, "error": "..."}`.
- A single dispatcher route keeps the FastAPI surface small (one route now,
  one route in v2 — no per-tool boilerplate). Tool name → handler map lives
  in `src/agent/tools.py` and is reused by both the dispatcher and v2's
  in-process orchestrator.
- HANA-backed tools route through the dispatcher; SAP-API-backed tools
  (`get_current_window_info`, `get_current_logs_sample`, `post_alert_message`)
  are called directly from the Streamlit page via `httpx` against the SAP
  API — there's no point in a HANA pool for those.
- Streamlit-side: a thin sync wrapper `_call_tool(name, args) -> dict` that
  posts to `{settings.api_base_url}/agent/tool`. 3s timeout. Reuses the same
  `_safe_get`/`_safe_post` pattern as `src/dashboard/_api.py`.
- Repository methods still live in `src/storage/repositories.py` — the
  dispatcher just calls them. Single HANA pool owner (FastAPI) is preserved.

## Alert state machine

`st.session_state["pending_alert"]` carries the full state:

```python
{
  "message": "WHAT: ... WHEN: ... WHY: ...",   # the formatted preview
  "drafted_at": <isoformat>,
  "source_turn_idx": <int>,                     # which assistant message contains the preview
  "status": "pending" | "sent" | "superseded" | "dropped",
}
```

Rules:
- `submit_alert` tool sets `pending_alert` with `status="pending"` and returns
  the preview as the tool result. The agent's final assistant text describes
  the preview and mentions that the analyst must click confirm.
- The Streamlit page renders an **Approve & send** button inline in the
  assistant chat message that drafted it (not in the sidebar) — only when
  `pending_alert.status == "pending"` and `source_turn_idx` matches.
- Click → call `post_alert_message`. On success, set `status="sent"` and
  append a synthetic user message `"[Alert sent ✓ — message: <...>]"` so the
  agent can reference it on the next turn. On failure, set `status="pending"`
  and surface an `st.error`.
- A second `submit_alert` call **replaces** the pending preview: previous
  entry's status flips to `"superseded"` (kept in session state for audit;
  button hidden). UI shows a small "previous draft superseded" note.
- A new user message arriving while `status="pending"` flips status to
  `"dropped"` silently — analyst moved on.

## Conversation history bound

Cap `st.session_state.messages` at **20 rounds** (40 entries: user/assistant
pairs). When the cap is exceeded, drop the oldest pair. The system prompt is
unaffected (it's not in the message list — passed as `system=` per call).

## File map

| Path | Action |
|---|---|
| `src/agent/__init__.py` | new — package marker |
| `src/agent/tools.py` | new — tool impls + `TOOL_REGISTRY` (name → callable) |
| `src/agent/schemas.py` | new — Anthropic JSON-schemas |
| `src/agent/agent.py` | new — tool-use loop, max `AGENT_MAX_ITERATIONS`; calls FastAPI dispatcher for HANA tools |
| `src/api/agent_routes.py` | new — `POST /agent/tool` dispatcher; reads `TOOL_REGISTRY` from `src/agent/tools.py` |
| `src/api/main.py` | edit — mount agent_routes |
| `src/dashboard/pages/5_Agent.py` | new — chat UI, sidebar quick actions, alert-confirm flow |
| `src/storage/repositories.py` | edit — add the new read methods |
| `src/ingestion/sap_log_fetcher.py` | edit — extract `fetch_info()` |
| `src/alerting/sap_webhook.py` | edit — add `post_alert_message()` |
| `src/common/config.py` | edit — three new fields |
| `.env.example` | edit |
| `requirements.txt` | edit |

## Safety rails
- `run_custom_query` validator lives in `tools.py` — runs regardless of caller.
- `submit_alert` is **two-step**: agent returns preview; UI sends after click. No agent path posts without UI approval.
- Empty `ANTHROPIC_API_KEY` → page shows `st.error(...)` and skips chat input.
- Mock HANA mode: every new repository method has a mock branch.

## Verification
1. `make lint && make test-unit` green; add unit tests for SQL validator and `post_alert_message` length validation.
2. `make dashboard` locally with `ANTHROPIC_API_KEY` set + `MOCK_HANA=1`. Walk through the five required conversations from the spec.
3. `make api` still serves `/health`.
4. With `ANTHROPIC_API_KEY=""`, page renders error and doesn't crash.

## Branching
**Single branch for v1+v2:** cut `feat/conversational-agent` off `dev`. Land
v1 and v2 as a sequence of cumulative PRs against `dev` on the same branch
(settings → tools-canned → agent-loop → page → semantic-model → helpers →
hardened-run-custom-query → tracing → tests). v1→v2 is purely additive;
splitting into two branches doubles merge overhead with no isolation benefit.
**Never** push to `main`.

**Precondition:** the in-flight `feat/codebase-cleanup` work must be at a
safe checkpoint (committed/pushed) before we cut the new branch.

## Resolved decisions (2026-04-29)
- **Model:** `claude-sonnet-4-6`.
- **`run_custom_query` deferred to v2** (no throwaway v1 implementation).
- **HANA access via FastAPI dispatcher** (`POST /agent/tool`), not direct
  repo import in Streamlit. Single HanaPool owner (FastAPI) preserved.
- **Single feature branch** `feat/conversational-agent` for v1+v2.
- **Column naming:** `threat_level` not `severity`; `min_score` not
  `max_score` (sign convention documented).

## Open extension (v2 — pending design approval)
User wants the agent to be able to *draw novel insights*, Snowflake
Cortex / Snowflake Intelligence style — not just answer the canned
questions. See `docs/agent_plan_v2_insights.md` (forthcoming) for the
proposed semantic-layer + analytical-helpers design.
