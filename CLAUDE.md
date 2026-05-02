# CLAUDE.md

## Build & Run

```bash
make install          # pip install -r requirements-dev.txt (local dev; CF uses requirements.txt)
make api              # uvicorn src.api.main:app --reload
make dashboard        # streamlit run src/dashboard/app.py
make mock             # generate 5000 mock SAP logs
make train            # train model from data/samples/
make run              # run pipeline locally (no FastAPI)
```

## Test & Lint

```bash
make lint             # ruff check src/ tests/ scripts/
make format           # ruff format src/ tests/ scripts/
make test             # unit + integration tests
make test-unit        # pytest tests/unit/ -v
make test-model       # pytest tests/model/ -v
make test-integration # pytest tests/integration/ -v
```

## Deploy

```bash
make deploy           # cf push -f infra/manifest.yml
```

Deployment manifest: `infra/manifest.yml`. Secrets set via GitHub Actions (`deploy.yml`).

## Architecture

Single CF app: FastAPI web process + asyncio background pipeline.
Pipeline: OBSERVE (ingestion) -> ANALYZE (features) -> DETECT (predict) -> RESPOND (alert).
Streamlit dashboard runs locally only, not on CF.

## Key Conventions

- **No `print()`** in `src/` — use `from src.common.logging import get_logger; logger = get_logger(__name__)`. Scripts in `scripts/` may use `print()` for CLI output.
- **Import from direct modules, not `src.model`**:
  `from src.model.train import train` (correct)
  `from src.model import train` (WRONG — namespace conflict with re-exported function)
- **No `os.getenv()`** outside `src/common/config.py` — import `settings` instead
- **joblib** for model persistence, not pickle
- **Settings dataclass** in `src/common/config.py` — frozen, loaded once from env
- Mock mode is derived from env vars, never explicitly set
- All async code uses `asyncio` (no threads)

## Branch Rules — READ BEFORE PUSHING

**Golden path (one-way flow):**
`feat/<your-work>` → PR → `dev` → (PM merges) → `main`

Nothing else is supported. Anything that goes directly into `main` from a feat
branch is a bug, regardless of how urgent it feels in the moment.

### Day-to-day commands

```bash
# Start a new piece of work
git checkout dev
git pull origin dev
git checkout -b feat/my-thing

# Keep your feat branch fresh (pull from dev, NEVER from main)
git fetch origin
git merge origin/dev           # or: git rebase origin/dev

# Ship it
git push -u origin feat/my-thing
gh pr create --base dev        # target is ALWAYS dev
```

### Hard rules

- Branch off **`dev`**, not `main`.
- Open PRs against **`dev`**. Never against `main`.
- **Never push to `main`.** **Never merge a feat branch into `main`.**
- Only the PM promotes `dev → main`, and only when CI is green on `dev`.
- When refreshing a feat branch, pull from `dev`, not `main`.

### For teammates using Claude Code

Claude Code sessions can suggest whatever looks locally convenient — including
things that violate this flow. If your session proposes any of the following,
**stop it and redirect**:

- `git push origin main` or `git push -f origin main`
- `gh pr create --base main` from a feat branch
- `git checkout -b feat/... main` (branching off main instead of dev)
- `git merge origin/main` into your feat branch (should be `origin/dev`)
- Cherry-picking feat commits directly onto `main`

If you realize your feat branch was cut from `main` by mistake, rebase it
onto `dev` before pushing:
```bash
git rebase --onto origin/dev $(git merge-base HEAD origin/main) HEAD
```
and flag it in the team channel so the PM can double-check.

### Why this is strict — incident on 2026-04-17

`main` had drifted **22 commits ahead of `dev`** because feat branches
(`feat/auto-retrain-real-data`, `fix/sap-api-field-mapping`, CF deploy
hotfixes, SAP API endpoint fixes, HANA param fixes, Python 3.10 compat,
the `/anomalies` endpoint, the LLM log-type filter, and more) had been
merged directly into `main`, bypassing `dev`. Meanwhile `dev` had 4 of its
own commits (`source_ip` filter, circular-import fix, two feat merges).

Consequences:
- `dev` was missing every prod hotfix on `main`. The next deploy from `dev`
  would have regressed CF startup fixes, SAP pagination, HANA queries, and
  dashboard features in production.
- A broken test (`_alert_id` rename on main with no test update) had been
  masking itself because nobody was running `dev` tests against main's code.
- Feature work on `feat/llm-anomaly-detector` was cut from `main`, so any
  merge of it into `dev` would have pulled in 18 unrelated commits.

Reconciliation (commit `66f9d4f`): merged `main → dev` with a combined
`features.py` (LLM filter + `source_ip` safety net), fixed the broken
`_alert_id` test import, then fast-forwarded `main` to match `dev` so the
two branches are byte-identical again.

**The rule exists because the fix was expensive. Don't repeat the incident.**

## Project Structure

```
src/
  api/          FastAPI endpoints (/health, /ready, /predict, /metrics)
  alerting/     Webhook, deduplication, incident reports
  common/       Config, logging, metrics, time utils
  dashboard/    Streamlit SOC dashboard
  ingestion/    SAP log fetcher + parser
  model/        Features, train, predict, DBSCAN, versioning
  storage/      HANA pool, repositories, migrations
  pipeline.py   Orchestrator
scripts/        CLI tools (generate_mock_logs, train_model, run_pipeline_local)
tests/          Unit, integration, model tests
infra/          CF manifest
```

## Dual MTTD

- `pipeline_mttd_ms` = detected_at - ingested_at (internal processing latency)
- `e2e_mttd_ms` = detected_at - log.datetime (real-world detection time)
- MTTD is the key competition metric (40% of evaluation score)

## Schema evolution — SECURITY_LOGS

The `SECURITY_LOGS` table was expanded in commit `5b5d777` (2026-04-21) from
6 columns to 22. Rows ingested before that commit have NULLs in the 16 new
columns. The training pipeline currently fills NaN with 0 (the final
`.fillna(0)` in `src/model/features.py::feature_matrix`), which silently
biases pre-expansion rows toward "zero-diversity" profiles.

**Before making any change that depends on `FEATURE_COLUMNS` or the feature
matrix, read the latest `data/reports/schema_audit_<date>.md`** (generated
by `python scripts/audit_schema_expansion.py`) and the decision table in
`docs/MODEL_JOURNAL.md`.

### Original 6 columns

| Column | Type | Notes |
|---|---|---|
| `DATETIME` | TIMESTAMP | NOT NULL |
| `SOURCE_IP` | NVARCHAR(50) | NOT NULL; primary grouping key |
| `PORT_SERVICE` | NVARCHAR(50) | |
| `EVENT_DESCRIPTION` | NVARCHAR(500) | |
| `STATUS` | NVARCHAR(50) | |
| `LOG_TYPE` | NVARCHAR(50) | Added very early; treat as pre-expansion |

### 16 columns added in `5b5d777`

`REQUEST_PATH`, `SAP_APPLICATION`, `REGION_CODE`, `MACRO_REGION`,
`HTTP_METHOD`, `SAP_SOURCE_TYPE`, `SAP_APP_ENV`, and the nine LLM columns
(`LLM_TOTAL_TOKENS`, `LLM_COST_USD`, `LLM_FINISH_REASON`, `LLM_STATUS`,
`LLM_RESPONSE_TIME_MS`, `LLM_PROMPT_CATEGORY`, `LLM_ERROR_MESSAGE`,
`LLM_MODEL_ID`, `LLM_PROMPT_TOKENS`). The nine `LLM_*` columns are NULL by
design for non-LLM traffic — their NULL rate is not a data-quality signal.

### Fields the SAP API returns that we deliberately discard

We ingest ~22 of the ~44 fields the API returns. The ones dropped are either
Elasticsearch/envelope metadata or LLM-internal payloads:

`_id`, `_ignored`, `_index`, `_score`, `@version`, `@event_time_requested`,
`event_code_version`, `event_hash`, `headers_content_type`,
`headers_http_host`, `region_id`, `region_name`, `sap_llm_response_size`,
`sap_llm_response_time`, `llm_provider`, `llm_prompt_id`, `llm_prompt`,
`llm_completion_tokens`, `llm_response_size_bytes`, `llm_temperature`,
`llm_top_p`, `llm_stream`.

If you need one of these, add it to `src/ingestion/log_parser.py`'s
`_COLUMN_ALIASES`, extend `src/storage/schema.sql`, and follow the migration
playbook below. **Do not silently fetch and drop** — wire it end-to-end or
leave it out.

### Migration playbook (adding columns to an existing SECURITY_LOGS)

`src/storage/migrations.py` only runs `CREATE`. For production tables that
already exist, use the idempotent ALTER pattern from
`scripts/migrate_add_columns.py`: wrap each `ALTER TABLE ... ADD (...)` in a
try/except that catches HANA's "already exists" error so the script is safe
to re-run. Never re-introduce a blanket `.fillna(0)` in the feature pipeline
after adding a new column — expand the null-handling strategy in
`src/model/features.py` instead.
