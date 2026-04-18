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
