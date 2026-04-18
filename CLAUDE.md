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

## Branch Rules

- Team members work on `feat/*` branches, PR into `dev`
- Only PM merges `dev` into `main`
- Never push directly to `main`

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
