# Architecture

## Overview

SAP AI Security — Threat Detector is an AI-powered Security Operations Center
that performs real-time anomaly detection on SAP security logs. It runs as a
single Cloud Foundry application on SAP BTP with a FastAPI web process and an
asyncio background pipeline.

## Pipeline Flow

```
OBSERVE ─────> ANALYZE ─────> DETECT ─────> RESPOND
  │               │              │              │
  │ sap_log_      │ features.    │ predict.py   │ sap_webhook.py
  │ fetcher.py    │ extract_     │ score +      │ send_alert()
  │ fetch_all_    │ features()   │ threshold    │ + incident_report
  │ logs()        │              │              │
  ▼               ▼              ▼              ▼
 CSV/API ──> per-IP stats ──> anomaly ──> webhook + HANA
 ingestion    aggregation     scores      persistence
```

### OBSERVE — `src/ingestion/`
- `sap_log_fetcher.py` — paginated async fetch from SAP API (or local CSV in mock mode)
- `log_parser.py` — normalize column names, parse raw API responses
- Returns a `pd.DataFrame` with `datetime`, `source_ip`, `event_type`, etc.

### ANALYZE — `src/model/features.py`
- Groups logs by `source_ip` within a configurable context window
- Extracts: `total_requests`, `unique_endpoints`, `error_rate`, `avg_response_time`,
  `multi_bucket_count`, `brute_force_score`, etc.

### DETECT — `src/model/predict.py`
- Loads the trained Isolation Forest (or DBSCAN) via `ModelRegistry`
- Scores feature vectors with `decision_function`
- Assigns threat levels: **high** / **medium** / **low** based on configurable thresholds
- Stamps dual MTTD on every row:
  - `pipeline_mttd_ms` = `detected_at` - `ingested_at` (internal latency)
  - `e2e_mttd_ms` = `detected_at` - earliest `log.datetime` (real-world latency)

### RESPOND — `src/alerting/`
- `sap_webhook.py` — HMAC-signed POST to SAP webhook with deduplication and retry
- `incident_report.py` — Markdown forensics report for high-severity anomalies
- `deduplication.py` — TTL-based alert deduplication to prevent alert storms

## Deployment Topology

```
┌──────────────────────────────────────────┐
│          SAP BTP Cloud Foundry           │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  Web Process (Procfile)            │  │
│  │  uvicorn src.api.main:app          │  │
│  │                                    │  │
│  │  FastAPI endpoints:                │  │
│  │    GET  /health    (liveness)      │  │
│  │    GET  /ready     (readiness)     │  │
│  │    POST /predict   (ad-hoc score)  │  │
│  │    GET  /metrics   (JSON KPIs)     │  │
│  │                                    │  │
│  │  asyncio background task:          │  │
│  │    Pipeline.run_forever()          │  │
│  │    polls every POLL_INTERVAL_S     │  │
│  └────────────────────────────────────┘  │
│              │              │             │
│     ┌────────┘              └────────┐   │
│     ▼                                ▼   │
│  HANA Cloud                    SAP Webhook│
│  (persistence)                (alerting)  │
└──────────────────────────────────────────┘

Developer laptop:
  - Streamlit dashboard (make dashboard) — connects to localhost:8000
  - NOT deployed to Cloud Foundry
```

## Mock Mode

Mock mode is **derived**, never explicitly configured. Each external dependency
flips out of mock mode the moment its URL/host env var is set:

| Dependency   | Env Var           | Mock Behavior                    |
|--------------|-------------------|----------------------------------|
| SAP API      | `SAP_API_URL`     | Reads from `data/samples/*.csv`  |
| SAP Webhook  | `SAP_WEBHOOK_URL` | Logs alert payload locally       |
| HANA Cloud   | `HANA_HOST`       | In-memory list repositories      |

## Module Map

```
src/
├── api/             FastAPI app + Pydantic schemas
├── alerting/        Webhook, deduplication, incident reports
├── common/          Config (Settings dataclass), logging, metrics, time utils
├── dashboard/       Streamlit SOC dashboard (local only)
├── ingestion/       SAP log fetcher + parser
├── model/           Feature extraction, train, predict, DBSCAN, versioning
├── storage/         HANA pool, repositories (with in-memory fallback), migrations
└── pipeline.py      Orchestrator — ties all modules together
```

## Configuration

All config flows through `src/common/config.py` → `Settings` dataclass.
Env vars are documented in `.env.example`. No `os.getenv()` calls outside of `config.py`.

## Model Persistence

Models are saved with `joblib` (not pickle) via `src/model/versioning.py`.
The `ModelRegistry` handles versioned save/load under `models/`.

## Observability

- Structured JSON logging via `python-json-logger` — no `print()` anywhere in `src/`
- `src/common/metrics.py` — in-memory counters and MTTD percentile tracking
- `/metrics` endpoint exposes all KPIs as JSON
- `/ready` endpoint checks HANA, model, and pipeline health

## Key Dates

| Date     | Milestone                                    |
|----------|----------------------------------------------|
| Apr 13   | SAP_API_URL + SAP_API_KEY available           |
| Apr 27   | SAP_WEBHOOK_URL available                     |
| May 4    | Go Live on SAP BTP Cloud Foundry              |
| May 12-14| First eliminatory phase — judges evaluate live|
