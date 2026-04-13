# Data Architect & Backend Developer — Onboarding Guide

> **TL;DR**
> - You own the database layer (SAP HANA) and the log parsing logic — you make sure data gets stored correctly and the log format is understood.
> - You own: `src/storage/` (all files), `src/ingestion/log_parser.py`
> - Your #1 priority on April 13: get HANA credentials working, verify the tables are created, and adapt `log_parser.py` if the real SAP API response format differs from what we expect.

---

## 1. WHO YOU ARE

You are the person who makes sure data flows in and gets stored properly. When security logs arrive from SAP, your `log_parser.py` normalizes them into a format the rest of the system understands. When the pipeline detects anomalies, your `repositories.py` writes them to SAP HANA so they're permanently stored and queryable. Think of it this way: the AI Specialist builds the brain, the Cloud Engineer builds the body, and you build the memory and the senses — the system's ability to read data and remember what happened.

---

## 2. YOUR MODULES

| File | What it does |
|------|-------------|
| `src/storage/repositories.py` | The interface between the pipeline and the database. Three classes: `LogRepository` (stores raw logs), `AnomalyRepository` (stores detected attacks), `ModelVersionRepository` (stores trained model metadata). Each has an in-memory fallback for when HANA isn't available. |
| `src/storage/pool.py` | Manages a fixed-size pool of connections to SAP HANA. Instead of opening and closing a connection for every query (slow), it keeps connections ready and hands them out when needed. |
| `src/storage/schema.sql` | The SQL definitions for three HANA tables: `SECURITY_LOGS`, `ANOMALIES`, `MODEL_VERSIONS`. This file is run once at startup to create the tables if they don't exist. |
| `src/storage/migrations.py` | Reads `schema.sql` and executes each statement against HANA. Smart enough to skip statements for tables that already exist. Runs automatically when the API starts. |
| `src/storage/__init__.py` | Package init for the storage module. |
| `src/ingestion/log_parser.py` | Normalizes raw SAP API responses into a standard DataFrame format. Maps different column names (e.g., "timestamp" → "datetime", "ip" → "source_ip") and validates that required columns exist. This is the ONE file that changes when the SAP API format changes. |

---

## 3. WHAT THE PROJECT DOES

This project detects cyberattacks in SAP security logs in real-time. Every 30 seconds, logs arrive from the SAP API, get parsed by your `log_parser.py` into a standard format, flow through the ML model for scoring, and the results are stored in SAP HANA via your repositories. The HANA database is critical for two reasons: (1) judges will query it to verify the system is actually processing data, and (2) the `ANOMALIES` table has `PIPELINE_MTTD_MS` and `E2E_MTTD_MS` columns that directly feed the metric worth 40% of the grade. If data isn't stored correctly, the system looks broken to judges even if everything else works.

---

## 4. SETUP — DO THIS FIRST

```bash
# Clone the repo
git clone https://github.com/danieldiazde/sap-threat-detector.git
cd sap-threat-detector

# Create YOUR branch
git checkout dev
git checkout -b feat/data-architect

# Create virtual environment
python3 -m venv .venv        # Use python3 if 'python' is not found
source .venv/bin/activate   # Mac/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
make install
# Success: you see "Successfully installed..." with no errors

# Copy environment variables file
cp .env.example .env
# This creates your local config file. Never commit this file.

# Generate mock SAP logs (fake data for development)
make mock
# Success: data/samples/ directory gets a CSV file with 5000 rows

# Train the model on mock data
make train
# Success: models/ directory appears with a version folder inside

# Run all tests
make test
# Success: all tests pass (green), no red errors

# Start the API server
make api
# Success: "Uvicorn running on http://127.0.0.1:8000" appears
# Open http://localhost:8000/health in your browser — should show {"status":"ok"}
# In the logs you'll see "migrations.apply_schema.mock_skip" — that's expected (no HANA yet)
```

---

## 5. YOUR FILES IN DETAIL

### `src/storage/schema.sql`

This file defines the three database tables:

**`SECURITY_LOGS`** — every raw log event that arrives from SAP. Columns: `DATETIME`, `SOURCE_IP`, `PORT_SERVICE`, `EVENT_DESCRIPTION`, `STATUS`, `LOG_TYPE`, `INGESTED_AT`. Indexed on `DATETIME` and `SOURCE_IP` for fast queries.

**`ANOMALIES`** — every detected attack. Columns include `SOURCE_IP`, `THREAT_LEVEL`, `ANOMALY_SCORE`, and critically: `PIPELINE_MTTD_MS` (time from ingestion to detection) and `E2E_MTTD_MS` (time from original event to detection). These two columns are what judges will query to evaluate our MTTD score. Also stores `ALERT_ID` (idempotency key), `WEBHOOK_SENT` (did the alert fire?), and `INCIDENT_REPORT_PATH` (link to the forensic report file).

**`MODEL_VERSIONS`** — metadata for every trained model. Version tag, model type, hyperparameters, feature columns, training samples, cross-validation scores. Used for MLOps tracking and rollback.

**Already built:** Complete table definitions with proper types, indexes, and constraints.

**TODO for April 13:** Nothing — this file is complete. If the SAP API provides additional fields we want to store, you would add columns here, but that's unlikely for the first version.

**Study:** SAP HANA SQL reference — HANA uses standard SQL with some extensions. The `CREATE INDEX` statements are important for query performance when the tables have thousands of rows.

### `src/storage/repositories.py`

This is the interface between the pipeline and the database. The rest of the codebase never writes raw SQL — it calls methods like `log_repository.insert_logs(df)` or `anomaly_repository.insert_anomaly(row)`. Each repository class has two modes:

1. **Mock mode** (when `HANA_HOST` is empty): writes go to an in-memory Python list. This lets the pipeline, tests, and dashboard work perfectly without a real database.
2. **Live mode** (when `HANA_HOST` is set): writes go to HANA via `executemany` batch inserts through the connection pool.

The switch between modes is automatic — no code changes needed.

**Already built:** All three repositories with insert, query, and MTTD sample retrieval methods. In-memory fallbacks are capped (10k logs, 2k anomalies) to prevent memory leaks.

**TODO for April 13:** After HANA credentials are set, monitor insert performance. If `log_repo.hana_insert` logs show slow inserts, increase `HANA_POOL_SIZE` in `.env` (default is 4). Also verify that `anomaly_repository.mttd_samples()` returns data — the dashboard needs this for MTTD distribution charts.

**Study:** The `executemany` pattern — instead of inserting one row at a time (slow), we batch 500 rows into a single database call. This is critical for performance when processing hundreds of logs per cycle.

### `src/storage/pool.py`

Manages a fixed-size pool of HANA connections using an `asyncio.Queue`. The `hdbcli` driver (SAP's official Python client for HANA) is synchronous, so all database operations are run in a thread executor via `asyncio.to_thread()` to avoid blocking the FastAPI event loop. The `acquire()` context manager checks out a connection, and when the block exits, the connection goes back to the pool for reuse.

**Already built:** Pool initialization, checkout/checkin, ping, close. Mock mode yields `None` connections and repositories handle that gracefully.

**TODO for April 13:** After setting HANA credentials, check logs for `hana_pool.init` with the configured pool size. If you see `hana_pool.ping_failed`, the credentials are wrong or HANA is unreachable.

**Study:** Connection pooling — opening a database connection is expensive (network handshake, authentication). Keeping connections open and reusing them is 100x faster for high-volume workloads.

### `src/storage/migrations.py`

Reads `schema.sql`, splits it into individual SQL statements, and executes each one against HANA. If a table already exists, the "already exists" error is caught and skipped — so this is safe to run on every startup. It only runs CREATE statements; if you need to ALTER a table after go-live, you do that manually through the SAP HANA cockpit.

**Already built:** Full idempotent migration runner.

**TODO for April 13:** After HANA credentials are set, watch logs for `migrations.apply_schema.start` and `migrations.apply_schema.done`. If you see `migrations.statement_failed`, check the error — it might be a permissions issue on the HANA user.

### `src/ingestion/log_parser.py`

This is the adapter between the SAP API and the rest of the system. It does two things:

1. **`parse_raw_response(payload)`** — takes the raw JSON from the SAP API and extracts the list of log records. Handles multiple envelope formats: `{"logs": [...]}`, `{"data": [...]}`, or a bare array `[...]`.

2. **`normalize_columns(df)`** — renames columns to our canonical names. The SAP API might call the timestamp field "time", "timestamp", "@timestamp", or "event_time" — this function maps all of them to "datetime". Same for IP address, status, and event description.

This file is intentionally isolated — when the real SAP API format is revealed on April 13, THIS is the only file that needs to change. Everything downstream assumes the canonical column names from `src/model/schema.py`.

**Already built:** Column alias mapping for 15+ common field names, schema validation, response envelope parsing.

**TODO for April 13:** This is your most critical task. Once you see the real SAP API response:
1. Check if the column names are already covered by the alias map. If not, add them.
2. Check if `parse_raw_response()` handles the envelope format. If SAP uses a different wrapper (e.g., `{"results": {"entries": [...]}}`), update the function.
3. Run `make test` — all log parser tests should still pass.

**Study:** Look at the current alias map in the file. It covers the most common patterns, but SAP might use something unique.

---

## 6. HOW TO USE CLAUDE CODE FOR YOUR ROLE

### Installation

```bash
# Prerequisite: Node.js must be installed (https://nodejs.org — LTS version)
# Install Claude Code (one time)
npm install -g @anthropic-ai/claude-code

# Open Claude Code in the project folder
cd sap-threat-detector
claude
```

### What is Claude Code?

Claude Code is an AI assistant that lives inside your terminal and reads your entire codebase. Unlike ChatGPT, it already knows every file in this project — you don't need to paste code. You talk to it in plain English and it writes, edits, and explains code directly in your files.

### Starter Prompt

Copy and paste this into Claude Code at the start of each session:

```
I am the Data Architect & Backend Developer on the TEC × SAP Hackathon team.
We are building an AI-powered Security Operations Center that detects
cyberattacks in real-time from SAP security logs.

PROJECT: sap-threat-detector
REPO: https://github.com/danieldiazde/sap-threat-detector
BRANCH: I am working on feat/data-architect, PRs go into dev (never main).

MY FILES (I own these):
- src/storage/repositories.py — LogRepository, AnomalyRepository, ModelVersionRepository
- src/storage/pool.py — async-compatible HANA connection pool
- src/storage/schema.sql — HANA table definitions (SECURITY_LOGS, ANOMALIES, MODEL_VERSIONS)
- src/storage/migrations.py — idempotent schema runner
- src/ingestion/log_parser.py — normalize SAP API responses to canonical column names

CURRENT STATE:
- MOCK_HANA is active (HANA_HOST is empty in .env)
- All DB operations use in-memory Python lists as fallback
- Real HANA credentials arrive on April 13
- schema.sql defines 3 tables with indexes
- The ANOMALIES table has PIPELINE_MTTD_MS and E2E_MTTD_MS columns (critical
  for the 40% MTTD grade)

CODING STANDARDS:
- No print() in src/ — use: from src.common.logging import get_logger
  then logger = get_logger(__name__). Scripts in scripts/ may use print() for CLI output.
- All config via: from src.common.config import settings
- All DB operations via repositories (never raw SQL outside repositories)
- Use asyncio.to_thread() for hdbcli calls (it's a sync driver)
- Type hints on every function, Google-style docstrings on public methods
- Import train/predict directly from their modules (not from src.model):
  from src.model.train import train (correct)
  from src.model import train (WRONG — namespace conflict)

KEY DATES:
- April 13: HANA credentials + SAP_API_URL arrive
- April 27: SAP_WEBHOOK_URL arrives
- May 4: Go Live on SAP BTP Cloud Foundry
- May 12-14: Judges evaluate live system, will query HANA tables

Help me understand and manage the storage layer and log parsing.
```

### Example Requests

1. "Walk me through how a log goes from the SAP API response to being stored in the SECURITY_LOGS table"
2. "The SAP API returns logs with a field called 'event_timestamp' instead of 'datetime'. Help me update log_parser.py"
3. "Explain the connection pool in pool.py — why do we use asyncio.Queue and asyncio.to_thread?"
4. "Help me add an index on ANOMALIES.SOURCE_IP for faster queries during the demo"
5. "The migration is failing with 'insufficient privilege'. What HANA permissions do I need?"

### Important Warning

Always tell Claude Code which branch you're on before making changes. Run `git status` and tell Claude Code the output before asking it to edit files.

---

## 7. DAY-TO-DAY WORKFLOW

### Working on your branch

Always work on your branch (`feat/data-architect`), never on `main` or `dev` directly.

```bash
# Make sure you're on your branch
git checkout feat/data-architect

# Pull latest changes from dev into your branch
git fetch origin
git merge origin/dev
```

### Committing your work

```bash
# Stage your changes
git add src/storage/ src/ingestion/log_parser.py

# Commit with a descriptive message
git commit -m "feat(storage): describe what you did"

# Push to GitHub
git push origin feat/data-architect
```

### Good commit message examples

- `feat(storage): add index on ANOMALIES.SOURCE_IP for faster dashboard queries`
- `fix(parser): add 'event_timestamp' alias mapping for real SAP API format`
- `fix(storage): increase insert batch size to 1000 for better HANA throughput`

### Opening a Pull Request

1. Go to the GitHub repo in your browser
2. Click "Compare & pull request" for your branch
3. Set the target branch to `dev` (NOT main)
4. Describe what you changed and why
5. Request review from Daniel (PM)

### If something breaks

```bash
# Undo changes to a specific file
git checkout -- src/storage/repositories.py

# See what you changed
git diff src/ingestion/log_parser.py
```

---

## 8. APRIL 13 CHECKLIST

1. **Get HANA credentials from Daniel (PM):** You need five values:
   - `HANA_HOST` (e.g., `abc123.hana.trial-us10.hanacloud.ondemand.com`)
   - `HANA_PORT` (usually `443`)
   - `HANA_USER`
   - `HANA_PASSWORD`
   - `HANA_DATABASE`

2. **Add credentials to `.env`:**
   ```
   HANA_HOST=abc123.hana.trial-us10.hanacloud.ondemand.com
   HANA_PORT=443
   HANA_USER=...
   HANA_PASSWORD=...
   HANA_DATABASE=...
   ```

3. **Start the API and verify HANA connects:**
   ```bash
   make api
   ```
   Look in logs for:
   - `hana_pool.init  size=4  host=abc123...` — pool started
   - `migrations.apply_schema.start  statements=9` — creating tables
   - `migrations.apply_schema.done` — tables created successfully

4. **Verify tables exist:** Open the SAP HANA cockpit or run:
   ```sql
   SELECT TABLE_NAME FROM TABLES WHERE SCHEMA_NAME = CURRENT_SCHEMA
     AND TABLE_NAME IN ('SECURITY_LOGS', 'ANOMALIES', 'MODEL_VERSIONS');
   ```
   You should see all three tables.

5. **Adapt log_parser.py for the real API format:** Once the Cloud Engineer confirms the SAP API is returning data:
   - Ask them for a sample response (or look at the pipeline logs)
   - Check if the column names are already in the alias map
   - If not, add the new mappings to `_COLUMN_ALIASES` in `log_parser.py`
   - Run `make test` — all parser tests must still pass

6. **Verify logs are being stored:**
   ```sql
   SELECT COUNT(*) FROM SECURITY_LOGS;
   -- Should increase every 30 seconds (pipeline polling interval)
   ```

7. **Monitor insert performance:** Watch the API logs for timing. If `log_repo.hana_insert` seems slow:
   - Increase `HANA_POOL_SIZE` in `.env` (try 6 or 8)
   - The batch size is 500 rows in `repositories.py` — increase `LOG_INSERT_BATCH_SIZE` if needed

---

## 9. DO NOT TOUCH

Do not edit these files. If you think something needs to change in them, open a GitHub Issue or ask Daniel.

- `src/model/` — ML model code (owned by AI Specialist)
- `src/api/` — FastAPI endpoints (owned by Cloud Engineer)
- `src/pipeline.py` — pipeline orchestrator (owned by Cloud Engineer)
- `src/ingestion/sap_log_fetcher.py` — log fetcher (owned by Cloud Engineer)
- `src/alerting/` — webhook and deduplication (owned by Cloud Engineer)
- `src/dashboard/` — Streamlit dashboard (owned by Security/Viz Lead)
- `src/common/` — shared config, logging, metrics (coordinate with Daniel before changing)
- `.github/workflows/` — CI/CD pipelines (owned by Cloud Engineer)
- `Makefile`, `Procfile`, `requirements.txt`, `pyproject.toml`

---

## 10. IF SOMETHING BREAKS

**ERROR:** `hdbcli.dbapi.Error: connection attempt to ... failed`
**CAUSE:** HANA_HOST is wrong, the instance is stopped, or network access is blocked.
**FIX:** Verify the host and port in `.env`. Check if the HANA instance is running in the SAP BTP cockpit. Make sure your network allows outbound connections on port 443.

**ERROR:** `migrations.statement_failed: insufficient privilege`
**CAUSE:** The HANA user doesn't have permission to create tables.
**FIX:** Ask Daniel to grant the user `CREATE TABLE`, `CREATE INDEX`, `INSERT`, `SELECT` privileges on the schema. In HANA cockpit: `GRANT CREATE ANY ON SCHEMA <schema> TO <user>`.

**ERROR:** `InvalidLogSchemaError: Log DataFrame is missing required columns: ['source_ip']`
**CAUSE:** The SAP API uses a different column name for the IP address than what `log_parser.py` expects.
**FIX:** Add the SAP column name to `_COLUMN_ALIASES` in `log_parser.py`. For example, if SAP calls it `"remote_ip"`, add `"remote_ip": "source_ip"` to the dict.

**ERROR:** `asyncio.Queue is full` or `hana_pool: connection timeout`
**CAUSE:** All pool connections are busy — the system is writing faster than HANA can accept.
**FIX:** Increase `HANA_POOL_SIZE` in `.env`. If it's already at 8+, the bottleneck is HANA itself — check HANA resource utilization.

**ERROR:** `log_repo.memory_insert` keeps appearing even after setting HANA_HOST
**CAUSE:** `settings.mock_hana` is still True — likely the `.env` change wasn't loaded.
**FIX:** Restart the API server (`make api`). The config loads from `.env` once at import time. If it still shows mock, check that `HANA_HOST` in `.env` has no quotes or trailing spaces.

---

## 11. GLOSSARY

| Term | Meaning |
|------|---------|
| **Database** | A program that stores data permanently on disk so it survives restarts. HANA is SAP's in-memory database — it stores data in RAM for fast access but also persists to disk. |
| **Schema** | The structure of a database — which tables exist, what columns they have, what types the columns are. Defined in `schema.sql`. |
| **SQL** | Structured Query Language — the standard language for talking to databases. `SELECT`, `INSERT`, `CREATE TABLE`, etc. |
| **HANA** | SAP's in-memory database. "In-memory" means it keeps data in RAM for extremely fast reads, unlike traditional databases that read from disk. |
| **Connection pool** | A collection of pre-opened database connections that are reused instead of opened/closed for each query. Much faster for high-volume workloads. |
| **Repository pattern** | A design pattern where database access is wrapped in classes with methods like `insert_logs()` and `recent_anomalies()`. The rest of the code never writes raw SQL — it calls repository methods. |
| **Migration** | Running SQL statements to create or modify database tables. Our migrations are CREATE-only and idempotent (safe to run multiple times). |
| **Mock mode** | When `HANA_HOST` is empty, all database operations happen in Python lists instead of a real database. The rest of the system doesn't know the difference. |
| **executemany** | A database technique for inserting many rows in a single call instead of one at a time. 10-100x faster for bulk inserts. |
| **async / asyncio** | Python's concurrency model. Our HANA driver is synchronous, so we use `asyncio.to_thread()` to run database operations without blocking the web server. |
| **Transaction** | A group of database operations that either all succeed or all fail. `conn.commit()` makes the changes permanent. |
| **Index** | A database optimization that speeds up queries on specific columns. Like a book index — instead of scanning every page, you jump to the right one. |
| **SECURITY_LOGS** | The HANA table that stores every raw log event from the SAP API. One row per event. |
| **ANOMALIES** | The HANA table that stores every detected attack. Contains the MTTD measurements that judges evaluate. |
| **MODEL_VERSIONS** | The HANA table that records metadata about each trained model for MLOps tracking. |
| **PIPELINE_MTTD_MS** | Column in ANOMALIES. Time in milliseconds from when the pipeline received the log batch to when the model flagged the anomaly. |
| **E2E_MTTD_MS** | Column in ANOMALIES. Time in milliseconds from when the original event happened to when the model flagged it. This is the "real-world" detection speed. |

---

*Questions? Ask Daniel (PM) or open a GitHub Issue tagged with label: `data`*
