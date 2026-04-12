# Technical Project Manager & Scrum Master — Onboarding Guide

> **TL;DR**
> - You own the whole project. Every module is yours to understand.
> - Your primary job: unblock your team, review PRs, manage the SAP relationship, and hit every deadline.
> - Your technical goal: be able to read, understand, and contribute to any file in the codebase.

---

## 1. YOUR ROLE IN PLAIN ENGLISH

**The management side.** You are the person who keeps the team moving forward. You manage the backlog on GitHub Projects, run sprints, communicate with SAP contacts, enforce deadlines, and review every pull request before it merges. When a team member is stuck, you unblock them — whether that means answering a question, reassigning work, or asking SAP for clarification. You are the single point of contact between this team and the SAP hackathon organizers. Every deadline (April 13, April 27, May 4, May 12-14) is YOUR deadline first, and the team's deadline second.

**The technical side.** You are not a hands-off PM. You want to go deep — you want to understand every module, read every file, and be capable of contributing code to any part of the system. When a team member explains a problem, you want to understand it at the code level, not just the summary level. This guide gives you the complete technical map. You can contribute to ANY module — you are not limited to "PM tasks."

---

## 2. THE FULL SYSTEM — YOUR MASTER MAP

Here is the complete request lifecycle, from the moment a security event happens in SAP to the moment a judge sees it on the dashboard. Every step maps to a file you can read.

### Step 1: OBSERVE — Fetching logs from SAP

**File:** `src/ingestion/sap_log_fetcher.py` (Cloud Engineer)
**What happens:** Every 30 seconds, the pipeline calls `fetch_all_logs()`. In mock mode, it reads from a local CSV file. When `SAP_API_URL` is set, it makes paginated async HTTP requests to the SAP API. Returns a pandas DataFrame with raw log rows.
**What could go wrong:** SAP API returns 401 (bad key), 429 (rate limited), or an unexpected response format. The fetcher has retry logic with exponential backoff.

### Step 2: OBSERVE — Parsing and normalizing

**File:** `src/ingestion/log_parser.py` (Data Architect)
**What happens:** The raw API response is parsed into a DataFrame with canonical column names. SAP might call the timestamp field "time" or "@timestamp" — this file maps all variations to "datetime", "source_ip", "status", "event_description".
**What could go wrong:** The real SAP API uses column names not in the alias map. The Data Architect updates `_COLUMN_ALIASES` to fix this. This is the #1 April 13 risk.

### Step 3: ANALYZE — Feature extraction

**File:** `src/model/features.py` (AI Specialist)
**What happens:** Raw logs (many rows per IP) are grouped by `source_ip` and summarized into 13 features per IP: total requests, error rate, POST ratio, unique paths, 4xx/5xx counts, denied ratio, suspicious path ratio, SQL injection hits, port diversity, brute force score, interarrival time std, and request rate z-score.
**What could go wrong:** Feature values are all zeros (keyword lists don't match real event descriptions), or feature distributions are wildly different from mock data (model may need retraining with different contamination).

### Step 4: DETECT — Scoring with the model

**File:** `src/model/predict.py` (AI Specialist)
**What happens:** The trained Isolation Forest model scores each IP's feature vector. More negative scores = more anomalous. Threat levels are assigned: score < -0.3 → high, score < -0.1 → medium, else low. Critical: `detected_at` is stamped here and `pipeline_mttd_ms` is computed as `detected_at - ingested_at`. This number is 40% of the competition grade.
**What could go wrong:** Too many false positives (lower contamination), too few detections (raise contamination), model not trained (run `make train`).

### Step 5: DETECT — Model versioning

**File:** `src/model/versioning.py` (AI Specialist)
**What happens:** Every trained model is saved under `models/<version-tag>/` with three files: `model.joblib`, `scaler.joblib`, `manifest.json`. The prediction code loads `latest` automatically. You can roll back to any previous version.
**What could go wrong:** Disk full (old versions accumulate), or cache mismatch (call `reset_active_model()` after retraining).

### Step 6: RESPOND — Webhook alert

**File:** `src/alerting/sap_webhook.py` (Cloud Engineer)
**What happens:** For each anomaly flagged above the threshold, a JSON payload is POSTed to the SAP webhook URL with an HMAC-SHA256 signature. The deduper (`deduplication.py`) suppresses repeat alerts for the same IP+threat_level within 300 seconds. In mock mode, the payload is logged locally.
**What could go wrong:** Webhook URL is wrong (check `.env`), HMAC secret mismatch, rate limiting, webhook service down.

### Step 7: RESPOND — Incident report

**File:** `src/alerting/incident_report.py` (Security/Viz Lead)
**What happens:** For high-severity anomalies, a markdown forensic report is generated and saved to `reports/incidents/`. The report includes evidence logs, feature values, MTTD measurements, and automated remediation recommendations.
**What could go wrong:** Empty evidence (small batches), unhelpful recommendations (keyword lists need tuning).

### Step 8: STORE — Persist to HANA

**File:** `src/storage/repositories.py` (Data Architect)
**What happens:** Raw logs go to `SECURITY_LOGS` table, anomalies go to `ANOMALIES` table (including `PIPELINE_MTTD_MS` and `E2E_MTTD_MS`). In mock mode, everything writes to in-memory Python lists. The switch to real HANA happens automatically when `HANA_HOST` is set.
**What could go wrong:** HANA connection refused, insufficient permissions, slow inserts (increase pool size).

### Step 9: DISPLAY — Dashboard

**File:** `src/dashboard/app.py` (Security/Viz Lead)
**What happens:** Streamlit dashboard fetches from `/metrics`, `/health`, `/ready` every 5 seconds. Shows MTTD KPIs, 4 Plotly charts, threat table, log feed, and system health sidebar.
**What could go wrong:** Dashboard can't reach API (make sure both are running), stale data (check auto-refresh).

### Step 10: EVALUATE — Judges see the result

**What judges evaluate:**
- MTTD numbers on dashboard (40%)
- App running on BTP URL (25%)
- Code quality, CI/CD, model versioning (20%)
- Incident reports, executive narrative (15%)

---

## 3. SETUP

```bash
# Clone the repo
git clone https://github.com/danieldiazde/sap-threat-detector.git
cd sap-threat-detector

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Mac/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
make install
# Success: you see "Successfully installed..." with no errors

# Copy environment variables file
cp .env.example .env
# This creates your local config file. Never commit this file.

# Generate mock SAP logs
make mock
# Success: data/samples/ gets a CSV file

# Train the model
make train
# Success: models/ directory appears

# Run all tests
make test
# Success: all tests pass

# Run the full system locally (two terminals):

# Terminal 1: Start the API + pipeline
make api
# Open http://localhost:8000/docs — interactive API documentation
# Open http://localhost:8000/health — liveness check
# Open http://localhost:8000/metrics — live metrics JSON

# Terminal 2: Start the dashboard
make dashboard
# Open http://localhost:8501 — the SOC dashboard
```

### Understanding any file with Claude Code

```bash
# Install Claude Code (one time)
npm install -g @anthropic-ai/claude-code

# Open Claude Code in the project folder
claude
```

Then ask it to explain anything:
```
Explain src/model/predict.py to me like I'm a junior dev. What does it do step by step?
```

### Testing the full pipeline manually

With the API running, send a POST to `/predict` with a sample attack batch:

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"logs": [
    {"datetime": "2026-04-12T10:00:00Z", "source_ip": "192.168.1.100", "status": "200", "event_description": "GET /api/data"},
    {"datetime": "2026-04-12T10:00:01Z", "source_ip": "10.0.0.1", "status": "DENIED", "event_description": "Failed login attempt - brute force detected"},
    {"datetime": "2026-04-12T10:00:01Z", "source_ip": "10.0.0.1", "status": "DENIED", "event_description": "Failed login attempt - brute force detected"},
    {"datetime": "2026-04-12T10:00:02Z", "source_ip": "10.0.0.1", "status": "403", "event_description": "UNION SELECT * FROM users--"}
  ]}'
```

Watch the response for `anomalies` — the suspicious IP should be flagged.

---

## 4. HOW TO USE CLAUDE CODE AS PM

### Installation

```bash
npm install -g @anthropic-ai/claude-code
cd sap-threat-detector
claude
```

### What is Claude Code?

Claude Code is an AI assistant that lives inside your terminal and reads your entire codebase. Unlike ChatGPT, it already knows every file in this project — you don't need to paste code. You talk to it in plain English and it writes, edits, and explains code directly in your files.

### PM Starter Prompt

Copy and paste this into Claude Code at the start of each session:

```
I am Daniel, the Technical Project Manager & Scrum Master on the TEC × SAP
Hackathon team. This is MY project — I want to understand every module at the
code level and be able to contribute to any file.

PROJECT: sap-threat-detector
REPO: https://github.com/danieldiazde/sap-threat-detector
BRANCH: dev (I merge PRs into dev, then dev into main for deployment)

TEAM ROLES AND FILE OWNERSHIP:
- AI Specialist: src/model/ (all files), tests/model/, notebooks/eda.ipynb
- Cloud Engineer: src/api/, src/pipeline.py, src/ingestion/sap_log_fetcher.py,
  infra/, .github/workflows/
- Data Architect: src/storage/ (all files), src/ingestion/log_parser.py
- Security/Viz Lead: src/dashboard/app.py, src/alerting/incident_report.py,
  docs/, notebooks/eda.ipynb
- PM (me): I can contribute to ANY module. I review all PRs.

TECH STACK:
- FastAPI + uvicorn (API + pipeline), asyncio background task for pipeline
- scikit-learn Isolation Forest (primary model), DBSCAN (backup)
- SAP HANA Cloud (database), hdbcli driver, connection pool
- Streamlit + Plotly (dashboard, local only)
- SAP BTP Cloud Foundry (deployment), GitHub Actions CI/CD

CURRENT STATE:
- All code is production-grade and complete
- Mock mode active everywhere (no real SAP credentials yet)
- April 13: SAP_API_URL + SAP_API_KEY arrive → mock auto-disables
- April 27: SAP_WEBHOOK_URL arrives → mock auto-disables
- May 4: Go Live on BTP
- May 12-14: First eliminatory phase, judges evaluate live

CODING STANDARDS (enforce in PR reviews):
- No print() in src/ — use get_logger(__name__)
- All config via Settings dataclass in src/common/config.py
- joblib not pickle for models
- FEATURE_COLUMNS from src/model/schema.py — never redefined
- Import train/predict directly from their modules:
  from src.model.train import train (correct)
  from src.model import train (WRONG — namespace conflict)
- Type hints on all functions, Google-style docstrings

EVALUATION CRITERIA:
- 40% Operational Efficiency & Real-Time Response (MTTD is key)
- 25% SAP Ecosystem Integration (BTP + CF + HANA + SAC)
- 20% Architecture & MLOps Maturity (clean code, versioning, CI/CD)
- 15% Business Impact & Strategic Analysis (incident reports, narrative)

SAP SECURITY RULES:
- Never commit .env or credentials
- Never commit data/raw/
- All secrets in .env locally and GitHub Secrets for CI/CD

I want to go deep technically. Help me understand, review, and contribute
to any part of this codebase.
```

### PM-Specific Use Cases

**Understanding any file:**
```
Explain src/model/predict.py to me like I'm a junior dev. What does it do step by step?
```

**Reviewing PRs:**
```
I'm reviewing this PR diff [paste diff]. What does it change and are there any concerns?
```

**Contributing code:**
```
I want to add a new feature to src/model/features.py that counts DNS lookups per IP.
What's the best way to do it given the existing code?
```

**Debugging:**
```
The pipeline is failing with this error: [paste error]. What's wrong and how do I fix it?
```

**Architecture decisions:**
```
My Cloud Engineer wants to add Redis for caching between pipeline cycles. Is that a good
idea for this project, or would it add unnecessary complexity?
```

### Example Requests

1. "Give me a full tour of the codebase — explain every file and how they connect"
2. "I want to understand the MTTD measurement end-to-end. Walk me through every line of code involved from log ingestion to the dashboard display"
3. "My AI Specialist is stuck on high false positive rates. Help me understand the problem so I can unblock them"
4. "Review the current state of src/model/features.py and tell me if there are improvements we should make before April 13"
5. "Generate a status report: what's complete, what's pending, what are the risks for May 4 go-live"

### Important Warning

Always tell Claude Code which branch you're on before making changes. Run `git status` and tell Claude Code the output before asking it to edit files.

---

## 5. MANAGING YOUR TEAM — GITHUB WORKFLOW

### Reviewing and merging PRs

Team members work on `feat/*` branches and open PRs into `dev`.

1. Go to the PR on GitHub
2. Click "Files changed" — read every line
3. Check:
   - No `print()` statements in `src/`
   - No hardcoded credentials
   - Type hints on all functions
   - Tests pass (CI checks should be green)
   - Changes are only in files the team member owns
4. Approve and merge (squash merge preferred for clean history)
5. Delete the feature branch after merge

### Merging dev into main (deployment)

Only YOU do this. This triggers the deployment to SAP BTP.

```bash
git checkout main
git merge dev
git push origin main
# deploy.yml triggers automatically
```

### Branch protection

Set up in GitHub → Settings → Branches:
- **main**: Require PR reviews, require CI to pass, only you can merge
- **dev**: Require CI to pass

### Creating issues for April 13

Create one issue per team member with their checklist:

```
Title: [AI Specialist] April 13 — Retrain on real data
Labels: model
Assignee: @ai-specialist

- [ ] Verify make mock and make train still work
- [ ] Train on real SAP logs
- [ ] Check score distribution
- [ ] Tune MODEL_CONTAMINATION
- [ ] Tune ALERT_HIGH_THRESHOLD and ALERT_MEDIUM_THRESHOLD
- [ ] Run make test — all pass
- [ ] Explore data in notebooks/eda.ipynb
```

Repeat for Cloud Engineer (infra label), Data Architect (data label), Security/Viz (dashboard label).

### GitHub Projects board

Create a project board with columns:
- **Backlog** — everything that needs doing
- **In Progress** — actively being worked on (max 2 per person)
- **In Review** — PR opened, waiting for your review
- **Done** — merged into dev

---

## 6. APRIL 13 MASTER CHECKLIST

This is your coordination playbook for when SAP credentials arrive.

### Phase 1: Credentials (you do this)
- [ ] Receive SAP_API_URL and SAP_API_KEY from SAP contact
- [ ] Distribute credentials to team via secure channel (NOT Slack/email)
- [ ] Each team member adds to their local `.env`
- [ ] Add to GitHub Secrets for CI/CD

### Phase 2: Verify connectivity (Cloud Engineer)
- [ ] `make api` shows `mock_api: false` in logs
- [ ] `/health` returns `mock_api: false`
- [ ] Pipeline logs show real log data being fetched
- [ ] **Go/No-Go:** If logs are flowing, proceed. If 401/403, escalate to SAP contact.

### Phase 3: Verify data format (Data Architect)
- [ ] Check pipeline logs for column names in incoming data
- [ ] Update `log_parser.py` if needed
- [ ] `make test` passes with updated parser
- [ ] **Go/No-Go:** If `validate_schema()` passes on real data, proceed. If not, Data Architect fixes parser immediately.

### Phase 4: Retrain model (AI Specialist)
- [ ] Wait for at least 5 pipeline cycles (2.5 minutes of real data)
- [ ] `make train` on real data
- [ ] Check anomaly rate (should be 1-10%)
- [ ] Tune contamination and thresholds
- [ ] `make test` passes
- [ ] **Go/No-Go:** If anomaly rate is reasonable and tests pass, proceed. If model flags >20% or <0.5%, more tuning needed.

### Phase 5: Verify storage (Data Architect)
- [ ] HANA credentials set in `.env`
- [ ] Tables created (check HANA cockpit)
- [ ] `SELECT COUNT(*) FROM SECURITY_LOGS` shows rows increasing
- [ ] `SELECT COUNT(*) FROM ANOMALIES` shows detections
- [ ] **Go/No-Go:** If rows are being written, proceed. If migration failed, check HANA permissions.

### Phase 6: Verify visualization (Security/Viz Lead)
- [ ] Dashboard shows live MTTD numbers (not dashes)
- [ ] Charts populate with real data
- [ ] Incident reports generated for high-severity detections
- [ ] EDA notebook runs on real data
- [ ] **Go/No-Go:** If MTTD KPIs are visible and charts work, proceed.

### Phase 7: Full system check (you verify)
- [ ] API running, pipeline processing every 30 seconds
- [ ] MTTD p50 < 5000 ms (our target)
- [ ] At least one anomaly detected and stored
- [ ] At least one webhook alert sent (or logged in mock webhook mode)
- [ ] Dashboard shows all data correctly
- [ ] All tests pass: `make test`

---

## 7. EVALUATION CRITERIA — YOUR SCORING GUIDE

### 40% — Operational Efficiency & Real-Time Response

**Who contributes:** Cloud Engineer (pipeline speed), AI Specialist (model accuracy), Data Architect (HANA write speed)

**What to show judges:**
- MTTD numbers on the dashboard — p50 and p95, prominently displayed
- Live detection during demo — have the pipeline running and show an anomaly being detected in real-time
- Pipeline cycle time — show logs proving 30-second cycles

**Your monitoring targets:**
- `pipeline_mttd_ms` p50 < 2000 ms (ideal), < 5000 ms (acceptable)
- `e2e_mttd_ms` depends on SAP API polling — try to minimize `POLL_INTERVAL_SECONDS`
- Zero pipeline errors during demo (check `errors_total` on `/metrics`)

### 25% — SAP Ecosystem Integration

**Who contributes:** Cloud Engineer (BTP + CF deployment), Data Architect (HANA integration), Security/Viz Lead (SAC dashboards)

**What to show judges:**
- Live app on BTP URL — `/health` returns 200, pipeline is running
- HANA data — query SECURITY_LOGS and ANOMALIES tables with real data
- SAC executive dashboard — connected to HANA, showing MTTD trends

**Your monitoring targets:**
- App stable on BTP for >24 hours without restart
- HANA tables have >1000 rows in SECURITY_LOGS
- Webhook fires successfully (check `alerts_sent_total` on `/metrics`)

### 20% — Architecture & MLOps Maturity

**Who contributes:** All roles

**What to show judges:**
- GitHub commit history — clean, descriptive messages, PR-based workflow
- Model versioning — show `models/` directory with multiple versions and manifests
- CI passing on all PRs — show green checks on GitHub
- `docs/ARCHITECTURE.md` — clean, accurate system description
- `CLAUDE.md` — shows the project is well-documented for onboarding

**Your monitoring targets:**
- All PRs have passing CI before merge
- At least 3 model versions in the registry (initial + tuning iterations)
- Code quality: no `print()`, proper logging, type hints everywhere

### 15% — Business Impact & Strategic Analysis

**Who contributes:** Security/Viz Lead (owns this entirely)

**What to show judges:**
- Forensic incident reports — detailed, professional, actionable
- Executive narrative — "what would happen if we didn't have this system?"
- Attack case studies — 3 real examples with full OBSERVE→RESPOND analysis
- SAC executive summary — business-level view of security posture

**Your monitoring targets:**
- At least 3 complete incident reports in `reports/incidents/`
- Executive summary slide deck ready
- Clear "before/after" narrative

---

## 8. KEY DATES — YOUR MASTER CALENDAR

### April 13 — SAP API Access
- **You receive:** SAP_API_URL, SAP_API_KEY
- **You distribute:** credentials to all team members
- **You coordinate:** Phase 1-7 checklist above
- **Success criteria:** pipeline running on real data, model retrained, dashboard showing live MTTD

### April 27 — SAP Webhook Access
- **You receive:** SAP_WEBHOOK_URL, SAP_WEBHOOK_SECRET
- **You distribute:** credentials to Cloud Engineer
- **Cloud Engineer:** adds to `.env` and GitHub Secrets
- **You verify:** `/metrics` shows `alerts_sent_total` incrementing
- **Success criteria:** alerts firing to SAP on every high-severity detection

### May 4 — Go Live on SAP BTP
- **Cloud Engineer:** runs `make deploy` or merges to main
- **You verify:** BTP URL + `/health` returns 200, pipeline running
- **Data Architect:** verifies HANA tables have data on BTP
- **Security/Viz Lead:** dashboard connects to BTP URL (update `API_BASE` in app.py)
- **Success criteria:** system running 24/7 on SAP infrastructure, no local dependencies

### May 12-14 — First Eliminatory Phase
- **You prepare:** demo script, talking points for each evaluation criterion
- **AI Specialist:** model tuned, versioning history ready
- **Cloud Engineer:** system stable, zero errors in last 24 hours
- **Data Architect:** HANA queries ready for judges
- **Security/Viz Lead:** dashboard polished, incident reports printed, SAC ready
- **Success criteria:** clean live demo, all 4 evaluation criteria addressed

---

## 9. GLOSSARY

| Term | Meaning |
|------|---------|
| **FastAPI** | Python web framework for building HTTP APIs. Creates the server that hosts /health, /ready, /predict, /metrics. |
| **Endpoint** | A URL path on the server (like /health) that responds to HTTP requests. |
| **asyncio** | Python's concurrency framework. Lets the pipeline and API run simultaneously in one process. |
| **Lifespan** | FastAPI feature that runs setup/teardown code when the app starts/stops. We start the pipeline here. |
| **Pipeline** | The detection loop: OBSERVE→ANALYZE→DETECT→RESPOND, running every 30 seconds. |
| **Isolation Forest** | ML algorithm that learns "normal" and flags outliers. Our primary detection model. |
| **DBSCAN** | Clustering algorithm that labels non-clustered points as anomalies. Our backup model. |
| **Feature engineering** | Converting raw logs into numerical measurements (features) the model can score. |
| **MTTD** | Mean Time To Detect — milliseconds from event to detection. 40% of the competition grade. |
| **pipeline_mttd_ms** | Detection latency we control: detected_at minus ingested_at. |
| **e2e_mttd_ms** | Real-world latency: detected_at minus the original log event time. |
| **Contamination** | Model parameter: estimated fraction of anomalous data. Controls sensitivity. |
| **Threshold** | Score cutoff that separates threat levels. Configurable in .env. |
| **Model versioning** | Saving each trained model with metadata for rollback and comparison. |
| **joblib** | Library for serializing scikit-learn models to disk. Used instead of pickle. |
| **SAP HANA** | SAP's in-memory database. Stores logs, anomalies, and model metadata. |
| **Connection pool** | Pre-opened database connections reused for performance. Managed in pool.py. |
| **Repository pattern** | Database access through classes with methods like insert_logs(). Never raw SQL outside repositories. |
| **Mock mode** | Automatic fallback when SAP credentials aren't set. Uses CSV files and in-memory storage. |
| **Cloud Foundry (CF)** | SAP's app hosting platform. Our app runs here in production. |
| **BTP** | SAP Business Technology Platform — the cloud ecosystem including CF, HANA, and SAC. |
| **manifest.yml** | CF deployment config: memory, buildpack, start command, health check. |
| **CI/CD** | Automated test (CI) and deploy (CD) pipelines via GitHub Actions. |
| **Webhook** | HTTP callback — we POST to SAP's webhook URL when we detect an attack. |
| **Streamlit** | Python library that creates web dashboards from Python scripts. Runs locally only. |
| **Plotly** | Charting library for interactive visualizations in the dashboard. |
| **Pydantic** | Data validation library used by FastAPI for request/response schemas. |
| **Scaler** | StandardScaler — normalizes features before model scoring. Saved alongside the model. |
| **GitHub Secrets** | Encrypted variables in repo settings, used by CI/CD for credentials. |
| **SAP Analytics Cloud** | SAP's BI tool for executive dashboards. Connects to HANA. |

---

*You are the PM. When in doubt — you own it.*
