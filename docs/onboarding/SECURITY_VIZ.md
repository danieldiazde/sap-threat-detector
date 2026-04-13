# Security Analyst & Visualization Lead — Onboarding Guide

> **TL;DR**
> - You own the dashboard, the incident reports, the documentation, and the story we tell judges about business impact — you make the system's results visible and compelling.
> - You own: `src/dashboard/app.py`, `docs/INCIDENT_REPORT.md`, `docs/ARCHITECTURE.md`, `notebooks/eda.ipynb`
> - Your #1 priority on April 13: explore real SAP data in the EDA notebook, adapt the dashboard charts for real patterns, and refine the incident report template.

---

## 1. WHO YOU ARE

You are the person who turns raw numbers into understanding. The AI model detects attacks, the pipeline processes them, the database stores them — but none of that matters if judges can't SEE it. Your dashboard is what they'll look at during the live demo. Your incident reports are the evidence that the system actually works. Your documentation explains the architecture to evaluators. You own 100% of the 15% "Business Impact & Strategic Analysis" grade, and your dashboard directly affects the 40% "Operational Efficiency" grade by making MTTD numbers front and center.

---

## 2. YOUR MODULES

| File | What it does |
|------|-------------|
| `src/dashboard/app.py` | The Streamlit dashboard — a real-time visualization of the SOC. Shows live MTTD KPIs, threat counts, Plotly charts, system health indicators, and a log feed. Auto-refreshes every 5 seconds. |
| `src/dashboard/__init__.py` | Package init for the dashboard module. |
| `src/alerting/incident_report.py` | Generates a markdown forensic report every time a high-severity attack is detected. Follows the OBSERVE→ANALYZE→DETECT→RESPOND framework. |
| `docs/INCIDENT_REPORT.md` | The template for manual incident reports. Your auto-generated reports are based on this structure. |
| `docs/ARCHITECTURE.md` | System architecture documentation that explains the full pipeline to judges and evaluators. |
| `notebooks/eda.ipynb` | A Jupyter notebook for exploring data visually — timeline charts, IP distributions, feature distributions, anomaly score plots. |

---

## 3. WHAT THE PROJECT DOES

This project is an AI-powered Security Operations Center that watches SAP system logs and detects cyberattacks in real-time. The pipeline runs every 30 seconds, fetching logs, scoring them with an ML model, and alerting on anything suspicious. Your dashboard is the "face" of the system — it's what judges see during the demo. It pulls live data from the FastAPI `/metrics` endpoint to display MTTD numbers (the key metric worth 40% of the grade), threat counts, anomaly distributions, and system health. When a high-severity attack is detected, your `incident_report.py` generates a forensic report that tells the story of what happened, why it's dangerous, and what to do about it — that's the 15% business impact grade.

---

## 4. SETUP — DO THIS FIRST

```bash
# Clone the repo
git clone https://github.com/danieldiazde/sap-threat-detector.git
cd sap-threat-detector

# Create YOUR branch
git checkout dev
git checkout -b feat/security-viz

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

# Start the API server (Terminal 1)
make api
# Success: "Uvicorn running on http://127.0.0.1:8000" appears

# In a NEW terminal, start the dashboard (Terminal 2)
source .venv/bin/activate
make dashboard
# Success: "You can now view your Streamlit app in your browser" appears
# Open http://localhost:8501 — the dashboard should load with live data
```

---

## 5. YOUR FILES IN DETAIL

### `src/dashboard/app.py`

The Streamlit dashboard — the live visualization judges will see during the demo. It fetches data from three FastAPI endpoints (`/metrics`, `/health`, `/ready`) every 5 seconds via `streamlit-autorefresh`. The layout:

- **KPI row** (top): 6 metrics — Active Threats, Pipeline MTTD p50, MTTD p95, E2E MTTD p50, Logs Processed, Alerts Sent/Failed
- **Charts row 1**: Requests/Min Timeline (area chart), Threat Level Distribution (donut chart)
- **Charts row 2**: Top 10 Source IPs (bar chart), MTTD Distribution (stats + progress bar)
- **Active Threats table**: count of anomalies detected
- **Recent Log Feed**: last 20 log entries
- **Sidebar**: System health indicators (HANA status, SAP API live/mock, Webhook live/mock, pipeline state, last run time, error count)

When the API is not running, it falls back to loading local CSV files and shows a warning banner.

**Already built:** Full dashboard with all 4 charts, KPI row, sidebar, auto-refresh, fallback mode.

**TODO for April 13:** Once real data is flowing:
1. Check if the chart colors and labels make sense for real traffic patterns
2. The MTTD KPIs should be the most prominent elements — consider increasing font size if needed
3. Add a chart or metric that shows attack types (SQL injection, brute force, etc.) if the data supports it

**Study:** Streamlit documentation — understand `st.metric()`, `st.columns()`, `st.plotly_chart()`. Also Plotly Express for creating charts.

### `src/alerting/incident_report.py`

Generates a markdown forensic report automatically for every high-severity anomaly. The report follows the OBSERVE→ANALYZE→DETECT→RESPOND framework:
- **Summary table**: incident ID, detected time, source IP, threat level, anomaly score, MTTD
- **OBSERVE**: evidence log entries from the triggering IP
- **ANALYZE**: the feature values that made the model flag this IP
- **DETECT**: latency measurements (pipeline MTTD and E2E MTTD)
- **RESPOND**: webhook status, alert ID, dedup key
- **Remediation**: automated recommendations based on the attack type (SQL injection → check WAF logs, brute force → enforce rate limiting, etc.)

Reports are saved to `reports/incidents/<incident-id>.md`.

**Already built:** Full report generation with evidence tables, feature tables, recommendations engine, and file persistence.

**TODO for April 13:** Review the generated reports with real data. Are the recommendations helpful? Is the evidence table showing the right columns? Refine the text in the remediation section to be more specific to SAP security contexts.

### `docs/INCIDENT_REPORT.md`

The manual incident report template. This is the reference format that `incident_report.py` is based on. You can edit this template to improve the structure, and then update the code to match.

**Already built:** Complete template with all sections.

**TODO for April 13:** After seeing real attacks, add example incidents to this template as appendices — concrete examples make the 15% business impact grade much stronger.

### `docs/ARCHITECTURE.md`

System architecture documentation. Explains the pipeline flow, module map, deployment topology, mock mode, configuration approach, and key dates. Judges evaluating the 20% architecture grade will read this.

**Already built:** Complete architecture document.

**TODO for April 13:** Update with any changes made during the real data transition. Add a "lessons learned" section if anything was surprising about the real data.

### `notebooks/eda.ipynb`

A Jupyter notebook for exploratory data analysis. Cells: load data → basic statistics → timeline chart → top IPs → feature engineering preview → feature distributions → anomaly score visualization.

**Already built:** Full notebook with all analysis cells.

**TODO for April 13:** This is your most important analysis tool on day one of real data. Run every cell with real SAP logs. Key questions to answer:
- What does normal traffic look like? (volume, timing, sources)
- What patterns do attacks have? (spikes, unusual IPs, error rates)
- Are there data quality issues? (missing fields, unexpected formats)

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
I am the Security Analyst & Visualization Lead on the TEC × SAP Hackathon team.
We are building an AI-powered Security Operations Center that detects
cyberattacks in real-time from SAP security logs.

PROJECT: sap-threat-detector
REPO: https://github.com/danieldiazde/sap-threat-detector
BRANCH: I am working on feat/security-viz, PRs go into dev (never main).

MY FILES (I own these):
- src/dashboard/app.py — Streamlit real-time SOC dashboard
- src/alerting/incident_report.py — auto-generated forensic reports
- docs/INCIDENT_REPORT.md — manual incident report template
- docs/ARCHITECTURE.md — system architecture documentation
- notebooks/eda.ipynb — exploratory data analysis notebook

CURRENT STATE:
- Dashboard is built and working with mock data
- Auto-refreshes every 5 seconds via streamlit-autorefresh
- Fetches from FastAPI /metrics, /health, /ready endpoints
- Falls back to local CSV when API is not running
- 4 Plotly charts: timeline, threat donut, top IPs, MTTD distribution
- Sidebar shows system health (HANA, API, Webhook, Pipeline status)
- Real data arrives April 13

CODING STANDARDS:
- No print() in src/ — use: from src.common.logging import get_logger
  then logger = get_logger(__name__). Scripts in scripts/ may use print() for CLI output.
- All config via: from src.common.config import settings
- Dashboard reads config via os.getenv() directly to avoid importing heavy ML libs
- Type hints on every function, Google-style docstrings on public methods
- Import train/predict directly from their modules (not from src.model):
  from src.model.train import train (correct)
  from src.model import train (WRONG — namespace conflict)

KEY DATES:
- April 13: real SAP data arrives → explore in notebook, adapt dashboard
- May 4: Go Live on SAP BTP
- May 12-14: Judges evaluate live system — dashboard is the demo

EVALUATION:
- 40% MTTD — must be most prominent KPIs on dashboard
- 15% Business Impact — I own this entirely (incident reports, narrative)
- 20% Architecture — docs/ARCHITECTURE.md contributes here

Help me improve the dashboard, incident reports, and data analysis.
```

### Example Requests

1. "Help me add a new Plotly chart to the dashboard that shows attack types over time"
2. "The MTTD numbers on the dashboard are too small — help me make them bigger and more prominent"
3. "Review the incident report template and suggest improvements to make it more compelling for judges"
4. "Help me create a new cell in the EDA notebook that compares weekday vs weekend traffic patterns"
5. "Walk me through how the dashboard connects to the API — which endpoints does it call and what data does it get?"

### Important Warning

Always tell Claude Code which branch you're on before making changes. Run `git status` and tell Claude Code the output before asking it to edit files.

---

## 7. DAY-TO-DAY WORKFLOW

### Working on your branch

Always work on your branch (`feat/security-viz`), never on `main` or `dev` directly.

```bash
# Make sure you're on your branch
git checkout feat/security-viz

# Pull latest changes from dev into your branch
git fetch origin
git merge origin/dev
```

### Committing your work

```bash
# Stage your changes
git add src/dashboard/ src/alerting/incident_report.py docs/ notebooks/

# Commit with a descriptive message
git commit -m "feat(dashboard): describe what you did"

# Push to GitHub
git push origin feat/security-viz
```

### Good commit message examples

- `feat(dashboard): add attack type breakdown chart with real data categories`
- `fix(dashboard): increase MTTD KPI font size for demo readability`
- `docs: add real incident examples to INCIDENT_REPORT.md`

### Opening a Pull Request

1. Go to the GitHub repo in your browser
2. Click "Compare & pull request" for your branch
3. Set the target branch to `dev` (NOT main)
4. Describe what you changed and why
5. Request review from Daniel (PM)

### If something breaks

```bash
# Undo changes to a specific file
git checkout -- src/dashboard/app.py

# See what you changed
git diff src/dashboard/app.py
```

---

## 8. APRIL 13 CHECKLIST

1. **Open the EDA notebook with real data:**
   ```bash
   jupyter notebook notebooks/eda.ipynb
   ```
   Run every cell. Answer these questions:
   - How many unique IPs are there?
   - What's the request volume per minute?
   - What event types appear? (check `event_description` column)
   - Are there obvious attack patterns visible in the data?

2. **Update the dashboard for real data patterns:**
   - Start the API: `make api` (Terminal 1)
   - Start the dashboard: `make dashboard` (Terminal 2)
   - Watch it for a few minutes with real data flowing
   - Are the charts useful? Do the colors make sense?
   - Is MTTD prominently displayed? (this is 40% of the grade)

3. **Review auto-generated incident reports:**
   - Wait for a high-severity detection (or trigger one manually)
   - Check `reports/incidents/` for the generated markdown
   - Read it: does it tell a clear story? Are the recommendations useful?
   - If not, edit `src/alerting/incident_report.py` to improve the template

4. **Prepare the SAP Analytics Cloud (SAC) executive dashboard:**
   - Connect SAC to HANA (coordinate with Data Architect)
   - Create an executive summary: total threats, MTTD trend, top attackers
   - This is for the 25% SAP integration grade

5. **Document 3 real attack examples:**
   - Pick 3 interesting anomalies from the first real data
   - Write up each one following the INCIDENT_REPORT.md template
   - Include in the final presentation for the 15% business impact grade

6. **Update docs/ARCHITECTURE.md** if anything changed during the real data transition.

---

## 9. DO NOT TOUCH

Do not edit these files. If you think something needs to change in them, open a GitHub Issue or ask Daniel.

- `src/model/` — ML model code (owned by AI Specialist)
- `src/api/` — FastAPI endpoints (owned by Cloud Engineer)
- `src/pipeline.py` — pipeline orchestrator (owned by Cloud Engineer)
- `src/ingestion/` — log fetching and parsing (owned by Cloud Engineer / Data Architect)
- `src/storage/` — HANA database layer (owned by Data Architect)
- `src/alerting/sap_webhook.py` �� webhook sender (owned by Cloud Engineer)
- `src/alerting/deduplication.py` — alert deduplication (owned by Cloud Engineer)
- `src/common/` — shared config, logging, metrics, time utilities
- `infra/` — Cloud Foundry deployment configuration
- `.github/workflows/` — CI/CD pipelines

---

## 10. IF SOMETHING BREAKS

**ERROR:** `streamlit: command not found`
**CAUSE:** The virtual environment isn't activated, or Streamlit isn't installed.
**FIX:** `source .venv/bin/activate && make install` then `make dashboard`

**ERROR:** Dashboard shows "API not reachable at localhost:8000"
**CAUSE:** The FastAPI server isn't running.
**FIX:** Open a separate terminal and run `make api`. The dashboard needs the API running to fetch live data.

**ERROR:** Charts show "No data available" even though the API is running
**CAUSE:** The pipeline hasn't processed any logs yet, or no mock data was generated.
**FIX:** Run `make mock` to generate sample data, then `make train` to train the model. Wait 30 seconds for the pipeline to process the first batch.

**ERROR:** `ModuleNotFoundError: No module named 'streamlit_autorefresh'`
**CAUSE:** The `streamlit-autorefresh` package isn't installed.
**FIX:** `pip install streamlit-autorefresh` or `make install`

**ERROR:** Incident reports have empty evidence tables ("No evidence rows captured")
**CAUSE:** The evidence DataFrame passed to `build_incident_report()` was empty — likely the triggering IP's logs weren't found in the current batch.
**FIX:** This can happen with small batches. Not a bug — the report still generates. With real data (larger batches), evidence should appear consistently.

---

## 11. GLOSSARY

| Term | Meaning |
|------|---------|
| **Streamlit** | A Python library that turns Python scripts into web applications. You write Python, it automatically becomes a website — no HTML, CSS, or JavaScript needed. |
| **Plotly** | A charting library that creates interactive graphs. You can hover over data points, zoom in, and export images. Used in the dashboard for all four charts. |
| **Dashboard** | A visual display of live data. Our dashboard shows MTTD numbers, threat counts, charts, and system health. Judges will look at this during the demo. |
| **MTTD** | Mean Time To Detect — how many milliseconds pass between a security event happening and the system detecting it. Lower is better. Worth 40% of the grade. |
| **KPI** | Key Performance Indicator — a number that tells you how well the system is doing. Our main KPIs are MTTD p50 and p95. |
| **Anomaly** | A data point that the model flagged as suspicious — it doesn't fit the pattern of normal traffic. Could be a real attack or a false positive. |
| **Incident report** | A document that describes a detected security incident: what happened, when, why it matters, and what to do about it. Generated automatically for high-severity anomalies. |
| **Forensic analysis** | The process of examining evidence from a security incident to understand what happened, how, and who did it. The incident report is a simplified version of this. |
| **SAP Analytics Cloud (SAC)** | SAP's business intelligence tool — used for executive-level dashboards and reports. Connects to HANA for live data. |
| **Endpoint** | A URL on the API server that returns data. The dashboard calls `/metrics` for MTTD numbers and `/health` for system status. |
| **API call** | When one program requests data from another over HTTP. The dashboard makes API calls to the FastAPI server every 5 seconds. |
| **Mock mode** | When the system uses fake data instead of real SAP data. The dashboard works in both modes — it just shows a warning banner in mock mode. |
| **pipeline_mttd_ms** | Time from when the pipeline received a log batch to when the model flagged an anomaly. Measures internal processing speed. |
| **e2e_mttd_ms** | Time from when the original event occurred to when it was detected. Measures real-world detection latency. |
| **Threat level** | Classification assigned by the model: high (serious attack), medium (suspicious), or low (minor anomaly). |
| **Auto-refresh** | The dashboard automatically reloads data every 5 seconds without you clicking anything. Powered by the `streamlit-autorefresh` library. |

---

*Questions? Ask Daniel (PM) or open a GitHub Issue tagged with label: `dashboard`*
