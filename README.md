# 🛡️ SAP AI Security — Anomaly Detection
**TEC × SAP Hackathon | Team Project**

> Real-time threat defense for SAP infrastructure using unsupervised ML anomaly detection.

---

## 🎯 Mission
**OBSERVE → ANALYZE → DETECT → RESPOND**

Build a live Security Operations Center (SOC) pipeline that:
1. **Ingests** security logs from the SAP API (paginated)
2. **Analyzes** log patterns using unsupervised ML (NumPy + Pandas + Scikit-learn)
3. **Detects** anomalies: spike attacks, multi-bucket anomalies, unusual request patterns
4. **Responds** automatically via a SAP Alerting Webhook

---

## 📅 Key Dates
| Date | Milestone |
|------|-----------|
| April 6 | Kick Off + Course & Learning Materials |
| **April 13** | API & Data Access provided by SAP |
| **April 27** | Alerting Webhook provided by SAP |
| **May 4** | Go Live |
| May 12–14 | First Eliminatory Phase |
| May 15 | Next Phase Winner Announcements |
| **May 21** | Final Phase — First To Go Down |

---

## 🏗️ Architecture

```
                        ┌─────────────────────────────────────┐
                        │           HIGH MICROSERVICE LEVEL    │
  SAP Data Centers ────►│                                      │
  (API Auth Key)        │  ┌────────────┐    ┌─────────────┐  │
                        │  │ ETL        │───►│ Data Storage │  │
  SAP Log Batches ─────►│  │ Pipeline   │    │ (SAP HANA)  │  │
                        │  └────────────┘    └─────────────┘  │
                        │        │                  │          │
                        │        ▼                  ▼          │
                        │  ┌──────────────────────────────┐   │
                        │  │        ML MODULE              │   │
                        │  │  ┌────────────┐ ┌──────────┐ │   │
                        │  │  │  Model     │ │ Retrain  │ │   │
                        │  │  │ Versioning │ │ Pipeline │ │   │
                        │  │  └────────────┘ └──────────┘ │   │
                        │  │  ┌────────────┐ ┌──────────┐ │   │
                        │  │  │    Obs     │ │Integrat- │ │   │
                        │  │  │Capabilities│ │  ions    │ │   │
                        │  └──────────────────────────────┘   │
                        │        │                             │
                        │        ▼                             │
                        │  ┌──────────┐   ┌───────────────┐  │
                        │  │Dashboards│   │Alerting System│  │
                        │  │(Streamlit│   │  → Webhook ───┼──┼──► SAP AI Security Team
                        │  │  + SAC)  │   │               │  │
                        │  └──────────┘   └───────────────┘  │
                        └─────────────────────────────────────┘
```

---

## 🗂️ Repository Structure

```
sap-threat-detector/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # Lint + tests on every PR
│   │   └── deploy.yml          # Deploy to SAP BTP Cloud Foundry on merge to main
│   └── CODEOWNERS              # Auto-assign reviewers by module
│
├── src/
│   ├── ingestion/              # OBSERVE — ETL Pipeline
│   │   ├── __init__.py
│   │   ├── sap_log_fetcher.py  # Paginated log ingestion from SAP API
│   │   └── log_parser.py       # Parse raw log format → structured DataFrame
│   │
│   ├── model/                  # ANALYZE + DETECT — ML Module
│   │   ├── __init__.py
│   │   ├── features.py         # Feature engineering (NumPy + Pandas)
│   │   ├── train.py            # Unsupervised model training (Isolation Forest / DBSCAN)
│   │   ├── predict.py          # Run inference on incoming log batches
│   │   └── versioning.py       # Model versioning + retrain pipeline
│   │
│   ├── alerting/               # RESPOND — Alerting System
│   │   ├── __init__.py
│   │   ├── sap_webhook.py      # POST alert to SAP webhook endpoint
│   │   └── incident_report.py  # Generate forensic incident report
│   │
│   ├── storage/                # Data persistence — SAP HANA
│   │   ├── __init__.py
│   │   ├── hana_client.py      # SAP HANA connection + queries
│   │   └── schema.sql          # Table definitions for log storage
│   │
│   └── dashboard/              # Visualization — Streamlit + SAC
│       ├── __init__.py
│       └── app.py              # Streamlit real-time dashboard
│
├── tests/
│   ├── unit/                   # Unit tests per module
│   │   ├── test_ingestion.py
│   │   ├── test_features.py
│   │   ├── test_model.py
│   │   └── test_alerting.py
│   ├── integration/            # End-to-end pipeline tests
│   │   └── test_pipeline.py
│   └── model/                  # Model quality tests (precision, recall, MTTD)
│       └── test_anomaly_detection.py
│
├── notebooks/
│   └── eda.ipynb               # Exploratory Data Analysis — use AFTER getting real data Apr 13
│
├── infra/
│   ├── manifest.yml            # SAP BTP Cloud Foundry deployment manifest
│   └── mta.yaml                # Multi-Target Application descriptor for BTP
│
├── data/
│   └── samples/
│       └── sample_logs.csv     # Mock log data matching SAP format (for dev before Apr 13)
│
├── docs/
│   ├── ARCHITECTURE.md         # Detailed architecture decisions
│   ├── ROLES.md                # Team roles and responsibilities
│   └── INCIDENT_REPORT.md      # Template for forensic incident reporting
│
├── .env.example                # Required environment variables (never commit .env)
├── .gitignore
├── Makefile                    # Shortcuts: make install, make test, make run, make deploy
├── requirements.txt            # Python dependencies
├── Procfile                    # Cloud Foundry process definition
└── README.md
```

---

## 👥 Team Roles

| Role | Responsibility | Primary Modules |
|------|---------------|-----------------|
| **AI & Data Science Specialist** | ML pipeline + anomaly detection models | `src/model/` |
| **Cloud Integration Engineer** | SAP BTP orchestration + Cloud Foundry deployment | `infra/`, `src/ingestion/` |
| **Data Architect & Backend Developer** | SAP HANA schema + data ingestion | `src/storage/`, `src/ingestion/` |
| **Security Analyst & Visualization Lead** | Streamlit dashboard + SAC reports + forensic analysis | `src/dashboard/`, `docs/` |
| **Technical Project Manager & Scrum Master** | Backlog, sprints, integration risk, stakeholder comms | GitHub Projects board |

---

## 🔬 ML Approach

The model uses **unsupervised learning** — no labeled attack data needed.

**Log format expected from SAP API:**
```
[IP] - - [TIME] "GET [PATH]/[FILE] HTTP/[VERSION]" [STATUS] [SIZE]
[IP] - - [TIME] "POST [PATH]/[FILE] HTTP/[VERSION]" [STATUS] [SIZE]
```

**Anomaly types to detect (per presentation):**
- **Spike Anomaly** — sudden massive request volume from an IP
- **Multi-Bucket Anomaly** — sustained elevated traffic across multiple time windows
- **Categorization Anomaly** — unusual request patterns (e.g. POST to `/cgi-bin/` returning 404)

**Candidate models:**
- `IsolationForest` (scikit-learn) — primary anomaly detector, threshold-based
- `DBSCAN` — clustering to identify outlier request patterns
- Keras neural network — optional enhancement after baseline works

---

## 📊 Evaluation Criteria (from SAP)

| Criterion | Weight | What we optimize |
|-----------|--------|-----------------|
| Operational Efficiency & Real-Time Response | **40%** | Minimize MTTD, maximize automation |
| SAP Ecosystem Integration & Tooling | **25%** | BTP + Cloud Foundry + HANA + SAC |
| Architecture & MLOps Maturity | **20%** | Scalable pipeline, clean separation ML vs integration |
| Business Impact & Strategic Analysis | **15%** | Forensic report, executive storytelling |

---

## ⚙️ Tech Stack

**Core Engineering & AI**
- Data manipulation: `pandas`, `numpy`
- ML: `scikit-learn` (baseline) + `keras` (advanced)
- Frontend: `streamlit`

**SAP Enterprise Infrastructure**
- SAP BTP — application orchestration
- SAP Cloud Foundry — runtime + deployment
- SAP HANA — log storage + querying
- SAP Analytics Cloud (SAC) — executive dashboards

---

## 🚀 Getting Started

```bash
# 1. Clone the repo
git clone https://github.com/your-org/sap-threat-detector.git
cd sap-threat-detector

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
make install

# 4. Copy and fill in environment variables
cp .env.example .env

# 5. Run tests
make test

# 6. Run the dashboard locally
make dashboard

# 7. Run the pipeline locally (uses mock data until Apr 13)
make run
```

---

## 🌿 Branching Strategy

- `main` — always deployable, protected, requires 1 PR review + CI green
- `dev` — integration branch, merge here first
- Feature branches: `feat/`, `fix/`, `mlops/`, `infra/`, `data/`

**Example:** `feat/isolation-forest-model`, `infra/btp-cloud-foundry`, `data/hana-schema`

---

## ⚠️ Important Security Rules (from SAP)

- **Never commit credentials** — use `.env` (gitignored) and GitHub Secrets
- **Never commit raw log data** — `data/raw/` is gitignored
- If credentials are exposed, SAP will **deprecate them and block the team for the next day**
- All SAP API keys go in GitHub Secrets, not in code

---

## 📝 Notes for the Team

- Until **April 13** (API access), use `data/samples/sample_logs.csv` for development
- Until **April 27** (webhook), mock the webhook call in `src/alerting/sap_webhook.py`
- The demo moment SAP judges care about most: **attack detected → webhook fires in real time**
- Prioritize **MTTD** (Mean Time to Detect) — it's 40% of the grade
