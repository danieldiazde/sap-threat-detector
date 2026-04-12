# 👥 Team Roles & Responsibilities

Based on the SAP Hackathon presentation.

---

## 1. AI & Data Science Specialist
**Primary modules:** `src/model/`

- Architect the log processing pipeline
- Develop unsupervised anomaly detection models (Isolation Forest, DBSCAN, Keras)
- Feature engineering from SAP security logs
- Noise reduction: distinguish real threats from normal traffic spikes
- Tune the model decision threshold for high precision
- Owns `tests/model/`

---

## 2. Cloud Integration Engineer
**Primary modules:** `infra/`, `src/ingestion/`, `.github/workflows/`

- Lead orchestration within SAP BTP
- Deploy and manage microservices on Cloud Foundry
- Manage API consumption from the SAP log API
- Automate the alerting flow (ingestion → model → webhook)
- Ensure seamless connectivity between AI models and SAP services
- Owns CI/CD pipelines

---

## 3. Data Architect & Backend Developer
**Primary modules:** `src/storage/`, `src/ingestion/`

- Design and manage SAP HANA schema for log storage
- Optimize real-time data ingestion (batch/bulk inserts)
- Query optimization for high-volume log volumes
- Support backend logic of the application
- Owns `src/storage/schema.sql` and `src/storage/hana_client.py`

---

## 4. Security Analyst & Visualization Lead
**Primary modules:** `src/dashboard/`, `docs/`

- Design executive dashboards in SAP Analytics Cloud (SAC)
- Build interactive real-time interface in Streamlit
- Translate technical anomalies into actionable business insights
- Perform forensic analysis on detected incidents
- Deliver the final strategic incident report
- Owns `docs/INCIDENT_REPORT.md`

---

## 5. Technical Project Manager & Scrum Master
**Primary scope:** GitHub Projects board, all modules (review)

- Oversee end-to-end project lifecycle using Agile
- Manage the Product Backlog and Sprint Goals
- Ensure alignment between technical delivery and SAP's objectives
- Mitigate integration risks between Cloud Foundry and HANA
- Primary link between the team and SAP stakeholders
- Ensure final solution meets compliance and security standards
- Resource allocation across the SAP landscape

---

## GitHub Project Board Columns
`Backlog` → `In Progress` → `In Review` → `Done`

## Issue Labels
`model` | `ingestion` | `alerting` | `infra` | `dashboard` | `data` | `bug` | `demo-ready`
