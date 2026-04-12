# AI & Data Science Specialist — Onboarding Guide

> **TL;DR**
> - You build and tune the anomaly detection model that decides what is an attack and what isn't.
> - You own: `src/model/` (all files), `tests/model/`, `notebooks/eda.ipynb`
> - Your #1 priority on April 13: retrain the model on real SAP logs and tune thresholds so the system catches real attacks without flooding the team with false alarms.

---

## 1. WHO YOU ARE

You are the person who teaches the computer what "normal" looks like — and flags everything that doesn't fit. Your job is to make sure the anomaly detection model works well: it should catch real attacks quickly (low MTTD) and not cry wolf on normal traffic (few false positives). You don't need to build things from scratch — the model code is already written and working. Your main work is understanding how it works, and then tuning it once real data arrives on April 13.

---

## 2. YOUR MODULES

| File | What it does |
|------|-------------|
| `src/model/schema.py` | Defines the exact list of features (measurements) the model uses, plus the expected columns in raw log data — this is the single source of truth that every other file imports from. |
| `src/model/features.py` | Takes raw log data (rows of events) and converts them into a table where each row represents one IP address's behavior — counting things like total requests, error rates, and brute-force attempts. |
| `src/model/train.py` | Trains the model on historical data so it learns what "normal" looks like — you run this manually when you have new data. |
| `src/model/predict.py` | Runs automatically in real-time: takes new log data, scores it with the trained model, and stamps each detection with a timestamp so we can measure how fast we detected it (MTTD). |
| `src/model/versioning.py` | Saves and loads trained models with version tags, so you can always roll back to a previous model if a new one performs worse. |
| `src/model/dbscan_detector.py` | A backup anomaly detection algorithm (DBSCAN) that works differently from the primary one — useful if Isolation Forest doesn't perform well on real data. |
| `src/model/evaluate.py` | Runs quality checks on a trained model: anomaly rate, cross-validation stability, and other metrics that tell you if the model is reasonable. |
| `src/model/__init__.py` | Package init — re-exports commonly used names so other modules can import them easily. |
| `tests/model/test_anomaly_detection.py` | Tests that verify the model trains correctly, scores data, and assigns threat levels properly. |
| `notebooks/eda.ipynb` | A Jupyter notebook for exploring data visually — distributions, top IPs, score charts. You'll use this heavily after April 13. |

---

## 3. WHAT THE PROJECT DOES

This project is an AI-powered Security Operations Center (SOC) that watches SAP system logs in real-time and detects cyberattacks. Every 30 seconds, the system fetches a batch of logs from SAP, extracts behavioral features per IP address, runs them through your anomaly detection model, and fires a webhook alert for anything suspicious. Your model is the brain of the entire system — without it, the system just collects logs without understanding them. The key metric judges care about is MTTD (Mean Time To Detect): how many milliseconds pass between a log event happening and the system flagging it as an attack. That metric is 40% of the competition grade, and your model's speed and accuracy directly determine it.

---

## 4. SETUP — DO THIS FIRST

```bash
# Clone the repo
git clone https://github.com/danieldiazde/sap-threat-detector.git
cd sap-threat-detector

# Create YOUR branch
git checkout dev
git checkout -b feat/ai-specialist

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

# Generate mock SAP logs (fake data for development)
make mock
# Success: data/samples/ directory gets a CSV file with 5000 rows

# Train the model on mock data
make train
# Success: models/ directory appears with a version folder inside
# You'll see a training report printed: version tag, anomaly rate, elapsed time

# Run all tests
make test
# Success: all tests pass (green), no red errors

# Start the API server
make api
# Success: "Uvicorn running on http://127.0.0.1:8000" appears
# Open http://localhost:8000/health in your browser — should show {"status":"ok"}
```

---

## 5. YOUR FILES IN DETAIL

### `src/model/schema.py`

This file is the single source of truth for what the model sees. It defines `FEATURE_COLUMNS` — the exact list of 13 measurements extracted from each IP's behavior. Every other file in `src/model/` imports this list instead of defining its own copy. If you want to add a new feature, you add it here first, then implement the computation in `features.py`, then retrain.

**Already built:** All 13 features defined, suspicious path fragments, SQL injection keywords, brute-force keywords, text-to-HTTP-code mappings for SAP's non-standard status codes.

**TODO for April 13:** Check whether real SAP logs have event descriptions that match the keyword lists. If SAP uses different wording (e.g., "login failed" instead of "failed login"), update the keyword tuples in this file.

**Study:** Read the SAP hackathon presentation slides on anomaly types (Spike, Multi-Bucket, Categorization) to understand why these specific features were chosen.

### `src/model/features.py`

This is the ANALYZE phase. It takes a raw log DataFrame (hundreds of rows, one per event) and groups them by `source_ip`, then computes 13 measurements per IP. For example: how many total requests did this IP make? What percentage were errors? How many looked like SQL injection attempts? The output is a feature matrix where each row is one IP and each column is one measurement.

**Already built:** All 13 feature computations, including global features like `request_rate_zscore` (how unusual is this IP's request volume compared to the batch average). The enrichment step handles SAP's text-based status codes ("DENIED", "BLOCKED") that don't look like normal HTTP codes.

**TODO for April 13:** Verify that `extract_features()` produces reasonable numbers on real data. If the feature distributions look wrong (e.g., all zeros for `brute_force_score`), the keywords in `schema.py` may need updating to match SAP's actual event descriptions.

**Study:** Look up "feature engineering for anomaly detection" — the goal is to convert raw events into numbers that highlight the difference between normal and malicious behavior.

### `src/model/train.py`

This is where the model learns what "normal" looks like. You run `make train` manually, and it: (1) loads the feature matrix, (2) scales it so all features have similar ranges, (3) fits an Isolation Forest that learns the shape of normal traffic, and (4) saves the trained model + scaler + metadata to disk via `ModelRegistry`. You don't need to label data as "attack" or "normal" — the model figures it out by assuming most traffic is normal and flagging the rest.

**Already built:** Full training pipeline with Isolation Forest (primary) and DBSCAN (secondary, selectable via `MODEL_TYPE=dbscan` in `.env`). Model evaluation runs automatically after training.

**TODO for April 13:** Retrain on real data (`make train`) and examine the score distribution. Tune `MODEL_CONTAMINATION` in `.env` — this tells the model roughly what percentage of traffic you think is malicious. Start with 0.05 (5%) and adjust based on what you see.

**Study:** Read scikit-learn's Isolation Forest documentation — the key idea is that anomalies are "easy to isolate" in random trees because they look different from everything else.

### `src/model/predict.py`

This runs automatically in real-time as part of the pipeline. Every 30 seconds, the pipeline calls `predict()` with a new batch of features. It loads the trained model, scores each IP, assigns a threat level (high/medium/low), and — critically — stamps each row with `detected_at` so the system can compute `pipeline_mttd_ms` (time from ingestion to detection). It also maintains a sliding context window that tracks IPs across multiple batches for multi-bucket anomaly detection.

**Already built:** Full prediction pipeline, threat level assignment, dual MTTD stamping, sliding context window, model caching (loads from disk once, reuses until a new version appears).

**TODO for April 13:** After retraining, check that `predict()` produces reasonable threat levels on real data. If too many IPs are flagged "high", loosen `ALERT_HIGH_THRESHOLD` in `.env` (make the number more negative). If too few are flagged, tighten it (make it less negative).

**Study:** The `decision_function` in scikit-learn returns a score where negative = more anomalous. The thresholds in `.env` control where "medium" and "high" cutoffs are.

### `src/model/versioning.py`

Every time you train a model, the `ModelRegistry` saves it under `models/<version_tag>/` with three files: `model.joblib` (the trained algorithm), `scaler.joblib` (the feature scaler), and `manifest.json` (metadata: which features, what hyperparameters, how many samples, when it was trained). There's also a `latest.txt` pointer that tells the prediction code which version to load. This means you can train multiple times, compare results, and roll back if a new model is worse.

**Already built:** Full versioning system with save, load, list, activate, and cache invalidation.

**TODO for April 13:** Nothing — this module is complete. Just be aware that each `make train` creates a new version, and the latest one is automatically used by `predict.py`.

**Study:** `joblib` is like `pickle` but optimized for NumPy arrays — it's the standard way to save scikit-learn models to disk.

### `src/model/dbscan_detector.py`

A wrapper around scikit-learn's DBSCAN algorithm. Unlike Isolation Forest (which scores how "isolated" a point is), DBSCAN groups points into clusters and labels anything that doesn't fit a cluster as an anomaly. This is your backup: if Isolation Forest doesn't work well on real data, set `MODEL_TYPE=dbscan` in `.env` and retrain.

**Already built:** Full DBSCAN wrapper with a `decision_function` interface that matches Isolation Forest (so the rest of the code doesn't need to change).

**TODO for April 13:** Only switch to this if Isolation Forest performs poorly. Test both and compare anomaly rates.

### `src/model/__init__.py`

**Important warning:** The `__init__.py` was modified to remove `train`, `predict`, `anomalies_only`, and `reset_active_model` from its exports. This was necessary to avoid Python namespace conflicts where the package was shadowing its own submodules.

Always import these functions directly from their modules:

```python
from src.model.train import train          # correct
from src.model.predict import predict      # correct
from src.model import train                # WRONG — will not work
from src.model import predict              # WRONG — will not work
```

This applies to any new code you write. If you see an `ImportError` about `train` or `predict`, this is probably why.

### `notebooks/eda.ipynb`

A Jupyter notebook for exploring data visually. It loads sample logs, shows basic statistics, plots request volume over time, shows top source IPs, previews the feature engineering output, and (if a model is trained) shows the anomaly score distribution. You'll use this heavily after April 13 to understand what real SAP traffic looks like before tuning the model.

**Already built:** Full notebook with cells for data loading, statistics, timeline charts, feature distributions, and anomaly score visualization.

**TODO for April 13:** Run every cell with real data. Look at the distributions. Ask: do the features make sense? Are the anomaly scores separating attacks from normal traffic?

---

## 6. HOW TO USE CLAUDE CODE FOR YOUR ROLE

### Installation

```bash
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
I am the AI & Data Science Specialist on the TEC × SAP Hackathon team. We are
building an AI-powered Security Operations Center that detects cyberattacks in
real-time from SAP security logs.

PROJECT: sap-threat-detector
REPO: https://github.com/danieldiazde/sap-threat-detector
BRANCH: I am working on feat/ai-specialist, PRs go into dev (never main).

MY FILES (I own these):
- src/model/schema.py — feature column definitions, keyword lists
- src/model/features.py — per-IP feature extraction from raw logs
- src/model/train.py — Isolation Forest / DBSCAN training
- src/model/predict.py — real-time scoring, threat levels, MTTD stamping
- src/model/versioning.py — ModelRegistry for saving/loading model versions
- src/model/dbscan_detector.py — backup DBSCAN anomaly detector
- src/model/evaluate.py — model quality metrics
- tests/model/test_anomaly_detection.py — model tests
- notebooks/eda.ipynb — exploratory data analysis

CURRENT STATE:
- Mock mode is active (no real SAP data yet, using CSV mock logs)
- Primary model: Isolation Forest (sklearn)
- Secondary model: DBSCAN (available via MODEL_TYPE=dbscan in .env)
- Keras is intentionally skipped until after April 13 validation
- Models directory may be empty — run "make train" to create a model

CODING STANDARDS:
- No print() anywhere in src/ — use: from src.common.logging import get_logger
  then logger = get_logger(__name__)
- All config via: from src.common.config import settings
- Model persistence: joblib only, never pickle
- FEATURE_COLUMNS is defined in src/model/schema.py — never redefine it
- Type hints on every function, Google-style docstrings on public methods
- Import train/predict functions directly from their modules:
  from src.model.train import train (correct)
  from src.model import train (WRONG — namespace conflict)

KEY DATES:
- April 13: real SAP_API_URL arrives → retrain model on real data
- May 4: Go Live on SAP BTP Cloud Foundry
- May 12-14: Judges evaluate live system

EVALUATION: MTTD (Mean Time To Detect) is 40% of our grade. Every millisecond
the model takes to score a batch directly impacts our MTTD. The model must be
both fast and accurate.

Help me understand and improve the anomaly detection model.
```

### Example Requests

1. "Explain what Isolation Forest does and how it's implemented in our train.py"
2. "Help me understand the FEATURE_COLUMNS in schema.py and what each one measures"
3. "The model is flagging too many false positives. Help me tune the threshold in .env"
4. "Walk me through what happens step by step when predict.py runs on a new batch"
5. "Help me write a test for the brute_force_score feature in features.py"

### Important Warning

Always tell Claude Code which branch you're on before making changes. Run `git status` and tell Claude Code the output before asking it to edit files.

---

## 7. DAY-TO-DAY WORKFLOW

### Working on your branch

Always work on your branch (`feat/ai-specialist`), never on `main` or `dev` directly.

```bash
# Make sure you're on your branch
git checkout feat/ai-specialist

# Pull latest changes from dev into your branch
git fetch origin
git merge origin/dev
```

### Committing your work

```bash
# Stage your changes
git add src/model/ tests/model/ notebooks/

# Commit with a descriptive message
git commit -m "feat(model): describe what you did"

# Push to GitHub
git push origin feat/ai-specialist
```

### Good commit message examples

- `feat(model): add request_burst_ratio feature to schema.py and features.py`
- `fix(model): lower contamination to 0.03 after testing on real data`
- `test(model): add edge case tests for empty feature DataFrame`

### Opening a Pull Request

1. Go to the GitHub repo in your browser
2. Click "Compare & pull request" for your branch
3. Set the target branch to `dev` (NOT main)
4. Describe what you changed and why
5. Request review from Daniel (PM)

### If something breaks

```bash
# Undo changes to a specific file (discard your edits)
git checkout -- src/model/features.py

# Or see what you changed first
git diff src/model/features.py
```

---

## 8. APRIL 13 CHECKLIST

When SAP API access arrives, here is exactly what you do:

1. **Verify the basics still work:**
   ```bash
   make mock
   make train
   make test
   ```
   All three should pass. If they don't, fix them before touching real data.

2. **Train on real data:** Once `SAP_API_URL` is set in `.env`, the pipeline will start fetching real logs. Wait for a few cycles (a few minutes), then:
   ```bash
   make train
   ```
   This will now train on real SAP logs instead of mock data.

3. **Examine the training report:** Look at the output from `make train`. Key numbers:
   - `anomaly_rate` — what percentage of IPs were flagged? If it's above 20%, the model is probably too aggressive. If it's below 1%, it might be too lenient.
   - `training_samples` — how many IPs did it train on? More is better.

4. **Tune MODEL_CONTAMINATION:** Open `.env` and adjust `MODEL_CONTAMINATION`:
   - Start with `0.05` (assumes 5% of traffic is malicious)
   - If too many false positives: lower it to `0.03` or `0.02`
   - If missing real attacks: raise it to `0.08` or `0.10`
   - Retrain after each change: `make train`

5. **Tune thresholds:** In `.env`, adjust:
   - `ALERT_HIGH_THRESHOLD` — anomaly score below this = "high" severity (default: `-0.3`)
   - `ALERT_MEDIUM_THRESHOLD` — score below this = "medium" severity (default: `-0.1`)
   - Look at the actual score distribution to set these intelligently

6. **Run all tests:**
   ```bash
   make test
   ```
   All model tests must still pass after tuning.

7. **Explore the data in the notebook:**
   ```bash
   jupyter notebook notebooks/eda.ipynb
   ```
   Run every cell. Look at feature distributions. Do they make sense? Are attacks visually separable from normal traffic?

---

## 9. DO NOT TOUCH

Do not edit these files. If you think something needs to change in them, open a GitHub Issue or ask Daniel.

- `src/api/` — FastAPI endpoints (owned by Cloud Engineer)
- `src/pipeline.py` — pipeline orchestrator (owned by Cloud Engineer)
- `src/ingestion/` — log fetching and parsing (owned by Cloud Engineer / Data Architect)
- `src/storage/` — HANA database layer (owned by Data Architect)
- `src/alerting/` — webhook and deduplication (owned by Cloud Engineer)
- `src/dashboard/` — Streamlit dashboard (owned by Security/Viz Lead)
- `src/common/` — shared config, logging, metrics, time utilities
- `infra/` — Cloud Foundry deployment configuration
- `.github/workflows/` — CI/CD pipelines
- `Makefile`, `Procfile`, `requirements.txt`, `pyproject.toml`

---

## 10. IF SOMETHING BREAKS

**ERROR:** `ModelNotFoundError: No trained model found in models/`
**CAUSE:** You haven't trained a model yet, or the `models/` directory was deleted.
**FIX:** Run `make train`. This creates a model version under `models/`.

**ERROR:** `InvalidLogSchemaError: Log DataFrame is missing required columns: ['datetime']`
**CAUSE:** The mock data CSV doesn't have the expected column names, or log_parser.py didn't normalize them.
**FIX:** Run `make mock` to regenerate the mock data. If the error persists with real data, ask the Data Architect to check `src/ingestion/log_parser.py`.

**ERROR:** `ValueError: Cannot train on empty feature DataFrame`
**CAUSE:** The feature extraction produced zero rows — likely the input logs were empty or missing required columns.
**FIX:** Check that `data/samples/` has a CSV file with data. Run `make mock` to regenerate. If using real data, check that the SAP API is returning logs.

**ERROR:** `KeyError: 'total_requests'` in features.py
**CAUSE:** A feature column that `schema.py` expects is missing from the feature extraction output.
**FIX:** Check `features.py::_ip_features()` — every column in `FEATURE_COLUMNS` must be computed there. If you added a new feature to `schema.py`, you must also add its computation to `_ip_features()`.

**ERROR:** Tests fail with `assert scored['is_anomaly'].sum() > 0` but no anomalies detected
**CAUSE:** The model isn't flagging any data as anomalous — likely the contamination is too low or the threshold is too strict.
**FIX:** In `.env`, try raising `MODEL_CONTAMINATION` to `0.10` and making `ANOMALY_SCORE_THRESHOLD` less negative (e.g., `-0.05`). Then retrain: `make train`.

---

## 11. GLOSSARY

| Term | Meaning |
|------|---------|
| **Unsupervised learning** | A type of machine learning where the model learns patterns without being told what's "good" or "bad" — it figures out what's normal and flags anything unusual. |
| **Anomaly score** | A number the model assigns to each IP address. More negative = more anomalous. Normal traffic gets scores near zero or positive. |
| **Contamination** | A parameter you set that tells the model roughly what percentage of the data you expect to be anomalous. It's a rough guess, not exact. |
| **Isolation Forest** | The primary algorithm — it builds random decision trees and measures how quickly each data point can be "isolated" (separated from the rest). Anomalies are isolated faster. |
| **DBSCAN** | The backup algorithm — it groups similar data points into clusters. Anything that doesn't fit any cluster is labeled an anomaly. |
| **Feature engineering** | The process of converting raw log events into numerical measurements (features) that a model can understand — like counting error rates or brute-force attempts per IP. |
| **MTTD (Mean Time To Detect)** | How many milliseconds pass between a security event happening and the system detecting it. Lower is better. This is 40% of the competition grade. |
| **pipeline_mttd_ms** | The time from when the pipeline ingested the log batch to when the model finished scoring it. This measures internal processing speed. |
| **e2e_mttd_ms** | The time from when the original event happened (the log's timestamp) to when the model detected it. This is the "real-world" detection time. |
| **Model versioning** | Saving each trained model with a unique version tag so you can compare versions, roll back to an older model, or track what changed over time. |
| **joblib** | A Python library for saving and loading scikit-learn models to disk. Faster and more reliable than pickle for models with large NumPy arrays. |
| **Cross-validation** | A technique for testing model stability: train on part of the data, test on another part, repeat multiple times. Helps catch models that only work on specific data. |
| **False positive** | When the model flags normal traffic as an attack. Too many false positives wastes the team's time investigating non-threats. |
| **Threshold** | A cutoff value that separates "anomalous" from "normal." Scores below the threshold are flagged. You tune this in `.env`. |
| **Scaler** | A preprocessor (StandardScaler) that adjusts all features to have similar ranges before feeding them to the model. Without it, features with large numbers would dominate. |

---

*Questions? Ask Daniel (PM) or open a GitHub Issue tagged with label: `model`*
