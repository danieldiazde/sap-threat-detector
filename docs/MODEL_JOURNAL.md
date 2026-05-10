# Model Training Journal

Living document tracking every model we train, the decisions behind each
experiment, and the state of the dataset it was trained on. Newer entries
go at the **top** of each section. When something is no longer true, leave
the entry and strike through — we want audit trail, not revisionism.

## How to use this doc

- **Before training** a new model, write a row in *Experiments* with the
  hypothesis, the config, the dataset snapshot, and *why* this experiment
  is worth running. Leaving the metrics column blank until after the run.
- **After training**, fill metrics and the decision (`accepted`,
  `rejected`, `inconclusive`). If accepted, update *Baseline (active)*.
- **When you kill an idea**, add it to *Rejected ideas & why*. Future-you
  will want to know whether the idea was tried and failed vs. never tried.
- **When the dataset shape changes** (new schema column, retention cut,
  re-ingest), add a row to *Dataset versions* with the date and a link to
  the audit report.
- Run `scripts/audit_schema_expansion.py` and `scripts/hana_summary.py`
  periodically and paste the headline numbers into *Dataset versions*.

---

## Baseline (active model)

| Field | Value |
|---|---|
| Version tag | *populated by `src.model.versioning.registry` on next train* |
| Algorithm | `sklearn.ensemble.IsolationForest` |
| Hyperparameters | `n_estimators=200`, `max_samples="auto"`, `contamination=0.05`, `random_state=42` (all configurable via `MODEL_N_ESTIMATORS`, `MODEL_MAX_SAMPLES`, `MODEL_CONTAMINATION`, `MODEL_RANDOM_STATE`) |
| Scaler | `StandardScaler` |
| Feature count | 17 (see `src/model/schema.py::FEATURE_COLUMNS`) |
| Features | `total_requests`, `error_rate`, `post_ratio`, `unique_paths`, `status_4xx_count`, `status_5xx_count`, `denied_ratio`, `suspicious_path_ratio`, `is_destructive_ratio`, `sql_injection_hits`, `brute_force_score`, `port_diversity`, `app_diversity`, `region_diversity`, `interarrival_std`, `interarrival_mean`, `request_rate_zscore` |
| Grouping | One feature row per `source_ip` in the training window |
| Evaluation | `anomaly_rate`, score distribution (`min`, `p10`, `median`, `p90`, `max`, `mean`, `std`), decile gap, 5-fold CV anomaly-rate stability (see `src/model/evaluate.py`) |
| Known caveat | Rows predating commit `5b5d777` (2026-04-21) have NULLs in 16 columns. `src/model/features.py::feature_matrix` currently applies blanket `.fillna(0)`, silently biasing those rows toward "zero-diversity" profiles. See *Open questions* #1. |

---

## Experiments table

| # | Date | Hypothesis | Algorithm | Feature set | Dataset | Key metrics | Decision |
|---|---|---|---|---|---|---|---|
| 1 | 2026-05-06 | SAP-native keywords + `interarrival_mean` improve signal quality | IForest | 17 features — `20260506-230038-b61b7b` | 626 samples (`data/samples/sample_logs.csv`) | anomaly_rate=0.051, score∈[−0.114, 0.182], CV std=0.000 | **accepted** |
| 0 | 2026-04-21 | *(baseline — pre-journal)* | IForest | 16-feature set | HANA `SECURITY_LOGS` at current state | see active baseline row above | **accepted** (incumbent) |

Add one row per experiment. Keep the hypothesis column ≤ 15 words; use the
experiment write-up (if one exists) for the long version. If you write
longer notes, create `docs/experiments/YYYY-MM-DD-<short-id>.md` and link
it from the row.

---

## Rejected ideas & why

*(None yet. First entry after the first failed experiment.)*

Template for a rejection entry:

- **Idea**: <one sentence>
- **Tried when**: <date, experiment #>
- **Why rejected**: <metric delta, complexity cost, dead-end result>
- **Revisit if**: <the condition under which this becomes worth retrying>

---

## Open questions

1. **Pre-expansion NULL handling.** `src/model/features.py:271` blanket-fills
   NaN with 0 across all 16 features, which masks pre-5b5d777 rows as
   low-diversity IPs. Strategy (drop / impute / legacy-model) will be
   decided from the first `scripts/audit_schema_expansion.py` output —
   see `data/reports/schema_audit_<date>.md`.
2. **Hyperparameter tuning.** `contamination`, `n_estimators`, and
   `max_samples` are now settings-driven, but no grid/Bayesian search has
   been run. First sweep is a Phase E task.
3. **Labels.** The dataset is unsupervised. The SAP API was expected to
   surface ground-truth anomaly labels post-April 13. Once labeled data
   exists, `src/model/evaluate.py` already supports precision/recall/F1 —
   re-baseline the model at that point.
4. **Alternative models.** Candidates to benchmark against IForest:
   One-Class SVM, Local Outlier Factor, HDBSCAN, autoencoder
   reconstruction error, gradient-boosted classifier (labels permitting).
5. **Drift detection.** No concept-drift monitoring exists. Should we
   alert when the live anomaly rate diverges by > N σ from the training
   rate?
6. ~~**SAP-native keyword coverage.** Were the brute-force and SQL-injection
   patterns in `BRUTE_FORCE_KEYWORDS` / `SQL_INJECTION_KEYWORDS` aligned
   with what the SAP API actually emits in `event_description`?~~
   **Resolved 2026-05-06** — audited 5,789 real log rows: classic payload
   echoes (`UNION SELECT`, `OR 1=1`, etc.) never appear in `event_description`;
   brute-force events use SAP-native phrasing ("authentication error",
   "unauthorised access attempt", "cross-tenant data access attempt");
   SQLi-type events surface as "anomalous query pattern" / "uncommon query
   parameter". Both keyword tuples updated in `src/model/schema.py`; model
   retrained as `20260506-230038-b61b7b` (experiment #1).

---

## Dataset versions

> **HANA retention trigger**: implement archival by **2026-06-15** *or*
> when `SECURITY_LOGS` row count exceeds 5,000,000 *or* when HANA reports
> >60% storage used — whichever comes first. Check weekly via
> `python scripts/hana_summary.py`. See `docs/adr/0001-hana-retention.md`
> (to be authored in Phase B).

| Date | Event | Source | Row count | Notes |
|---|---|---|---|---|
| 2026-04-27 | LLM telemetry audit (`data/reports/llm_audit_2026-04-27.md`) | `scripts/audit_llm_telemetry.py` | 638,970 LLM rows of 1,773,138 (36.0%); 320 (MODEL_ID, PROMPT_CATEGORY) cohorts | Per-LLM-row NULL rate of 38.8% on telemetry columns is a real missing-data signal (these rows *are* LLM rows). Use p99.5 of `LLM_PROMPT_TOKENS` as the data-driven 'token bomb' floor; rule catalog in `src/model/llm_rules.py` derives from this audit. |
| 2026-04-22 | First schema-expansion audit (`data/reports/schema_audit_2026-04-22.md`) | `scripts/audit_schema_expansion.py` | 895,904 total; **701,838 pre-expansion (78.3%)** | Rubric: >40% → legacy-only model or backfill. Drop strategy would lose 78.3% of training data (194,066 rows remaining). Impute keeps all rows but biases 7 features. See Open question #1. |
| 2026-04-21 | Schema expansion (commit `5b5d777`) | migration | *see 2026-04-22 audit above* | 16 columns added; rows before this date have NULLs in those columns. |

Paste the headline numbers from each `data/reports/schema_audit_<date>.md`
into this table as they're generated.

---

## Glossary

- **Pre-expansion row** — a row in `SECURITY_LOGS` ingested before commit
  `5b5d777` (2026-04-21); lacks `HTTP_METHOD`, `REGION_CODE`,
  `SAP_APPLICATION`, and 13 other columns.
- **Expansion column** — any of the 16 columns added in `5b5d777`.
- **Design-NULL** — a column intentionally NULL for certain row types
  (e.g., all nine `LLM_*` columns are NULL for non-LLM traffic).
- **MTTD** — mean time to detect. Dual-defined in this project:
  `pipeline_mttd_ms` and `e2e_mttd_ms`. See `docs/ARCHITECTURE.md`.
