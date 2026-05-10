# ADR-0001: HANA retention and cold archival of SECURITY_LOGS

- **Status**: Proposed
- **Date**: 2026-04-22
- **Deciders**: Data Architect, Cloud Engineer, PM
- **Related**: `docs/MODEL_JOURNAL.md` → Dataset Versions; `scripts/audit_schema_expansion.py`; the 2026-04-21 planning thread

> **Hard trigger — do not miss**: implementation must land by **2026-06-15**
> *or* when `SECURITY_LOGS` row count exceeds **5,000,000** *or* when HANA
> reports **>60% storage used** — whichever comes first. Check weekly via
> `python scripts/hana_summary.py`. If this ADR is still in *Proposed*
> status on 2026-06-01, escalate.

## Context

`SECURITY_LOGS` grows unboundedly. No retention, pruning, or archival
logic exists anywhere in `src/` (verified 2026-04-21). At current
ingestion — polling every 30s over a 30-minute rolling window, roughly
300k logs/day at ~700 bytes each — the table adds ~210 MB/day to HANA.
A 30 GB free-tier HANA instance fills in **~143 days** at the middle
estimate and **~90 days** at the high end.

At the same time, the team needs historical data available for:

1. Retrospective threat analysis after an incident
2. Longitudinal model evaluation (drift detection, retraining against
   a larger window than 30 days)
3. Competition metrics: judges may request historical breakdowns

Pure deletion satisfies (0) storage survival but loses (1)(2)(3). Pure
retention (do nothing) loses (0). We need both.

A secondary constraint: the team works on a free SAP BTP tier today.
Paid object-store services may not be provisioned yet. The archival
strategy must work in two modes — prod (SAP BTP Object Store) and dev
(local filesystem under `data/archive/`) — selected via env, mirroring
the project's existing mock-mode-is-derived convention.

## Decision

We keep the last **30 days** of `SECURITY_LOGS` hot in HANA, and archive
older rows as **Parquet files partitioned by ingest date**
(`data/archive/YYYY/MM/DD/security_logs.parquet` in dev;
`s3://<btp-object-store-bucket>/security_logs/YYYY/MM/DD/` in prod).

Archival runs as a **weekly scheduled job** (GitHub Actions cron,
modeled on `.github/workflows/hana-watchdog.yml`) that:

1. Locks the archive date range (everything `INGESTED_AT < now - 30d`).
2. Exports the rows to Parquet, grouped by ingest date.
3. Writes each Parquet to the archive target.
4. Verifies the write by re-reading row count.
5. Deletes the archived rows from HANA in batches of 10,000 with an
   explicit `COMMIT` after each batch so a mid-job failure leaves HANA
   in a recoverable state.
6. Records the archive manifest in a new `ARCHIVE_LOG` HANA table so we
   always know what is archived and where.

`ANOMALIES` and `MODEL_VERSIONS` are **out of scope** for this ADR.
`ANOMALIES` grows at roughly 50–100 rows/day — no retention pressure
this decade. `MODEL_VERSIONS` grows at ~1 row per retrain cycle
(4-hour cadence) and is tiny.

## Consequences

- **Positive**
  - HANA storage growth is bounded; instance never fills unattended.
  - Historical data remains queryable (via Parquet in archive) — just
    slower. Sufficient for retrospectives and longitudinal evaluation.
  - The archive is *immutable* (append-only), so re-ingest after a bad
    schema migration is always possible.
  - Weekly schedule amortizes HANA load; we are not running a delete
    job during incident response.
  - Decouples hot-path cost from history length — letting us tune the
    30-day window independently of storage constraints.

- **Negative**
  - Dashboard queries that expect full history need to fall back to
    Parquet; this adds complexity to the dashboard's data access layer
    (likely via DuckDB reading Parquet directly, not a new service).
  - Training runs that want > 30 days of data must hydrate from the
    archive — a slower path. The first pass of the next model
    experiment should cap at the 30-day hot window to avoid this until
    it's proven necessary.
  - Two archive targets (dev local vs prod object store) means two
    code paths. Mitigated by a single `ArchiveWriter` abstraction
    (one method: `write(partition_date, df)`), not a full adapter
    pattern.
  - One-way: once archived and deleted, the row is no longer in HANA.
    If a bug corrupts the Parquet write, it will be caught by the
    post-write row-count verification (step 4 above) before the delete
    fires — but the team still needs to treat step 4's assertion as
    load-bearing.

- **Neutral**
  - Parquet + DuckDB is new tooling for this project. Small learning
    cost, well-understood pattern industry-wide.
  - `ARCHIVE_LOG` adds one more HANA table to schema.sql; trivial.

## Alternatives considered

### Retention only (drop rows older than 30 days)

Simplest possible option. Rejected because it loses (1)(2)(3) above —
no incident forensics, no longitudinal eval, no historical breakdowns
for the competition. The cost of storage is small; the cost of
discarded data is large.

### Partition by date + drop old partitions

Most efficient at HANA scale. SAP HANA Cloud does support range
partitioning. Rejected because: (a) adds schema-migration complexity
the team hasn't needed before, (b) still requires a destination for
the dropped partitions unless we accept the data loss of the previous
alternative, (c) doesn't materially outperform "archive + batched
delete" until row counts are well above the free-tier cap.

### External data warehouse (BigQuery / Snowflake) instead of Parquet

Overkill for hackathon scale and not budgeted. Could be revisited
post-competition if we commercialize and the archive grows past
~100 GB.

### Archive to `data/archive/` only (no object store)

Considered — the user asked for "local computer" archival. Works for
dev, but the Cloud Foundry deployment has **ephemeral disk**, so an
archive written locally on the CF instance would be lost on restart.
Prod must use object storage. Dev keeps `data/archive/` for
convenience; prod uses BTP Object Store.

## Implementation sketch (non-binding; actual plan comes later)

- `src/storage/archive.py` — new module. `ArchiveWriter` base class;
  `LocalArchiveWriter` (writes to `settings.archive_dir`) and
  `ObjectStoreArchiveWriter` (writes to BTP Object Store via the
  SDK, once the bucket binding exists). Selection is derived the same
  way mock-mode is — presence/absence of an env-configured bucket name.
- `scripts/archive_old_logs.py` — orchestrator. Invokes archiver for
  each date-partition older than 30 days, verifies, deletes in batches.
  Dry-run flag (`--dry-run`) prints what *would* happen without
  touching HANA.
- `src/storage/schema.sql` — add `ARCHIVE_LOG` table (partition date,
  row count, archive URI, archived_at, verified, sha256_of_parquet).
- `.github/workflows/archive-old-logs.yml` — weekly cron. Checks
  health, calls `python -m scripts.archive_old_logs`, notifies on
  failure.
- `src/common/config.py` — add `archive_dir`, `archive_bucket`,
  `archive_retention_days` (default 30), following the existing
  settings pattern.
- Dashboard fallback to Parquet: defer until a dashboard query needs
  it; YAGNI for the first implementation.

**Pre-implementation checkpoint — DO NOT IMPLEMENT BEFORE:**

1. `scripts/audit_schema_expansion.py` has been run and its output
   logged in `MODEL_JOURNAL.md` → Dataset Versions. The schema-audit
   decision (drop/impute/legacy) must be resolved first, because it
   changes what "pre-expansion row" means and whether those rows
   should be archived verbatim or re-parsed.
2. The first post-audit model baseline is captured in
   `MODEL_JOURNAL.md` → Experiments so we can compare model metrics
   before/after the archive window starts clipping the hot set.

## Future work

- **Experiment tracker migration** — as noted in the ADR template, once
  model iteration intensifies (Phase E), migrate hyperparameter +
  artifact tracking from `MODEL_JOURNAL.md` to MLflow / W&B / SAP AI
  Launchpad. This ADR will need a companion ADR when that happens,
  because retention policy for experiment-tracker artifacts is a
  separate decision.
- **Dashboard cold-read path** — once (a) a dashboard query actually
  needs >30-day history, add a DuckDB-over-Parquet reader. Not before.
- **Retention window tuning** — 30 days is a hypothesis, not a
  measurement. Revisit after the first quarter of data, armed with
  cost numbers and SOC usage patterns.
- **Compliance / retention minimums** — if this is ever sold to a
  regulated SAP customer, their data-retention requirements supersede
  the 30-day window. Flag to legal before any commercial rollout.

## References

- `docs/MODEL_JOURNAL.md` → schema evolution and the NULL-handling
  caveat that affects pre-expansion rows in the archive.
- `scripts/hana_summary.py` — row-count and HANA-size probe, source
  of the weekly CI check.
- `scripts/migrate_add_columns.py` — idempotent-ALTER pattern to reuse
  when `ARCHIVE_LOG` is added to the schema.
- `.github/workflows/hana-watchdog.yml` — cron-job scaffolding to clone.
