-- schema.sql
-- SAP HANA table definitions for the threat detection system.
--
-- Owner: Data Architect & Backend Developer
-- Applied idempotently at startup by src/storage/migrations.py
--
-- NOTE: This file only contains CREATE statements. If columns are added in
-- a future revision and tables already exist in production, run the ALTER
-- statements manually via SAP HANA cockpit — migrations.py is CREATE-only.

-- ─────────────────────────────────────────────────────────
-- Raw security logs ingested from SAP API
-- ─────────────────────────────────────────────────────────
CREATE TABLE SECURITY_LOGS (
    ID                BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    DATETIME          TIMESTAMP     NOT NULL,
    SOURCE_IP         NVARCHAR(50)  NOT NULL,
    PORT_SERVICE      NVARCHAR(50),
    EVENT_DESCRIPTION NVARCHAR(500),
    STATUS            NVARCHAR(50),
    LOG_TYPE          NVARCHAR(50),
    INGESTED_AT       TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IDX_SECURITY_LOGS_DATETIME  ON SECURITY_LOGS (DATETIME);
CREATE INDEX IDX_SECURITY_LOGS_SOURCE_IP ON SECURITY_LOGS (SOURCE_IP);


-- ─────────────────────────────────────────────────────────
-- Detected anomalies — used for SAC dashboards, forensics, MTTD tracking.
-- ─────────────────────────────────────────────────────────
CREATE TABLE ANOMALIES (
    ID                   BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    DETECTED_AT          TIMESTAMP       NOT NULL,
    INGESTED_AT          TIMESTAMP,
    SOURCE_IP            NVARCHAR(50)    NOT NULL,
    THREAT_LEVEL         NVARCHAR(10)    NOT NULL,   -- 'high' | 'medium' | 'low'
    ANOMALY_SCORE        DECIMAL(10, 6),
    TOTAL_REQUESTS       INTEGER,
    ERROR_RATE           DECIMAL(5, 4),
    PIPELINE_MTTD_MS     INTEGER,                    -- detected_at - ingested_at
    E2E_MTTD_MS          INTEGER,                    -- detected_at - log event time
    ALERT_ID             NVARCHAR(100),              -- idempotency key
    DEDUP_KEY            NVARCHAR(100),
    WEBHOOK_SENT         BOOLEAN         DEFAULT FALSE,
    INCIDENT_REPORT_PATH NVARCHAR(500),
    RESOLVED_AT          TIMESTAMP,
    CREATED_AT           TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IDX_ANOMALIES_DETECTED_AT  ON ANOMALIES (DETECTED_AT);
CREATE INDEX IDX_ANOMALIES_THREAT_LEVEL ON ANOMALIES (THREAT_LEVEL);
CREATE UNIQUE INDEX UX_ANOMALIES_ALERT_ID ON ANOMALIES (ALERT_ID);


-- ─────────────────────────────────────────────────────────
-- Model versions — for MLOps tracking and rollback.
-- ─────────────────────────────────────────────────────────
CREATE TABLE MODEL_VERSIONS (
    ID               BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    VERSION_TAG      NVARCHAR(50)    NOT NULL,
    MODEL_TYPE       NVARCHAR(50),                    -- 'isolation_forest' | 'dbscan'
    TRAINED_AT       TIMESTAMP       NOT NULL,
    CONTAMINATION    DECIMAL(5, 4),
    TRAINING_SAMPLES INTEGER,
    FEATURE_COLUMNS  NCLOB,                           -- JSON array
    HYPERPARAMS      NCLOB,                           -- JSON object
    CV_SCORES        NCLOB,                           -- JSON object
    IS_ACTIVE        BOOLEAN         DEFAULT FALSE,
    NOTES            NVARCHAR(500),
    CREATED_AT       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX UX_MODEL_VERSIONS_TAG ON MODEL_VERSIONS (VERSION_TAG);
