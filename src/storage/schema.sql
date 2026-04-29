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
    LOG_ID            NVARCHAR(64),                -- API _id; UNIQUE for dedup (see UX_SECURITY_LOGS_LOG_ID)
    DATETIME          TIMESTAMP     NOT NULL,
    SOURCE_IP         NVARCHAR(50)  NOT NULL,
    PORT_SERVICE      NVARCHAR(50),
    EVENT_DESCRIPTION NVARCHAR(500),
    STATUS            NVARCHAR(50),
    LOG_TYPE          NVARCHAR(50),
    REQUEST_PATH      NVARCHAR(500),              -- heathers_request_path (typo in API preserved)
    SAP_APPLICATION   NVARCHAR(100),              -- sap_function_application
    REGION_CODE       NVARCHAR(20),               -- e.g. "NL-AMS2", "US-TX"
    MACRO_REGION      NVARCHAR(50),               -- e.g. "Europe", "North America"
    HTTP_METHOD       NVARCHAR(10),               -- GET | POST | DELETE | PUT | PATCH
    SAP_SOURCE_TYPE   NVARCHAR(50),               -- BTP-Event | BAPI | RFC | OData | REST | SOAP
    SAP_APP_ENV       NVARCHAR(50),               -- sandbox | development | staging | production | qa
    LLM_TOTAL_TOKENS  INTEGER,                    -- null for non-LLM rows
    LLM_COST_USD      DOUBLE,                     -- null for non-LLM rows
    LLM_FINISH_REASON NVARCHAR(50),               -- stop | length | content_filter
    LLM_STATUS        NVARCHAR(50),               -- success | error
    LLM_RESPONSE_TIME_MS DOUBLE,                  -- ms per LLM call
    LLM_PROMPT_CATEGORY  NVARCHAR(100),           -- Finance | HR | Support | etc.
    LLM_ERROR_MESSAGE    NVARCHAR(500),           -- populated when llm_status = error
    LLM_MODEL_ID         NVARCHAR(100),           -- gpt-4 | claude-3-opus | etc.
    LLM_PROMPT_TOKENS    INTEGER,                 -- input tokens (caps ~2k in observed traffic)
    INGESTED_AT       TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IDX_SECURITY_LOGS_DATETIME  ON SECURITY_LOGS (DATETIME);
CREATE INDEX IDX_SECURITY_LOGS_SOURCE_IP ON SECURITY_LOGS (SOURCE_IP);
CREATE UNIQUE INDEX UX_SECURITY_LOGS_LOG_ID ON SECURITY_LOGS (LOG_ID);


-- ─────────────────────────────────────────────────────────
-- Detected anomalies — used for SAC dashboards, forensics, MTTD tracking.
-- ─────────────────────────────────────────────────────────
CREATE TABLE ANOMALIES (
    ID                   BIGINT          GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    DETECTED_AT          TIMESTAMP       NOT NULL,
    INGESTED_AT          TIMESTAMP,
    -- Discriminator: 'sap' (existing source-IP-keyed detector) | 'llm' (cohort-keyed detector).
    DETECTOR             NVARCHAR(20)    DEFAULT 'sap',
    -- Nullable: LLM anomalies are keyed on (LLM_MODEL_ID, LLM_PROMPT_CATEGORY) instead.
    SOURCE_IP            NVARCHAR(50),
    LLM_MODEL_ID         NVARCHAR(100),
    LLM_PROMPT_CATEGORY  NVARCHAR(100),
    THREAT_LEVEL         NVARCHAR(10)    NOT NULL,   -- 'high' | 'medium' | 'low'
    ANOMALY_SCORE        DECIMAL(10, 6),
    -- Per-detector breakdown for the LLM ensemble (nullable for SAP rows).
    IF_GLOBAL_SCORE      DECIMAL(10, 6),
    IF_CATEGORY_SCORE    DECIMAL(10, 6),
    -- JSON array of rule_ids that fired (e.g. ["LLM_TOKEN_HIGH","LLM_NEAR_TIMEOUT"]).
    RULE_IDS             NCLOB,
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
CREATE INDEX IDX_ANOMALIES_DETECTOR     ON ANOMALIES (DETECTOR);
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
