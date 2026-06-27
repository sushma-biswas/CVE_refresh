-- setup_snowflake.sql — One-time Snowflake infrastructure setup.
--
-- Run this in your Snowflake worksheet as ACCOUNTADMIN or SYSADMIN before
-- executing the pipeline for the first time.
--
-- Designed for the Snowflake free trial tier:
--   - XSMALL warehouse with 60-second auto-suspend to minimise credit usage
--   - Auto-resume so the warehouse wakes on demand

-- ── Warehouse ─────────────────────────────────────────────────────────────
CREATE WAREHOUSE IF NOT EXISTS CVE_WH
    WAREHOUSE_SIZE    = XSMALL
    AUTO_SUSPEND      = 60          -- suspend after 60 seconds idle
    AUTO_RESUME       = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT           = 'Warehouse for CVE refresh pipeline';

-- ── Database and schema ───────────────────────────────────────────────────
CREATE DATABASE IF NOT EXISTS CVE_DB
    COMMENT = 'CVE data warehouse';

CREATE SCHEMA IF NOT EXISTS CVE_DB.CVE_SCHEMA
    COMMENT = 'Schema for raw and transformed CVE data';

USE DATABASE CVE_DB;
USE SCHEMA   CVE_SCHEMA;
USE WAREHOUSE CVE_WH;

-- ── Raw landing table ────────────────────────────────────────────────────
-- Append-only. Each COPY INTO run adds rows; stg_cve_raw deduplicates.
CREATE TABLE IF NOT EXISTS CVE_RAW (
    RAW_JSON     VARIANT       NOT NULL,
    LOADED_AT    TIMESTAMP_TZ  DEFAULT CURRENT_TIMESTAMP(),
    DELTA_TAG    VARCHAR(60)   NOT NULL,
    SOURCE_FILE  VARCHAR(500)
)
COMMENT = 'Raw landing table for CVE JSON 5 records loaded by the pipeline';

-- ── File format for JSON loading ─────────────────────────────────────────
CREATE FILE FORMAT IF NOT EXISTS CVE_JSON_FORMAT
    TYPE              = 'JSON'
    STRIP_OUTER_ARRAY = FALSE
    COMMENT           = 'JSON format for individual CVE JSON 5 files';

-- ── Internal stage ───────────────────────────────────────────────────────
CREATE STAGE IF NOT EXISTS CVE_STAGE
    FILE_FORMAT = CVE_JSON_FORMAT
    COMMENT     = 'Temporary staging area for CVE JSON files before COPY INTO';

-- ── Service role and permissions ─────────────────────────────────────────
-- Create a least-privilege role for the pipeline and dbt to use.
-- Grant this role to your pipeline service user.
CREATE ROLE IF NOT EXISTS DBT_ROLE;

GRANT USAGE  ON WAREHOUSE CVE_WH                        TO ROLE DBT_ROLE;
GRANT USAGE  ON DATABASE  CVE_DB                        TO ROLE DBT_ROLE;
GRANT USAGE  ON SCHEMA    CVE_DB.CVE_SCHEMA             TO ROLE DBT_ROLE;
GRANT SELECT, INSERT ON TABLE CVE_DB.CVE_SCHEMA.CVE_RAW TO ROLE DBT_ROLE;
GRANT ALL    ON STAGE CVE_DB.CVE_SCHEMA.CVE_STAGE       TO ROLE DBT_ROLE;
GRANT CREATE TABLE ON SCHEMA CVE_DB.CVE_SCHEMA          TO ROLE DBT_ROLE;
GRANT CREATE VIEW  ON SCHEMA CVE_DB.CVE_SCHEMA          TO ROLE DBT_ROLE;

-- Grant DBT_ROLE to your pipeline user (replace YOUR_USER):
-- GRANT ROLE DBT_ROLE TO USER YOUR_USER;

-- ── Verify setup (run interactively in a Snowflake worksheet to confirm) ──
-- SHOW WAREHOUSES   LIKE 'CVE_WH';
-- SHOW TABLES       LIKE 'CVE_RAW';
-- SHOW STAGES       LIKE 'CVE_STAGE';
-- SHOW FILE FORMATS LIKE 'CVE_JSON_FORMAT';
