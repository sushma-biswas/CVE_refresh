# CVE Refresh Pipeline

An automated pipeline that loads CVE (Common Vulnerabilities and Exposures) data from the [CVEProject GitHub releases](https://github.com/CVEProject/cvelistV5) into Snowflake and transforms it with dbt.

## Why this project exists

CVE data is the backbone of cyber risk modelling - it's what drives vulnerability scoring, security ratings, and figuring out how much exposure an insurer actually has. I built this pipeline to reflect the kind of data infrastructure I worked on at Chubb: pulling in data incrementally from an external provider, landing it raw, transforming it into something clean and usable with dbt, and keeping the whole thing running on a schedule with proper observability. I picked this domain on purpose — it ties directly to the work I do as a Cyber insurance data SME.

## How it works

1. **Baseline (first run only)** — downloads the complete CVE dataset (`all_CVEs_at_midnight.zip`), which contains every CVE record ever published.
2. **Hourly deltas (all subsequent runs)** — downloads the latest delta ZIP, which contains only records changed since the previous delta.
3. Raw JSON is loaded into a Snowflake landing table (`CVE_RAW`) via SnowSQL `PUT` + `COPY INTO`.
4. dbt transforms the raw data into a clean, deduplicated `cve_records` table using an incremental MERGE strategy.

The pipeline runs via cron at `:30` past every hour. It is idempotent — running it twice with the same release tag is a safe no-op.

## Data source

CVE data is published in **CVE JSON 5 format** by the [CVEProject](https://github.com/CVEProject/cvelistV5). Legacy formats (CSV, XML, HTML) were retired on 30 June 2024. Records are updated approximately every 7 minutes via the CVE Services API, with GitHub releases published roughly once per hour.

## Project structure

```
CVE_refresh/
├── scripts/
│   ├── cve_pipeline.sh         # Main orchestrator — run this manually or via cron
│   ├── download_cve.sh         # Downloads baseline or delta ZIP from GitHub
│   ├── stage_to_snowflake.sh   # Stages JSON to Snowflake and runs COPY INTO
│   └── setup_cron.sh           # Registers the hourly cron job
├── sql/
│   └── setup_snowflake.sql     # One-time Snowflake infrastructure setup
├── dbt/
│   ├── models/staging/         # stg_cve_raw — parse and deduplicate raw JSON
│   └── models/marts/           # cve_records — final incremental table
├── tests/                      # Bash tests (bats-core)
├── config/
│   └── .env.example            # Credential template
└── logs/                       # Pipeline log output (gitignored)
```

## Prerequisites

On your Linux server:

| Tool | Version | Install |
|---|---|---|
| `bash` | 4.0+ | pre-installed |
| `curl` | any | `apt install curl` |
| `jq` | 1.6+ | `apt install jq` |
| `unzip` | any | `apt install unzip` |
| [SnowSQL](https://docs.snowflake.com/en/user-guide/snowsql-install-config) | 1.2+ | Snowflake installer |
| [dbt-snowflake](https://docs.getdbt.com/docs/core/connect-data-platform/snowflake-setup) | 1.7+ | `pip install dbt-snowflake` |
| [bats-core](https://github.com/bats-core/bats-core) (optional, for tests) | 1.10+ | see note below |

> **bats-core install note:** `apt install bats` on Ubuntu 20.04/22.04 installs an older version (1.1–1.2). Install from source for 1.10+:
> ```bash
> git clone https://github.com/bats-core/bats-core.git
> cd bats-core && sudo ./install.sh /usr/local
> ```

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/CVE_refresh.git
cd CVE_refresh
```

### 2. Set up Snowflake infrastructure

In your Snowflake worksheet, run `sql/setup_snowflake.sql`. This creates:
- Warehouse: `CVE_WH` (XSMALL, auto-suspends after 60 seconds)
- Database: `CVE_DB`
- Schema: `CVE_SCHEMA`
- Table: `CVE_RAW` (raw landing table)
- Stage: `CVE_STAGE`
- Role: `DBT_ROLE`

Grant `DBT_ROLE` to your service user:
```sql
GRANT ROLE DBT_ROLE TO USER YOUR_USER;
```

### 3. Configure credentials

```bash
cp config/.env.example .env
chmod 600 .env
# Edit .env and fill in your Snowflake credentials
```

### 4. Configure dbt

```bash
cp dbt/profiles.yml.example dbt/profiles.yml
# (dbt/profiles.yml.example is committed to the repo as a template; dbt/profiles.yml is gitignored)
# profiles.yml reads credentials from env vars.
# cve_pipeline.sh loads .env automatically before calling dbt.
# If you run dbt directly from the command line, load .env first:
#   source .env && dbt run --project-dir dbt --profiles-dir dbt
```

Install dbt packages:
```bash
cd dbt && dbt deps && cd ..
```

## Running manually

```bash
# First run (downloads baseline — may take 30-60 minutes for 200k+ files)
./scripts/cve_pipeline.sh
```

> **Disk space:** the baseline ZIP expands to 10+ GB. Ensure `/tmp` has at least 15 GB free,
> or set `CVE_TMP_DIR` to a directory on a larger mount:
> ```bash
> export CVE_TMP_DIR=/data/tmp
> ./scripts/cve_pipeline.sh
> ```

```bash
# Check results
# (run in Snowflake worksheet)
# SELECT COUNT(*), MAX(DATE_UPDATED) FROM CVE_DB.CVE_SCHEMA.CVE_RECORDS;
```

## Scheduling

Register the hourly cron job:

```bash
./scripts/setup_cron.sh
```

This schedules `cve_pipeline.sh` to run at 30 minutes past every hour (00:30, 01:30, 02:30, …) and appends output to `logs/pipeline.log`.

Verify:
```bash
crontab -l
```

## Table schema

### `CVE_RAW` (raw landing table — append-only)

| Column | Type | Description |
|---|---|---|
| `RAW_JSON` | VARIANT | Full CVE JSON 5 record |
| `LOADED_AT` | TIMESTAMP_TZ | When this row was inserted |
| `DELTA_TAG` | VARCHAR(60) | GitHub release tag (e.g. `cve_2026-06-27_0700Z`) |
| `SOURCE_FILE` | VARCHAR(500) | Original filename from the ZIP |

### `CVE_RECORDS` (final table — one row per CVE)

| Column | Type | Description |
|---|---|---|
| `CVE_ID` | VARCHAR(20) | Primary key (e.g. `CVE-2024-12345`) |
| `STATE` | VARCHAR(20) | `PUBLISHED`, `REJECTED`, `RESERVED`, `MODIFIED` |
| `DATE_PUBLISHED` | TIMESTAMP_TZ | Date first published |
| `DATE_UPDATED` | TIMESTAMP_TZ | Date of most recent update |
| `DATE_RESERVED` | TIMESTAMP_TZ | Date the CVE ID was reserved by a CVE Numbering Authority (CNA) |
| `ASSIGNER_ORG_ID` | VARCHAR(100) | UUID of the CVE Numbering Authority (CNA) that assigned this CVE |
| `RAW_JSON` | VARIANT | Full CVE JSON 5 record for flexible querying |
| `LOADED_AT` | TIMESTAMP_TZ | When this version was loaded |
| `DELTA_TAG` | VARCHAR(60) | Source release tag |

**Example queries:**

```sql
-- Count by state
SELECT state, COUNT(*) FROM CVE_DB.CVE_SCHEMA.CVE_RECORDS GROUP BY 1 ORDER BY 2 DESC;

-- Recent additions
SELECT cve_id, state, date_updated FROM CVE_DB.CVE_SCHEMA.CVE_RECORDS
ORDER BY date_updated DESC LIMIT 20;

-- Query nested JSON — titles
SELECT cve_id, RAW_JSON:containers:cna:title::VARCHAR AS title
FROM CVE_DB.CVE_SCHEMA.CVE_RECORDS
WHERE state = 'PUBLISHED' LIMIT 10;
```

## Running tests

```bash
# Bash unit tests (requires bats-core)
bats tests/

# dbt data quality tests (requires Snowflake connection)
cd dbt && dbt test
```

## Security

- Credentials are stored in `.env` (server-only, `chmod 600`). This file is gitignored and never committed.
- `dbt/profiles.yml` is also gitignored — only `profiles.yml.example` is committed.
- Pipeline logs contain timestamps, record counts, and release tags only. Passwords are never echoed or logged.
- Bash trace mode is disabled at script start (`{ set +x; } 2>/dev/null`) to prevent credentials from being echoed to logs or a terminal session, even if the calling shell has `set -x` active.
- The optional `GITHUB_TOKEN` uses only public-repo read scope. Without it, unauthenticated GitHub API requests are limited to 60/hour (sufficient for one request per hourly run).

## Logs

Live log:
```bash
tail -f logs/pipeline.log
```

Sample output:
```
[2026-06-27 07:30:01 UTC] INFO  Pipeline start
[2026-06-27 07:30:02 UTC] INFO  Latest release tag: cve_2026-06-27_0700Z
[2026-06-27 07:30:15 UTC] INFO  Staged 347 JSON files for tag cve_2026-06-27_0700Z
[2026-06-27 07:30:45 UTC] INFO  Loaded 347 rows into CVE_RAW
[2026-06-27 07:31:10 UTC] INFO  dbt run complete
[2026-06-27 07:31:10 UTC] INFO  State updated to cve_2026-06-27_0700Z
[2026-06-27 07:31:10 UTC] INFO  Pipeline complete (69s)
```
