#!/usr/bin/env bash
set -euo pipefail

# cve_pipeline.sh — Orchestrates the full CVE refresh pipeline:
#   1. Load credentials from .env
#   2. Download baseline (first run) or latest delta
#   3. Stage JSON files and load into Snowflake CVE_RAW
#   4. Run dbt to transform CVE_RAW → cve_records
#   5. Update state file on success
#
# Usage:
#   cve_pipeline.sh [--state-file PATH] [--log-file PATH]
#
# Environment (optional):
#   DBT_TARGET — dbt target to use (default: prod)
#
# The script is idempotent: running it multiple times with the same release
# tag is a no-op (state file prevents reprocessing).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DBT_DIR="${PROJECT_DIR}/dbt"

# State file defaults to the project directory (not HOME) so it works
# correctly regardless of which service user runs the pipeline.
DEFAULT_STATE_FILE="${PROJECT_DIR}/.pipeline_state"
DEFAULT_LOG_FILE="${PROJECT_DIR}/logs/pipeline.log"

STATE_FILE="$DEFAULT_STATE_FILE"
LOG_FILE="$DEFAULT_LOG_FILE"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-file) STATE_FILE="$2"; shift 2 ;;
    --log-file)   LOG_FILE="$2";   shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "$(dirname "$LOG_FILE")"

log() {
  local level="$1"; shift
  local msg="[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] ${level}  $*"
  echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

# ── Guard: disable xtrace to prevent credential leakage ──────────────────
{ set +x; } 2>/dev/null

# ── Preflight: verify required tools are installed ───────────────────────
for cmd in jq curl unzip snowsql dbt; do
  command -v "$cmd" &>/dev/null || { log "ERROR" "Required command not found: ${cmd}"; exit 1; }
done

# ── Load credentials ──────────────────────────────────────────────────────
ENV_FILE="${PROJECT_DIR}/.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
else
  log "WARN " ".env not found at ${ENV_FILE} — expecting credentials in shell environment"
fi

DBT_TARGET="${DBT_TARGET:-prod}"

# ── Optional: check source freshness (warns if prior load is stale) ───────
log "INFO " "Checking source freshness"
dbt source freshness \
  --project-dir "$DBT_DIR" \
  --profiles-dir "$DBT_DIR" \
  --target "$DBT_TARGET" \
  --no-version-check 2>&1 | tee -a "$LOG_FILE" || true

# ── Step 1: Download ──────────────────────────────────────────────────────
log "INFO " "Pipeline start"
START_TIME=$(date +%s)

download_output=$(bash "${SCRIPT_DIR}/download_cve.sh" \
  --state-file "$STATE_FILE" \
  --tmp-dir "${CVE_TMP_DIR:-/tmp}") || {
  log "ERROR" "Download step failed"
  exit 1
}

# Forward sub-script log lines (prefixed with #) to LOG_FILE, then isolate result
echo "$download_output" | grep '^#' | sed 's/^# //' >> "$LOG_FILE"
result_line=$(echo "$download_output" | grep -v '^#' | grep -v '^$' | tail -1)

if [[ "$result_line" == "SKIP" ]]; then
  log "INFO " "Latest release already processed — nothing to do (SKIP)"
  exit 0
fi

TAG=$(echo "$result_line" | awk '{print $1}')
EXTRACT_DIR=$(echo "$result_line" | awk '{print $2}')

if [[ -z "$TAG" || -z "$EXTRACT_DIR" ]]; then
  log "ERROR" "Download step returned unexpected output: ${result_line}"
  exit 1
fi

log "INFO " "Latest release tag: ${TAG}"

# ── Step 2: Stage and load to Snowflake ───────────────────────────────────
log "INFO " "Staging files to Snowflake"
bash "${SCRIPT_DIR}/stage_to_snowflake.sh" "$TAG" "$EXTRACT_DIR" 2>&1 | tee -a "$LOG_FILE"
stage_exit="${PIPESTATUS[0]}"
if [[ "$stage_exit" -ne 0 ]]; then
  log "ERROR" "Snowflake staging step failed for tag ${TAG}"
  exit 1
fi
log "INFO " "Snowflake load complete"

# ── Step 3: Run dbt ──────────────────────────────────────────────────────
log "INFO " "Running dbt models (target: ${DBT_TARGET})"

dbt run \
  --project-dir "$DBT_DIR" \
  --profiles-dir "$DBT_DIR" \
  --select stg_cve_raw cve_records \
  --target "$DBT_TARGET" \
  --no-version-check 2>&1 | tee -a "$LOG_FILE"

# tee always exits 0 — capture dbt's exit code via PIPESTATUS
dbt_exit="${PIPESTATUS[0]}"
if [[ "$dbt_exit" -ne 0 ]]; then
  log "ERROR" "dbt run failed for tag ${TAG} (exit ${dbt_exit})"
  exit 1
fi
log "INFO " "dbt run complete"

log "INFO " "Running dbt tests"
dbt test \
  --project-dir "$DBT_DIR" \
  --profiles-dir "$DBT_DIR" \
  --select stg_cve_raw cve_records \
  --target "$DBT_TARGET" \
  --no-version-check 2>&1 | tee -a "$LOG_FILE"
dbt_test_exit="${PIPESTATUS[0]}"
if [[ "$dbt_test_exit" -ne 0 ]]; then
  log "ERROR" "dbt test failed for tag ${TAG} (exit ${dbt_test_exit})"
  exit 1
fi
log "INFO " "dbt tests passed"

# ── Update state file ────────────────────────────────────────────────────
echo "$TAG" > "$STATE_FILE"
log "INFO " "State updated to ${TAG}"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
log "INFO " "Pipeline complete (${ELAPSED}s)"
