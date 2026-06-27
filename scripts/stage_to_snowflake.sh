#!/usr/bin/env bash
set -euo pipefail

# stage_to_snowflake.sh — Stage CVE JSON files and load them into Snowflake.
#
# Usage:
#   stage_to_snowflake.sh <TAG> <EXTRACT_DIR>
#
# Required environment variables:
#   SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PASSWORD,
#   SNOWFLAKE_DATABASE, SNOWFLAKE_SCHEMA, SNOWFLAKE_WAREHOUSE
#   SNOWFLAKE_ROLE  (optional)
#
# Exit codes:
#   0  success
#   1  error (validation failure, PUT error, COPY error, 0 rows loaded)

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <TAG> <EXTRACT_DIR>" >&2
  exit 1
fi

TAG="$1"
EXTRACT_DIR="$2"

# ── Guard: disable xtrace to prevent password leakage ────────────────────
{ set +x; } 2>/dev/null

log() { echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $*"; }

# ── Validate TAG format ────────────────────────────────────────────────────
if [[ ! "$TAG" =~ ^(cve_|baseline_)[0-9]{4}-[0-9]{2}-[0-9]{2}(_[0-9]{4}Z)?$ ]]; then
  log "ERROR: TAG has unexpected format (possible injection): ${TAG}"
  exit 1
fi

# ── Validate EXTRACT_DIR is under a known temp path ───────────────────────
# Resolve to an absolute canonical path and verify it sits under a known temp root.
real_extract_dir="$(realpath "$EXTRACT_DIR" 2>/dev/null || echo "")"
real_tmp_dir="$(realpath "${TMPDIR:-/tmp}" 2>/dev/null || echo "/tmp")"
if [[ -z "$real_extract_dir" || "$real_extract_dir" != "${real_tmp_dir}"/* ]]; then
  log "ERROR: EXTRACT_DIR is outside expected temp location: ${EXTRACT_DIR}"
  exit 1
fi
if [[ ! -d "$EXTRACT_DIR" ]]; then
  log "ERROR: EXTRACT_DIR does not exist: ${EXTRACT_DIR}"
  exit 1
fi

json_count=$(find "$EXTRACT_DIR" -name '*.json' | wc -l | tr -d ' ')
if [[ "$json_count" -eq 0 ]]; then
  log "ERROR: No JSON files found in ${EXTRACT_DIR}"
  exit 1
fi
log "Staging ${json_count} JSON files for tag ${TAG}"

# ── Validate required env vars ────────────────────────────────────────────
for var in SNOWFLAKE_ACCOUNT SNOWFLAKE_USER SNOWFLAKE_PASSWORD \
           SNOWFLAKE_DATABASE SNOWFLAKE_SCHEMA SNOWFLAKE_WAREHOUSE; do
  if [[ -z "${!var:-}" ]]; then
    log "ERROR: Required env var ${var} is not set"
    exit 1
  fi
done

# Build SnowSQL connection args.
# SNOWFLAKE_PASSWORD is passed via SNOWSQL_PWD scoped per-invocation (not exported
# globally) to keep it out of the process environment for unrelated child processes.
SNOWSQL_ARGS=(
  -a "$SNOWFLAKE_ACCOUNT"
  -u "$SNOWFLAKE_USER"
  -d "$SNOWFLAKE_DATABASE"
  -s "$SNOWFLAKE_SCHEMA"
  -w "$SNOWFLAKE_WAREHOUSE"
  --noup
  -o output_format=plain
  -o friendly=false
  -o timing=false
)
if [[ -n "${SNOWFLAKE_ROLE:-}" ]]; then
  SNOWSQL_ARGS+=(-r "$SNOWFLAKE_ROLE")
fi

# Wrapper: runs snowsql with SNOWSQL_PWD scoped only to that command.
run_snowsql() {
  SNOWSQL_PWD="$SNOWFLAKE_PASSWORD" snowsql "${SNOWSQL_ARGS[@]}" "$@"
}

STAGE_PATH="@CVE_STAGE/${TAG}"

# ── PUT files to Snowflake internal stage ─────────────────────────────────
log "PUT ${EXTRACT_DIR}/*.json → ${STAGE_PATH}/"
put_start=$(date +%s)
run_snowsql -q \
  "PUT 'file://${EXTRACT_DIR}/*.json' '${STAGE_PATH}/' AUTO_COMPRESS=TRUE OVERWRITE=TRUE;" || {
  log "ERROR: snowsql PUT failed"
  exit 1
}
put_elapsed=$(( $(date +%s) - put_start ))
log "PUT complete in ${put_elapsed}s"

# ── COPY INTO CVE_RAW ─────────────────────────────────────────────────────
log "COPY INTO CVE_RAW from ${STAGE_PATH}/"
copy_output=$(run_snowsql -q "
  COPY INTO CVE_RAW (RAW_JSON, DELTA_TAG, SOURCE_FILE)
  FROM (
    SELECT
      \$1,
      '${TAG}',
      METADATA\$FILENAME
    FROM ${STAGE_PATH}/
  )
  FILE_FORMAT = (FORMAT_NAME = CVE_JSON_FORMAT)
  ON_ERROR = 'CONTINUE';
") || {
  log "ERROR: COPY INTO CVE_RAW failed"
  exit 1
}

# Count files that failed to parse (LOAD_FAILED lines in COPY output)
error_count=$(echo "$copy_output" | grep -c "LOAD_FAILED" || true)
if [[ "$error_count" -gt 0 ]]; then
  log "WARN  COPY INTO: ${error_count} file(s) failed to parse and were skipped (ON_ERROR=CONTINUE)"
fi

# ── Verify rows actually landed (tag-based count — reliable across all SnowSQL versions)
rows_loaded=$(run_snowsql -q \
  "SELECT COUNT(*) FROM CVE_RAW WHERE DELTA_TAG = '${TAG}';" \
  | grep -Eo '[0-9]+' | head -1 || echo "0")

if [[ -z "$rows_loaded" || "$rows_loaded" -eq 0 ]]; then
  log "ERROR: COPY INTO loaded 0 rows for tag ${TAG} — check JSON format or stage path"
  exit 1
fi
log "Loaded ${rows_loaded} rows into CVE_RAW (tag: ${TAG})"

# ── Remove files from internal stage ─────────────────────────────────────
log "Removing staged files from ${STAGE_PATH}/"
run_snowsql -q "REMOVE '${STAGE_PATH}/';" || {
  log "WARN  Failed to clean up stage ${STAGE_PATH}/ — manual cleanup may be needed"
}

# ── Remove local extract directory (with path safety check) ──────────────
real_extract_dir="$(realpath "$EXTRACT_DIR" 2>/dev/null || echo "")"
real_tmp_dir="$(realpath "${TMPDIR:-/tmp}" 2>/dev/null || echo "/tmp")"
if [[ -n "$real_extract_dir" && "$real_extract_dir" == "${real_tmp_dir}"/* ]]; then
  rm -rf "$EXTRACT_DIR"
  log "Removed local extract dir ${EXTRACT_DIR}"
else
  log "WARN  Skipped deletion of EXTRACT_DIR (path outside temp location): ${EXTRACT_DIR}"
fi

log "Stage load complete for ${TAG}"
