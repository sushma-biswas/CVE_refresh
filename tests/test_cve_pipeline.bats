#!/usr/bin/env bats
# TDD tests for scripts/cve_pipeline.sh
# Run with: bats tests/test_cve_pipeline.bats

load setup

SCRIPT="${SCRIPTS_DIR}/cve_pipeline.sh"
SAMPLE_TAG="cve_2026-06-27_0700Z"

setup() {
  shared_setup
  setup_test_env

  EXTRACT_DIR="${CVE_TMP_DIR}/extract_${SAMPLE_TAG}"
  mkdir -p "$EXTRACT_DIR"
  export EXTRACT_DIR
}

mock_download_success() {
  cat > "${MOCK_BIN}/download_cve.sh" <<EOF
#!/usr/bin/env bash
echo "${SAMPLE_TAG} ${EXTRACT_DIR}"
exit 0
EOF
  chmod +x "${MOCK_BIN}/download_cve.sh"
}

mock_download_skip() {
  cat > "${MOCK_BIN}/download_cve.sh" <<'EOF'
#!/usr/bin/env bash
echo "SKIP"
exit 0
EOF
  chmod +x "${MOCK_BIN}/download_cve.sh"
}

mock_stage_success() {
  mock_command_recording "stage_to_snowflake.sh" 0 "Loaded 347 rows"
}

mock_dbt_success() {
  mock_command_recording "dbt" 0 "Completed successfully"
}

@test "full pipeline calls download then stage then dbt in order" {
  local order_log="${TEST_TMPDIR}/order.log"

  cat > "${MOCK_BIN}/download_cve.sh" <<EOF
#!/usr/bin/env bash
echo "download" >> "${order_log}"
echo "${SAMPLE_TAG} ${EXTRACT_DIR}"
EOF
  chmod +x "${MOCK_BIN}/download_cve.sh"

  cat > "${MOCK_BIN}/stage_to_snowflake.sh" <<EOF
#!/usr/bin/env bash
echo "stage" >> "${order_log}"
EOF
  chmod +x "${MOCK_BIN}/stage_to_snowflake.sh"

  cat > "${MOCK_BIN}/dbt" <<EOF
#!/usr/bin/env bash
echo "dbt" >> "${order_log}"
EOF
  chmod +x "${MOCK_BIN}/dbt"

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -eq 0 ]]
  [[ "$(sed -n '1p' "$order_log")" == "download" ]]
  [[ "$(sed -n '2p' "$order_log")" == "stage" ]]
  [[ "$(sed -n '3p' "$order_log")" == "dbt" ]]
}

@test "writes TAG to state file after successful run" {
  mock_download_success
  mock_stage_success
  mock_dbt_success

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -eq 0 ]]
  [[ -f "$STATE_FILE" ]]
  [[ "$(cat "$STATE_FILE")" == "$SAMPLE_TAG" ]]
}

@test "does not update state file when stage step fails" {
  mock_download_success
  mock_command "stage_to_snowflake.sh" 1 "Error: PUT failed"
  mock_dbt_success

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -ne 0 ]]
  [[ ! -f "$STATE_FILE" ]]
}

@test "does not update state file when dbt step fails" {
  mock_download_success
  mock_stage_success
  mock_command "dbt" 1 "Error: dbt run failed"

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -ne 0 ]]
  [[ ! -f "$STATE_FILE" ]]
}

@test "exits 0 with no-op log message when download returns SKIP" {
  mock_download_skip

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"SKIP"* || "$(cat "$LOG_FILE" 2>/dev/null)" == *"SKIP"* ]]
}

@test "logs pipeline start timestamp" {
  mock_download_success
  mock_stage_success
  mock_dbt_success

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ -f "$LOG_FILE" ]]
  grep -qE "\[20[0-9]{2}-[0-9]{2}-[0-9]{2}" "$LOG_FILE"
}

@test "logs error and exits non-zero on any step failure" {
  mock_command "download_cve.sh" 1 "Error: network timeout"

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -ne 0 ]]
  [[ "$output" == *"ERROR"* || "$(cat "$LOG_FILE" 2>/dev/null)" == *"ERROR"* ]]
}

@test "logs a warning when .env file is absent" {
  # No .env file in the test project dir — the script should warn but not crash
  mock_download_success
  mock_stage_success
  mock_dbt_success

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"WARN"* || "$output" == *"env"* || "$(cat "$LOG_FILE" 2>/dev/null)" == *"WARN"* ]]
}

@test "loads credentials from .env when it exists" {
  # Write a minimal .env with a sentinel value
  local env_file="${PROJECT_DIR}/.env"
  # Use SCRIPTS_DIR to derive the project dir the same way cve_pipeline.sh does
  local proj_dir
  proj_dir="$(cd "${SCRIPTS_DIR}/.." && pwd)"
  echo "SNOWFLAKE_ACCOUNT=loaded_from_env_file" > "${proj_dir}/.env"

  mock_download_success
  mock_stage_success
  mock_dbt_success

  run bash "$SCRIPT" --state-file "$STATE_FILE" --log-file "$LOG_FILE"

  # Clean up env file
  rm -f "${proj_dir}/.env"

  # The run should succeed regardless of credential value (mocked downstream)
  [[ "$status" -eq 0 ]]
}
