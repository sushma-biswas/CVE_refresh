#!/usr/bin/env bats
# TDD tests for scripts/stage_to_snowflake.sh
# Run with: bats tests/test_stage_to_snowflake.bats

load setup

SCRIPT="${SCRIPTS_DIR}/stage_to_snowflake.sh"
SAMPLE_TAG="cve_2026-06-27_0700Z"

# Per-file setup: shared_setup initialises temp dir and mock PATH, then we
# layer on per-file requirements.
setup() {
  shared_setup
  setup_test_env

  EXTRACT_DIR="${CVE_TMP_DIR}/extract_${SAMPLE_TAG}"
  mkdir -p "$EXTRACT_DIR"
  cp "${FIXTURES_DIR}/sample_delta/CVE-2024-12345.json" "$EXTRACT_DIR/"
  export EXTRACT_DIR
}

@test "calls snowsql PUT with correct stage path" {
  mock_command_recording "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  assert_called_with "snowsql" "@CVE_STAGE/${SAMPLE_TAG}"
}

@test "calls COPY INTO CVE_RAW with the correct TAG value" {
  mock_command_recording "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  assert_called_with "snowsql" "CVE_RAW"
}

@test "calls REMOVE on stage path after successful load" {
  mock_command_recording "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  assert_called_with "snowsql" "REMOVE"
}

@test "removes local extract dir after successful load" {
  mock_command "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  [[ "$status" -eq 0 ]]
  [[ ! -d "$EXTRACT_DIR" ]]
}

@test "exits non-zero when snowsql PUT fails" {
  # Use a stateful counter in TEST_TMPDIR (not /tmp) so it is always cleaned up
  local call_count_file="${TEST_TMPDIR}/snowsql_call_count"
  echo "0" > "$call_count_file"

  cat > "${MOCK_BIN}/snowsql" <<EOF
#!/usr/bin/env bash
count=\$(cat "${call_count_file}")
count=\$((count + 1))
echo "\$count" > "${call_count_file}"
if [[ \$count -eq 1 ]]; then exit 1; fi
echo "1"
exit 0
EOF
  chmod +x "${MOCK_BIN}/snowsql"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  [[ "$status" -ne 0 ]]
}

@test "exits non-zero when COPY INTO reports 0 rows loaded" {
  # snowsql returns 0 for the row-count query → treated as a load failure
  mock_command "snowsql" 0 "0"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  [[ "$status" -ne 0 ]]
}

@test "sources credentials from environment before calling snowsql" {
  mock_command_recording "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  assert_called_with "snowsql" "test-account"
  assert_called_with "snowsql" "test_user"
}

@test "does not log SNOWFLAKE_PASSWORD in output" {
  mock_command "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  [[ "$output" != *"test_password_do_not_log"* ]]
  [[ "${lines[*]}" != *"test_password_do_not_log"* ]]
}

@test "exits non-zero when EXTRACT_DIR does not exist" {
  setup_test_env
  mock_command "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "/tmp/nonexistent_dir_$$"

  [[ "$status" -ne 0 ]]
  [[ "$output" == *"ERROR"* ]]
}

@test "exits non-zero when required env var is missing" {
  # Unset a required credential
  unset SNOWFLAKE_PASSWORD

  mock_command "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  [[ "$status" -ne 0 ]]
  [[ "$output" == *"ERROR"* ]]
}

@test "includes SNOWFLAKE_ROLE in snowsql args when role is set" {
  export SNOWFLAKE_ROLE="MY_CUSTOM_ROLE"
  mock_command_recording "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  assert_called_with "snowsql" "MY_CUSTOM_ROLE"
}

@test "omits role flag from snowsql args when SNOWFLAKE_ROLE is not set" {
  unset SNOWFLAKE_ROLE
  mock_command_recording "snowsql" 0 "1"

  run bash "$SCRIPT" "$SAMPLE_TAG" "$EXTRACT_DIR"

  [[ "$status" -eq 0 ]]
  call_log="${TEST_TMPDIR}/snowsql.calls"
  if [[ -f "$call_log" ]]; then
    run grep -c " -r " "$call_log"
    [[ "$output" == "0" ]]
  fi
}
