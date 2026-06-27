#!/usr/bin/env bats
# TDD tests for scripts/download_cve.sh
# Run with: bats tests/test_download_cve.bats

load setup

SCRIPT="${SCRIPTS_DIR}/download_cve.sh"

@test "first run downloads baseline when state file is absent" {
  [[ ! -f "$STATE_FILE" ]]

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  mock_command "unzip" 0 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"baseline_"* ]]
}

@test "incremental run downloads delta when state file exists with prior tag" {
  echo "cve_2026-06-26_2300Z" > "$STATE_FILE"

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  mock_command "unzip" 0 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"cve_2026-06-27_0700Z"* ]]
  [[ "$output" != *"baseline_"* ]]
}

@test "skips download when latest GitHub tag equals last processed tag" {
  echo "cve_2026-06-27_0700Z" > "$STATE_FILE"

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"SKIP"* ]]
}

@test "exits non-zero when GitHub API call fails (non-zero curl exit)" {
  echo "cve_old_tag" > "$STATE_FILE"

  # Simulate a network/HTTP failure: curl exits non-zero on all 3 attempts
  mock_command "curl" 1 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -ne 0 ]]
}

@test "exits non-zero when GitHub API returns a response with no tag_name" {
  echo "cve_old_tag" > "$STATE_FILE"

  # Valid JSON but no tag_name field (e.g. rate-limit response body)
  mock_command "curl" 0 '{"message":"API rate limit exceeded"}'

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -ne 0 ]]
}

@test "exits non-zero when download URL is missing from release assets" {
  echo "cve_old_tag" > "$STATE_FILE"

  mock_command "curl" 0 '{"tag_name":"cve_2026-06-27_0700Z","assets":[]}'

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -ne 0 ]]
}

@test "extracts ZIP to EXTRACT_DIR and prints TAG and EXTRACT_DIR to stdout" {
  echo "cve_old_tag" > "$STATE_FILE"

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  mock_command "unzip" 0 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -eq 0 ]]
  tag=$(echo "$output" | grep -v "^#" | grep -v "^$" | tail -1 | awk '{print $1}')
  extract_dir=$(echo "$output" | grep -v "^#" | grep -v "^$" | tail -1 | awk '{print $2}')
  [[ -n "$tag" ]]
  [[ -n "$extract_dir" ]]
}

@test "deletes the ZIP file after successful extraction" {
  echo "cve_old_tag" > "$STATE_FILE"

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  mock_command "unzip" 0 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -eq 0 ]]
  zip_count=$(find "$CVE_TMP_DIR" -name "*.zip" 2>/dev/null | wc -l)
  [[ "$zip_count" -eq 0 ]]
}

@test "sets Authorization header when GITHUB_TOKEN is set" {
  echo "cve_old_tag" > "$STATE_FILE"
  export GITHUB_TOKEN="ghp_testtoken123"

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  mock_command "unzip" 0 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  assert_called_with "curl" "Authorization"
}

@test "omits Authorization header when GITHUB_TOKEN is empty" {
  echo "cve_old_tag" > "$STATE_FILE"
  export GITHUB_TOKEN=""

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  mock_command "unzip" 0 ""

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  call_log="${TEST_TMPDIR}/curl.calls"
  if [[ -f "$call_log" ]]; then
    run grep -c "Authorization" "$call_log"
    [[ "$output" == "0" ]]
  fi
}

@test "exits non-zero when unzip fails (corrupted ZIP)" {
  echo "cve_old_tag" > "$STATE_FILE"

  mock_command_recording "curl" 0 "$(cat "${FIXTURES_DIR}/github_latest_release.json")"
  # unzip exits non-zero — simulates a corrupted or truncated archive
  mock_command "unzip" 1 "error: bad local file header signature"

  run bash "$SCRIPT" --state-file "$STATE_FILE" --tmp-dir "$CVE_TMP_DIR"

  [[ "$status" -ne 0 ]]
  # Result line must NOT have been emitted
  [[ "$output" != *"cve_2026-06-27_0700Z"* || "$output" == *"ERROR"* ]]
}
