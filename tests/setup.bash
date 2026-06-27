#!/usr/bin/env bash
# Shared bats helpers — sourced by each test file via `load setup`.
#
# Usage in test files:
#   load setup
#
#   setup() {
#     shared_setup          # initialise temp dir, mock PATH, etc.
#     setup_test_env        # set fake Snowflake credentials
#     # … any per-file additions …
#   }
#
# bats calls setup() before each test and teardown() after.

FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../scripts" && pwd)"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shared_setup — call this at the top of every per-file setup() function.
shared_setup() {
  TEST_TMPDIR="$(mktemp -d)"
  export TEST_TMPDIR
  export STATE_FILE="${TEST_TMPDIR}/.cve_pipeline_state"
  export LOG_FILE="${TEST_TMPDIR}/pipeline.log"

  MOCK_BIN="${TEST_TMPDIR}/bin"
  mkdir -p "$MOCK_BIN"
  export PATH="${MOCK_BIN}:${PATH}"

  export CVE_TMP_DIR="${TEST_TMPDIR}/cve_work"
  mkdir -p "$CVE_TMP_DIR"
}

# For test files that define no custom setup(), bats uses this default.
# Test files that need per-file setup must define their own setup() that
# calls shared_setup first.
setup() {
  shared_setup
}

teardown() {
  [[ -n "${TEST_TMPDIR:-}" ]] && rm -rf "$TEST_TMPDIR"
}

# mock_command <name> [exit_code] [stdout_output]
# Creates a mock binary that exits with the given code and prints output.
mock_command() {
  local name="$1"
  local exit_code="${2:-0}"
  local output="${3:-}"
  printf '#!/usr/bin/env bash\nprintf "%%s\n" "%s"\nexit %s\n' \
    "$output" "$exit_code" > "${MOCK_BIN}/${name}"
  chmod +x "${MOCK_BIN}/${name}"
}

# mock_command_recording <name> [exit_code] [stdout_output]
# Like mock_command, but also appends all arguments to $TEST_TMPDIR/<name>.calls.
mock_command_recording() {
  local name="$1"
  local exit_code="${2:-0}"
  local output="${3:-}"
  local call_log="${TEST_TMPDIR}/${name}.calls"
  cat > "${MOCK_BIN}/${name}" <<EOF
#!/usr/bin/env bash
echo "\$@" >> "${call_log}"
printf '%s\n' "${output}"
exit ${exit_code}
EOF
  chmod +x "${MOCK_BIN}/${name}"
}

# assert_called_with <name> <expected_substring>
# Fails if the named mock's call log does not contain the expected string.
assert_called_with() {
  local name="$1"
  local expected="$2"
  local call_log="${TEST_TMPDIR}/${name}.calls"
  if [[ ! -f "$call_log" ]]; then
    echo "FAIL: ${name} was never called" >&2
    return 1
  fi
  if ! grep -qF "$expected" "$call_log"; then
    echo "FAIL: expected '${expected}' in ${name} call log" >&2
    echo "Actual calls:" >&2
    cat "$call_log" >&2
    return 1
  fi
}

# setup_test_env — export fake Snowflake credentials for tests.
# Call this in per-file setup() after shared_setup.
setup_test_env() {
  export SNOWFLAKE_ACCOUNT="test-account"
  export SNOWFLAKE_USER="test_user"
  export SNOWFLAKE_PASSWORD="test_password_do_not_log"
  export SNOWFLAKE_DATABASE="CVE_DB"
  export SNOWFLAKE_SCHEMA="CVE_SCHEMA"
  export SNOWFLAKE_WAREHOUSE="CVE_WH"
  export SNOWFLAKE_ROLE="DBT_ROLE"
  export GITHUB_TOKEN=""
}
