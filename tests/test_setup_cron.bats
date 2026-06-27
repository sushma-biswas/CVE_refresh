#!/usr/bin/env bats
# Tests for scripts/setup_cron.sh
# Run with: bats tests/test_setup_cron.bats

load setup

SCRIPT="${SCRIPTS_DIR}/setup_cron.sh"

# Override crontab with a mock that reads/writes a local file so we don't
# touch the real crontab during tests.
setup() {
  shared_setup
  local cron_file="${TEST_TMPDIR}/crontab"
  touch "$cron_file"

  cat > "${MOCK_BIN}/crontab" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "-l" ]]; then
  cat "${cron_file}" 2>/dev/null || true
  exit 0
fi
# Write mode: read from stdin
cat > "${cron_file}"
exit 0
EOF
  chmod +x "${MOCK_BIN}/crontab"

  export CRON_FILE="$cron_file"
}

@test "registers the pipeline cron entry" {
  run bash "$SCRIPT"

  [[ "$status" -eq 0 ]]
  grep -q "cve_pipeline.sh" "$CRON_FILE"
}

@test "cron entry runs at minute 30 of every hour" {
  run bash "$SCRIPT"

  [[ "$status" -eq 0 ]]
  grep -qE "^30 \* \* \* \*" "$CRON_FILE"
}

@test "running setup_cron.sh twice does not create duplicate entries" {
  bash "$SCRIPT"
  bash "$SCRIPT"

  count=$(grep -c "cve_pipeline.sh" "$CRON_FILE" || echo 0)
  [[ "$count" -eq 1 ]]
}

@test "--dry-run prints the proposed entry without modifying crontab" {
  run bash "$SCRIPT" --dry-run

  [[ "$status" -eq 0 ]]
  [[ "$output" == *"cve_pipeline.sh"* ]]
  # crontab file must remain empty
  [[ ! -s "$CRON_FILE" ]]
}

@test "cron entry redirects stdout and stderr to the log file" {
  run bash "$SCRIPT"

  [[ "$status" -eq 0 ]]
  grep -q ">>" "$CRON_FILE"
  grep -q "2>&1" "$CRON_FILE"
}
