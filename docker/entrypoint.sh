#!/usr/bin/env bash
set -euo pipefail

# entrypoint.sh — Container startup script.
# Runs once at container start before crond takes over.

log() { echo "[entrypoint] $*"; }

# ── 1. Activate dbt profile ───────────────────────────────────────────────────
# profiles.yml.example reads exclusively from env vars — copying it is enough.
if [[ ! -f /app/dbt/profiles.yml ]]; then
  cp /app/dbt/profiles.yml.example /app/dbt/profiles.yml
  log "Created dbt/profiles.yml from example"
fi

# ── 2. Install dbt packages ───────────────────────────────────────────────────
log "Running dbt deps"
dbt deps \
  --project-dir /app/dbt \
  --profiles-dir /app/dbt \
  --no-version-check

# ── 3. Ensure runtime directories ────────────────────────────────────────────
mkdir -p /state /app/logs

# ── 4. Inject env vars for cron ──────────────────────────────────────────────
# cron does not inherit the container environment. We dump the relevant vars
# to a sourced file. Two hardening measures:
#   - umask 077 subshell: file is created 600 from the start (no TOCTOU window)
#   - values are single-quoted so special chars in passwords survive sourcing
#     under dash (which runs /etc/cron.d entries)
ENV_FILE=/etc/cron.d/cve-pipeline-env
# umask 077 creates the file 600 atomically (no TOCTOU window).
# Values are single-quoted so special chars survive sourcing under dash.
# The subshell failing is fatal: a missing env file means cron runs without
# credentials, which is silent and hard to diagnose. Abort startup instead.
(umask 077
 printenv | grep -E '^(SNOWFLAKE_|DBT_|GITHUB_|CVE_)' | \
 while IFS= read -r line; do
   key="${line%%=*}"
   val="${line#*=}"
   val="${val//"'"/"'\''"}"
   printf "export %s='%s'\n" "$key" "$val"
 done > "$ENV_FILE") || { log "FATAL: failed to write cron env file ${ENV_FILE}"; exit 1; }
# cveuser's primary group is root (useradd -g root), so chmod 640 (root:root)
# lets cveuser read this file via the group-read bit without needing a cveuser group.
chmod 640 "$ENV_FILE"
log "Wrote cron env vars to ${ENV_FILE} (root:root 640, readable by cveuser)"

# ── 5. Fix runtime directory ownership for non-root pipeline user ─────────────
chown -R cveuser:root /state /app/logs /app/dbt
log "Set ownership of runtime dirs to cveuser"

# ── 6. Write cron job ────────────────────────────────────────────────────────
# /etc/cron.d files must be 644 and root-owned or crond silently ignores them.
# The username field (cveuser) runs the job as a non-root user.
CRON_FILE=/etc/cron.d/cve-pipeline
cat > "$CRON_FILE" <<'EOF'
30 * * * * cveuser . /etc/cron.d/cve-pipeline-env && /app/scripts/cve_pipeline.sh --state-file /state/.pipeline_state --log-file /app/logs/pipeline.log >> /app/logs/cron.log 2>&1
EOF
chmod 644 "$CRON_FILE"
log "Registered cron job: runs at :30 past every hour as cveuser"

# ── 7. Start crond in the foreground ─────────────────────────────────────────
# cron -f keeps crond as the main process so tini (PID 1) can forward SIGTERM
# and in-progress pipeline jobs get the container's stop-grace-period to finish.
touch /app/logs/pipeline.log /app/logs/cron.log
log "Starting crond (foreground). To run the pipeline now:"
log "  docker compose exec cve-pipeline su -c '/app/scripts/cve_pipeline.sh --state-file /state/.pipeline_state --log-file /app/logs/pipeline.log' cveuser"
exec /usr/sbin/cron -f
