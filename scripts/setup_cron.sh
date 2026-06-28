#!/usr/bin/env bash
set -euo pipefail

# setup_cron.sh — Register the hourly CVE pipeline cron job.
#
# Runs the pipeline at 30 minutes past every hour (00:30, 01:30, …).
# GitHub publishes delta releases approximately 20-25 minutes after the hour,
# so the :30 schedule provides a safe buffer.
#
# Usage:
#   ./scripts/setup_cron.sh [--dry-run]
#
# Run this once on the server after cloning the repo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PIPELINE_SCRIPT="${PROJECT_DIR}/scripts/cve_pipeline.sh"
LOG_FILE="${PROJECT_DIR}/logs/pipeline.log"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ ! -f "$PIPELINE_SCRIPT" ]]; then
  echo "ERROR: Pipeline script not found: ${PIPELINE_SCRIPT}" >&2
  exit 1
fi

chmod +x "$PIPELINE_SCRIPT"

CRON_ENTRY="30 * * * * bash ${PIPELINE_SCRIPT} >> ${LOG_FILE} 2>&1"

echo "Current cron table (before change):"
crontab -l 2>/dev/null | grep "cve_pipeline" || echo "  (no existing cve_pipeline entry)"
echo ""
echo "Proposed entry:"
echo "  ${CRON_ENTRY}"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "Dry run — no changes made."
  exit 0
fi

# Remove any existing cve_pipeline entry, then add the new one atomically
(crontab -l 2>/dev/null | grep -v "cve_pipeline"; echo "$CRON_ENTRY") | crontab -

echo "Cron job registered. Verify with: crontab -l"
