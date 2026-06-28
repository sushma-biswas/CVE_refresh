#!/usr/bin/env bash
set -euo pipefail

# download_cve.sh — Download CVE data from CVEProject GitHub releases.
#
# First run (no state file): downloads the full baseline ZIP.
# Subsequent runs: downloads the latest hourly delta ZIP.
#
# Usage:
#   download_cve.sh [--state-file PATH] [--tmp-dir PATH]
#
# Output (stdout):
#   Lines beginning with # are log messages and must be ignored by the caller.
#   The final non-comment, non-empty line is the result:
#     <TAG> <EXTRACT_DIR>   on success  (space-separated; neither value may contain spaces)
#     SKIP                  when the latest tag was already processed
#
#   TMP_DIR must not contain spaces — it is used in a space-delimited output line.
#
# Exit codes:
#   0  success or skip
#   1  error (GitHub API failure, missing asset, download failure, bad format, etc.)

GITHUB_API="https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

# Fix 3: derive SCRIPT_DIR and PROJECT_DIR so the default state file is
# co-located with the project rather than in $HOME.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_STATE_FILE="${PROJECT_DIR}/.pipeline_state"
DEFAULT_TMP_DIR="/tmp"

STATE_FILE="$DEFAULT_STATE_FILE"
TMP_DIR="$DEFAULT_TMP_DIR"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-file) STATE_FILE="$2"; shift 2 ;;
    --tmp-dir)    TMP_DIR="$2";    shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── Guard: disable xtrace so credentials/tokens are never echoed ───────────
{ set +x; } 2>/dev/null

log() { echo "# [$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $*"; }

# ── Temp-file cleanup on any exit ─────────────────────────────────────────
ZIP_PATH=""
EXTRACT_DIR=""
cleanup() {
  [[ -n "$ZIP_PATH"    ]] && rm -f "$ZIP_PATH"
  [[ -n "$EXTRACT_DIR" ]] && rm -rf "$EXTRACT_DIR"
}
trap cleanup ERR EXIT

# ── Helpers ───────────────────────────────────────────────────────────────

# curl_with_retry <attempts> <curl-args…>
# Retries on transient failure with a 30-second back-off.
curl_with_retry() {
  local attempts="$1"; shift
  local attempt=0
  while (( attempt < attempts )); do
    if curl "$@"; then return 0; fi
    attempt=$(( attempt + 1 ))
    if (( attempt < attempts )); then
      log "WARN  curl failed (attempt ${attempt}/${attempts}) — retrying in 30s"
      sleep 30
    fi
  done
  return 1
}

# fetch_release_json — call the GitHub API and print the release JSON to stdout.
fetch_release_json() {
  local headers=(-H "Accept: application/vnd.github+json")
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  curl_with_retry 3 -sf "${headers[@]}" "$GITHUB_API"
}

# validate_github_url <url> — abort if the URL is not from the expected host.
validate_github_url() {
  local url="$1"
  if [[ "$url" != "https://github.com/CVEProject/cvelistV5/releases/download/"* ]]; then
    log "ERROR: Unexpected download URL (possible API tampering): ${url}"
    exit 1
  fi
}

# ── Validate TMP_DIR ──────────────────────────────────────────────────────
if [[ ! -d "$TMP_DIR" ]]; then
  log "ERROR: TMP_DIR does not exist: ${TMP_DIR}"
  exit 1
fi
if [[ "$TMP_DIR" == *" "* ]]; then
  log "ERROR: TMP_DIR must not contain spaces: ${TMP_DIR}"
  exit 1
fi

# ── Determine whether this is a baseline or delta run ─────────────────────
LAST_TAG=""
if [[ -f "$STATE_FILE" ]]; then
  # Validate state file content to prevent injection from a tampered file
  # Fix 2: require full tag format with optional time suffix and end anchor
  LAST_TAG=$(grep -E '^(cve_|baseline_)[0-9]{4}-[0-9]{2}-[0-9]{2}(_[0-9]{4}Z)?$' "$STATE_FILE" | head -1 || true)
fi

# ── Fetch release metadata (shared by baseline and delta paths) ────────────
release_json=$(fetch_release_json) || {
  log "ERROR: GitHub API request failed"
  exit 1
}

tag_name=$(echo "$release_json" | jq -r '.tag_name // empty')
if [[ -z "$tag_name" ]]; then
  log "ERROR: Could not parse tag_name from GitHub API response"
  exit 1
fi

if [[ -z "$LAST_TAG" ]]; then
  # ── BASELINE (first run — one time only) ─────────────────────────────
  log "No prior state found — fetching baseline"

  # Disk-space guard: baseline expands to 10+ GB; require at least 15 GB free
  available_kb=$(df -k "$TMP_DIR" | awk 'NR==2 {print $4}')
  if (( available_kb < 15000000 )); then
    log "ERROR: Insufficient disk space in ${TMP_DIR} — ${available_kb}KB free, need 15GB"
    exit 1
  fi

  baseline_url=$(echo "$release_json" | \
    jq -r '[.assets[] | select(.name | test("all_CVEs_at_midnight")) | .browser_download_url] | first // empty')
  if [[ -z "$baseline_url" ]]; then
    log "ERROR: No baseline asset found in release ${tag_name}"
    exit 1
  fi
  validate_github_url "$baseline_url"

  DATE_PART="${tag_name#cve_}"; DATE_PART="${DATE_PART#baseline_}"; DATE_PART="${DATE_PART%%_*}"
  TAG="baseline_${DATE_PART}"
  ZIP_PATH="${TMP_DIR}/cve_${TAG}.zip"
  EXTRACT_DIR="${TMP_DIR}/cve_extract_${TAG}"

  log "Downloading baseline from ${baseline_url}"
  # Fix 1: use array pattern so -H flag and value are separate words
  download_args=(-sfL)
  [[ -n "${GITHUB_TOKEN:-}" ]] && download_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  curl_with_retry 3 "${download_args[@]}" -o "$ZIP_PATH" "$baseline_url" || {
    log "ERROR: Failed to download baseline ZIP"
    exit 1
  }

else
  # ── DELTA (all subsequent runs) ───────────────────────────────────────
  log "Last processed tag: ${LAST_TAG} — checking for new delta"

  if [[ "$tag_name" == "$LAST_TAG" ]]; then
    log "Latest tag ${tag_name} already processed — nothing to do"
    echo "SKIP"
    exit 0
  fi

  delta_url=$(echo "$release_json" | \
    jq -r '[.assets[] | select(.name | test("delta")) | .browser_download_url] | first // empty')
  if [[ -z "$delta_url" ]]; then
    log "ERROR: No delta asset found in release ${tag_name}"
    exit 1
  fi
  validate_github_url "$delta_url"

  TAG="$tag_name"
  ZIP_PATH="${TMP_DIR}/cve_${TAG}.zip"
  EXTRACT_DIR="${TMP_DIR}/cve_extract_${TAG}"

  log "Downloading delta from ${delta_url}"
  # Fix 1: use array pattern so -H flag and value are separate words
  download_args=(-sfL)
  [[ -n "${GITHUB_TOKEN:-}" ]] && download_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  curl_with_retry 3 "${download_args[@]}" -o "$ZIP_PATH" "$delta_url" || {
    log "ERROR: Failed to download delta ZIP"
    exit 1
  }
fi

# ── Log and sanity-check download size ────────────────────────────────────
zip_bytes=$(stat -c%s "$ZIP_PATH" 2>/dev/null || stat -f%z "$ZIP_PATH" 2>/dev/null || echo 0)
if (( zip_bytes < 1000 )); then
  log "ERROR: Downloaded ZIP is suspiciously small (${zip_bytes} bytes) — aborting"
  exit 1
fi
log "Downloaded ${zip_bytes} bytes to ${ZIP_PATH}"

# ── Extract ZIP ────────────────────────────────────────────────────────────
mkdir -p "$EXTRACT_DIR"
log "Extracting to ${EXTRACT_DIR}"
unzip -q "$ZIP_PATH" -d "$EXTRACT_DIR" || {
  log "ERROR: Failed to extract ${ZIP_PATH}"
  exit 1
}

# ZIP no longer needed — remove it before emitting result
rm -f "$ZIP_PATH"
ZIP_PATH=""  # prevent trap from double-deleting

json_count=$(find "$EXTRACT_DIR" -name '*.json' | wc -l | tr -d ' ')
log "Extracted ${json_count} JSON files"

# Disable the trap and pass EXTRACT_DIR ownership to the caller.
# Clear the variable so the EXIT trap does not clean it up on normal exit.
trap - ERR EXIT
RESULT_EXTRACT_DIR="$EXTRACT_DIR"
EXTRACT_DIR=""

# ── Emit result for caller ─────────────────────────────────────────────────
echo "${TAG} ${RESULT_EXTRACT_DIR}"
