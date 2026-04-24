#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_DIR="${SHESHNAAG_RELEASE_ARCHIVE_DIR:-/tmp/sheshnaag-release-host-lane/${STAMP}}"
mkdir -p "$ARCHIVE_DIR"

declare -a STEPS=(
  "Release metadata|python scripts/sheshnaag_release_metadata.py --output ${ARCHIVE_DIR}/release-metadata.json"
  "Migration rehearsal|python scripts/sheshnaag_migration_rehearsal.py --output ${ARCHIVE_DIR}/migration-rehearsal.json"
  "Execute smoke|python scripts/sheshnaag_execute_smoke.py"
  "osquery smoke|python scripts/sheshnaag_osquery_smoke.py"
  "Tracee smoke|python scripts/sheshnaag_tracee_smoke.py"
  "Secure-mode smoke|python scripts/sheshnaag_secure_mode_smoke.py --output ${ARCHIVE_DIR}/secure-mode-smoke.json"
  "Frontend route smoke|python scripts/sheshnaag_frontend_smoke.py"
  "Frontend build|npm --prefix frontend run build"
)

echo "Sheshnaag secure host rehearsal"
echo "Archive dir: ${ARCHIVE_DIR}"
echo

for step in "${STEPS[@]}"; do
  name="${step%%|*}"
  cmd="${step#*|}"
  slug="$(echo "${name}" | tr '[:upper:]' '[:lower:]' | tr ' /' '--')"
  logfile="${ARCHIVE_DIR}/${slug}.log"
  echo "==> ${name}"
  if bash -c "$cmd" >"${logfile}" 2>&1; then
    echo "PASS: ${name}"
  else
    echo "FAIL: ${name} (see ${logfile})"
    cat "${logfile}"
    exit 1
  fi
  echo
done

echo "Secure host rehearsal finished successfully."
echo "Artifacts archived under ${ARCHIVE_DIR}"
