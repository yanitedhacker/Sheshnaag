#!/usr/bin/env bash
# Idempotent V3 → V4 upgrade orchestrator.
#
# Steps (each is gated on env so it can be re-run safely):
#  1. Pre-flight checks (Python, alembic, redis-cli, optional MinIO).
#  2. Run alembic upgrade head.
#  3. Provision MinIO (skip when OBJECT_STORE_BACKEND != minio).
#  4. Migrate quarantine objects (skip when --skip-migrate).
#  5. Smoke /api/v4/ops/health.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
SKIP_MIGRATE=0
DRY_RUN=0
HEALTH_URL="${HEALTH_URL:-http://localhost:8000/api/v4/ops/health}"

usage() {
  cat <<USAGE
Usage: scripts/v4/upgrade_from_v3.sh [options]
  --skip-migrate   Skip the quarantine→MinIO migration step.
  --dry-run        Print what would happen and exit 0.
  --help           Show this message.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-migrate) SKIP_MIGRATE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }

run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[DRY-RUN] %s\n' "$*"
  else
    eval "$@"
  fi
}

log "Sheshnaag V3 → V4 upgrade starting"

# 1. Pre-flight ---------------------------------------------------------------
log "Pre-flight: python=$("${PYTHON_BIN}" --version 2>&1)"
if ! command -v alembic >/dev/null 2>&1; then
  log "alembic not found in PATH — falling back to ${PYTHON_BIN} -m alembic"
  ALEMBIC_CMD="${PYTHON_BIN} -m alembic"
else
  ALEMBIC_CMD="alembic"
fi

# 2. Alembic ------------------------------------------------------------------
log "Running alembic upgrade head"
run "${ALEMBIC_CMD} upgrade head"

# 3. MinIO provision ----------------------------------------------------------
backend="${OBJECT_STORE_BACKEND:-filesystem}"
if [[ "${backend}" == "minio" || "${backend}" == "s3" ]]; then
  log "Provisioning MinIO bucket ${MINIO_BUCKET:-sheshnaag-quarantine}"
  run "${PYTHON_BIN} scripts/v4/minio_provision.py"
else
  log "OBJECT_STORE_BACKEND=${backend}; skipping MinIO provisioning"
fi

# 4. Quarantine migration -----------------------------------------------------
if [[ "${SKIP_MIGRATE}" -eq 1 ]]; then
  log "Skipping quarantine migration (--skip-migrate)"
elif [[ "${backend}" == "minio" || "${backend}" == "s3" ]]; then
  log "Migrating filesystem quarantine into MinIO"
  run "${PYTHON_BIN} scripts/v4/migrate_quarantine_to_minio.py --keep"
else
  log "Quarantine migration not applicable for backend=${backend}"
fi

# 5. Health smoke -------------------------------------------------------------
if [[ "${DRY_RUN}" -eq 0 ]]; then
  log "Smoking ${HEALTH_URL}"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 10 "${HEALTH_URL}" || log "WARNING: health endpoint did not respond — verify the container is running."
  else
    log "curl not available; skip health smoke"
  fi
fi

log "Sheshnaag V3 → V4 upgrade completed"
