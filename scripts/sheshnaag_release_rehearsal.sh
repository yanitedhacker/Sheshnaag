#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"

declare -a STEPS=(
  "Environment metadata [deployment]|${PYTHON_BIN} scripts/sheshnaag_release_metadata.py --include-checks"
  "Backend smoke [runtime-execution]|${PYTHON_BIN} scripts/sheshnaag_api_smoke.py"
  "Migration rehearsal [deployment]|${PYTHON_BIN} scripts/sheshnaag_migration_rehearsal.py"
  "Frontend route smoke [deployment]|${PYTHON_BIN} scripts/sheshnaag_frontend_smoke.py"
  "Maintainer CLI smoke [deployment]|${PYTHON_BIN} scripts/sheshnaag_maintainer.py --help >/dev/null && ${PYTHON_BIN} scripts/sheshnaag_maintainer.py assess --help >/dev/null"
  "Targeted pytest [integration]|PYTHONPATH=. RUN_INTEGRATION_TESTS=1 ${PYTHON_BIN} -m pytest -q tests/unit/test_recipe_schema.py tests/unit/test_sheshnaag_service.py tests/unit/test_collectors_framework.py tests/unit/test_sheshnaag_parity.py tests/integration/test_lab_lifecycle.py tests/integration/test_evidence_collectors.py tests/integration/test_provenance_and_disclosure_routes.py"
  "Build osquery image [image]|bash scripts/build_sheshnaag_osquery_image.sh"
  "Build Tracee image [image]|bash scripts/build_sheshnaag_tracee_image.sh"
  "Execute smoke [runtime-execution]|${PYTHON_BIN} scripts/sheshnaag_execute_smoke.py"
  "osquery smoke [runtime-execution]|${PYTHON_BIN} scripts/sheshnaag_osquery_smoke.py"
  "Tracee smoke [runtime-execution]|${PYTHON_BIN} scripts/sheshnaag_tracee_smoke.py"
  "Secure-mode smoke [secure-mode]|${PYTHON_BIN} scripts/sheshnaag_secure_mode_smoke.py"
  "Frontend audit [deployment]|npm --prefix frontend audit --audit-level=moderate"
  "Frontend build [deployment]|npm --prefix frontend run build"
)

echo "Sheshnaag release rehearsal"
echo

failures=0
for step in "${STEPS[@]}"; do
  name="${step%%|*}"
  cmd="${step#*|}"
  echo "==> ${name}"
  if bash -c "$cmd"; then
    echo "PASS: ${name}"
  else
    echo "FAIL: ${name}"
    failures=$((failures + 1))
  fi
  echo
done

echo "Manual follow-up"
echo "- Review warning output for collector skips, deprecations, and disclosure safety prompts."
echo "- If running execute-mode labs, rerun lifecycle checks with Docker available and capture the host environment in release notes."
echo "- For the dedicated secure host lane, run bash scripts/sheshnaag_secure_host_rehearsal.sh and archive the generated JSON/log bundle."
echo "- If secure-mode smoke ran, archive the reported Lima capability state and any snapshot/revert audit metadata."
echo "- Confirm bundle exports were created under the expected export root and remove stale archives after review."
echo

if [[ "$failures" -gt 0 ]]; then
  echo "Release rehearsal finished with ${failures} failing step(s)."
  exit 1
fi

echo "Release rehearsal finished successfully."
