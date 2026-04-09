#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

declare -a STEPS=(
  "Environment metadata [deployment]|python scripts/sheshnaag_release_metadata.py"
  "Backend smoke [runtime-execution]|python scripts/sheshnaag_api_smoke.py"
  "Frontend route smoke [deployment]|python scripts/sheshnaag_frontend_smoke.py"
  "Targeted pytest [integration]|PYTHONPATH=. RUN_INTEGRATION_TESTS=1 pytest -q tests/unit/test_recipe_schema.py tests/unit/test_sheshnaag_service.py tests/unit/test_collectors_framework.py tests/unit/test_sheshnaag_parity.py tests/integration/test_lab_lifecycle.py tests/integration/test_evidence_collectors.py tests/integration/test_provenance_and_disclosure_routes.py"
  "Build osquery image [image]|bash scripts/build_sheshnaag_osquery_image.sh"
  "Build Tracee image [image]|bash scripts/build_sheshnaag_tracee_image.sh"
  "Execute smoke [runtime-execution]|python scripts/sheshnaag_execute_smoke.py"
  "osquery smoke [runtime-execution]|python scripts/sheshnaag_osquery_smoke.py"
  "Tracee smoke [runtime-execution]|python scripts/sheshnaag_tracee_smoke.py"
  "Secure-mode smoke [secure-mode]|python scripts/sheshnaag_secure_mode_smoke.py"
  "Frontend build [deployment]|npm --prefix frontend run build"
)

echo "Sheshnaag release rehearsal"
echo

failures=0
for step in "${STEPS[@]}"; do
  name="${step%%|*}"
  cmd="${step#*|}"
  echo "==> ${name}"
  if bash -lc "$cmd"; then
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
