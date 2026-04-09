#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

declare -a STEPS=(
  "Backend smoke|python scripts/sheshnaag_api_smoke.py"
  "Frontend route smoke|python scripts/sheshnaag_frontend_smoke.py"
  "Targeted pytest|PYTHONPATH=. pytest -q tests/unit/test_recipe_schema.py tests/unit/test_sheshnaag_service.py tests/integration/test_lab_lifecycle.py tests/integration/test_evidence_collectors.py tests/integration/test_provenance_and_disclosure_routes.py"
  "Frontend build|npm --prefix frontend run build"
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
echo "- Confirm bundle exports were created under the expected export root and remove stale archives after review."
echo

if [[ "$failures" -gt 0 ]]; then
  echo "Release rehearsal finished with ${failures} failing step(s)."
  exit 1
fi

echo "Release rehearsal finished successfully."
