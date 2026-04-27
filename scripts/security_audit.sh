#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${PYTHON_BIN:-${VIRTUAL_ENV:+${VIRTUAL_ENV}/bin/python}}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

printf "Security audit starting in %s\n" "$ROOT_DIR"

failures=0

# 1) Secret/key scan (best-effort, fast patterns)
printf "\n[1/3] Scanning for hardcoded secrets...\n"
secret_patterns='(api[_-]?key|secret|token|password|passwd|private_key|auth[_-]?token|access[_-]?key|AWS_|AKIA|BEGIN[[:space:]]+PRIVATE[[:space:]]+KEY|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})'

if grep -RIn --exclude-dir={.git,.venv,venv,env,__pycache__,.pytest_cache} \
  --exclude="*.db" --exclude="*.sqlite*" --exclude="*.log" \
  -E "$secret_patterns" . > /tmp/secret_scan_hits.txt; then
  printf "Potential secrets found:\n"
  cat /tmp/secret_scan_hits.txt
  failures=$((failures + 1))
else
  printf "No obvious hardcoded secrets found.\n"
fi

# 2) Ensure no .env files are tracked
printf "\n[2/3] Checking for tracked env files...\n"
if git ls-files | grep -E '(^|/)\.env(\.|$)' >/tmp/tracked_envs.txt; then
  printf "Tracked env files detected (should not be committed):\n"
  cat /tmp/tracked_envs.txt
  failures=$((failures + 1))
else
  printf "No tracked .env files found.\n"
fi

# 3) Dependency vulnerability scan (pip-audit)
printf "\n[3/3] Dependency vulnerability scan (pip-audit)...\n"
if "$PYTHON_BIN" -m pip_audit -r requirements.txt; then
  printf "pip-audit completed.\n"
else
  printf "pip-audit not available or failed.\n"
  printf "To install: python3 -m pip install pip-audit\n"
  failures=$((failures + 1))
fi

printf "\nSecurity audit completed.\n"
if [ "$failures" -ne 0 ]; then
  printf "Failures: %s\n" "$failures"
  exit 2
fi

printf "All checks passed.\n"
