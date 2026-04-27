#!/usr/bin/env python3
"""Run the Sheshnaag release rehearsal and write reviewer proof artifacts."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_BIN = os.getenv("PYTHON_BIN", sys.executable)
ARTIFACT_DIR = Path(os.getenv("SHESHNAAG_RELEASE_OUTPUT_DIR", "data/release_metadata"))


STEPS = [
    (
        "Environment metadata [deployment]",
        f"{PYTHON_BIN} scripts/sheshnaag_release_metadata.py --include-checks --output {ARTIFACT_DIR}/release-metadata.json",
    ),
    ("Backend smoke [runtime-execution]", f"{PYTHON_BIN} scripts/sheshnaag_api_smoke.py"),
    ("Migration rehearsal [deployment]", f"{PYTHON_BIN} scripts/sheshnaag_migration_rehearsal.py"),
    ("Frontend route smoke [deployment]", f"{PYTHON_BIN} scripts/sheshnaag_frontend_smoke.py"),
    (
        "Maintainer CLI smoke [deployment]",
        f"{PYTHON_BIN} scripts/sheshnaag_maintainer.py --help >/dev/null && "
        f"{PYTHON_BIN} scripts/sheshnaag_maintainer.py assess --help >/dev/null",
    ),
    (
        "Maintainer demo proof [deployment self-skip without local API]",
        f"{PYTHON_BIN} scripts/sheshnaag_maintainer_demo.py --allow-skip "
        f"--output {ARTIFACT_DIR}/maintainer-demo-assessment.json",
    ),
    (
        "Targeted pytest [integration]",
        "PYTHONPATH=. RUN_INTEGRATION_TESTS=1 "
        f"{PYTHON_BIN} -m pytest -q "
        "tests/unit/test_recipe_schema.py "
        "tests/unit/test_sheshnaag_service.py "
        "tests/unit/test_collectors_framework.py "
        "tests/unit/test_sheshnaag_parity.py "
        "tests/integration/test_lab_lifecycle.py "
        "tests/integration/test_evidence_collectors.py "
        "tests/integration/test_provenance_and_disclosure_routes.py",
    ),
    ("Build osquery image [image self-skip without Docker]", "bash scripts/build_sheshnaag_osquery_image.sh"),
    ("Build Tracee image [image self-skip without Docker]", "bash scripts/build_sheshnaag_tracee_image.sh"),
    (
        "Execute smoke [runtime-execution self-skip without Docker]",
        f"{PYTHON_BIN} scripts/sheshnaag_execute_smoke.py",
    ),
    (
        "osquery smoke [runtime-execution self-skip without Docker]",
        f"{PYTHON_BIN} scripts/sheshnaag_osquery_smoke.py",
    ),
    (
        "Tracee smoke [runtime-execution self-skip without Docker]",
        f"{PYTHON_BIN} scripts/sheshnaag_tracee_smoke.py",
    ),
    (
        "Secure-mode smoke [secure-mode self-skip without limactl]",
        f"{PYTHON_BIN} scripts/sheshnaag_secure_mode_smoke.py",
    ),
    ("Frontend audit [deployment]", "npm --prefix frontend audit --audit-level=moderate"),
    ("Frontend build [deployment]", "npm --prefix frontend run build"),
]


def _log(message: str = "") -> None:
    print(message, flush=True)


def _command_ok(argv: list[str]) -> bool:
    if shutil.which(argv[0]) is None:
        return False
    return subprocess.run(argv, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def main() -> int:
    os.chdir(ROOT)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    _log("Sheshnaag release rehearsal")
    _log()
    if _command_ok(["docker", "info"]):
        _log("Docker preflight: available")
    else:
        _log("Docker preflight: unavailable; Docker-backed local steps are expected to self-skip.")
    if shutil.which("limactl"):
        _log("Lima preflight: limactl available")
    else:
        _log("Lima preflight: limactl unavailable; secure-mode local step is expected to self-skip.")
    _log(f"Artifact output: {ARTIFACT_DIR}")
    _log()

    results: list[tuple[str, str]] = []
    failures = 0
    for name, command in STEPS:
        _log(f"==> {name}")
        completed = subprocess.run(command, cwd=ROOT, shell=True)
        if completed.returncode == 0:
            status = "PASS"
            _log(f"PASS: {name}")
        else:
            status = "FAIL"
            failures += 1
            _log(f"FAIL: {name}")
        results.append((status, name))
        _log()

    _log("Result summary")
    _log(f"{'Status':<8} Step")
    for status, name in results:
        _log(f"{status:<8} {name}")
    _log()

    _log("Manual follow-up")
    _log("- Review warning output for collector skips, deprecations, and disclosure safety prompts.")
    _log("- If running execute-mode labs, rerun lifecycle checks with Docker available and capture the host environment in release notes.")
    _log("- For the dedicated secure host lane, run bash scripts/sheshnaag_secure_host_rehearsal.sh and archive the generated JSON/log bundle.")
    _log("- If secure-mode smoke ran, archive the reported Lima capability state and any snapshot/revert audit metadata.")
    _log("- Confirm bundle exports were created under the expected export root and remove stale archives after review.")
    _log(f"- Release metadata and maintainer demo proof are written under {ARTIFACT_DIR}.")
    _log()

    if failures:
        _log(f"Release rehearsal finished with {failures} failing step(s).")
        return 1
    _log("Release rehearsal finished successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
