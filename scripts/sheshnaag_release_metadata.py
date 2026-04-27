#!/usr/bin/env python3
"""Emit reproducible environment metadata for release rehearsal records."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def command_output(argv: list[str], *, timeout: int = 15) -> str | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return (result.stdout or "").strip()
        return (result.stderr or "").strip() or None
    except Exception:
        return None


def command_status(argv: list[str], *, timeout: int = 60) -> dict:
    if shutil.which(argv[0]) is None:
        return {"status": "missing_tool", "command": argv}
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {
            "status": "passed" if result.returncode == 0 else "failed",
            "returncode": result.returncode,
            "command": argv,
            "stdout_tail": (result.stdout or "").strip()[-2000:],
            "stderr_tail": (result.stderr or "").strip()[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": argv}
    except Exception as exc:
        return {"status": "error", "command": argv, "error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=None, help="Optional file path to also write the metadata JSON.")
    parser.add_argument("--include-checks", action="store_true", help="Run lightweight audit/status checks.")
    parser.add_argument("--test-summary", default=None, help="Optional path to a test summary JSON file.")
    parser.add_argument("--sbom-artifact", action="append", default=[], help="SBOM artifact path to include.")
    args = parser.parse_args()
    git_sha = command_output(["git", "rev-parse", "HEAD"]) if shutil.which("git") else None
    git_status = command_output(["git", "status", "--porcelain"], timeout=5) if shutil.which("git") else None
    sbom_artifacts = [
        {"path": item, "exists": Path(item).exists(), "bytes": Path(item).stat().st_size if Path(item).exists() else None}
        for item in args.sbom_artifact
    ]
    test_summary = None
    if args.test_summary:
        try:
            test_summary = json.loads(Path(args.test_summary).read_text(encoding="utf-8"))
        except Exception as exc:
            test_summary = {"status": "unreadable", "error": str(exc), "path": args.test_summary}
    payload = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "git": {
            "sha": git_sha,
            "dirty": bool(git_status),
            "dirty_paths": git_status.splitlines() if git_status else [],
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "tools": {
            "docker": command_output(["docker", "--version"]) if shutil.which("docker") else None,
            "node": command_output(["node", "--version"]) if shutil.which("node") else None,
            "npm": command_output(["npm", "--version"]) if shutil.which("npm") else None,
            "pytest": command_output(["pytest", "--version"]) if shutil.which("pytest") else None,
            "limactl": command_output(["limactl", "--version"]) if shutil.which("limactl") else None,
        },
        "checks": {
            "python_dependency_audit": command_status([sys.executable, "-m", "pip_audit", "-r", "requirements.txt"], timeout=120)
            if args.include_checks
            else {"status": "not_run"},
            "frontend_dependency_audit": command_status(["npm", "--prefix", "frontend", "audit", "--audit-level=moderate"], timeout=120)
            if args.include_checks
            else {"status": "not_run"},
            "docker": {
                "available": shutil.which("docker") is not None,
                "version": command_output(["docker", "--version"]) if shutil.which("docker") else None,
            },
        },
        "sbom_artifacts": sbom_artifacts,
        "test_summary": test_summary or {"status": "not_provided"},
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
