#!/usr/bin/env python3
"""Emit reproducible environment metadata for release rehearsal records."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone


def command_output(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return (result.stdout or "").strip()
        return (result.stderr or "").strip() or None
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=None, help="Optional file path to also write the metadata JSON.")
    args = parser.parse_args()
    payload = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
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
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
