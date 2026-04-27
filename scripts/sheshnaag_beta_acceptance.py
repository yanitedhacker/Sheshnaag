#!/usr/bin/env python3
"""Full V4 beta acceptance gate.

This script is intentionally conservative: it does not try to prove deep
runtime behavior by itself. Instead it checks the release hygiene gates and
captures the live ops-health verdict that is responsible for fail-closed beta
readiness.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def _run(argv: list[str], *, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def _find_duplicate_artifacts() -> list[str]:
    return sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("* 2.*")
        if "__pycache__" not in path.parts
    )


def _fetch_json(url: str, *, timeout: int = 10) -> dict[str, Any]:
    with urlopen(url, timeout=timeout) as response:  # noqa: S310 - operator-supplied local URL
        return json.loads(response.read().decode("utf-8"))


def _status(value: bool) -> str:
    return "ok" if value else "blocked"


def build_report(api: str, compose_env: str) -> dict[str, Any]:
    blockers: list[str] = []
    duplicate_artifacts = _find_duplicate_artifacts()
    if duplicate_artifacts:
        blockers.append("duplicate_artifacts")

    compose_rc, compose_output = _run(["docker", "compose", "--env-file", compose_env, "config"], timeout=90)
    if compose_rc != 0:
        blockers.append("docker_compose_config")

    git_rc, git_output = _run(["git", "status", "--short"], timeout=30)
    if git_rc != 0:
        blockers.append("git_status")

    health: dict[str, Any] | None = None
    health_error: str | None = None
    try:
        health = _fetch_json(f"{api.rstrip('/')}/api/v4/ops/health")
        if health.get("beta", {}).get("status") != "ok":
            blockers.append("ops_health_beta")
    except (OSError, URLError, json.JSONDecodeError) as exc:
        health_error = str(exc)
        blockers.append("ops_health_unreachable")

    required_proofs = {
        "real_detonation": os.getenv("SHESHNAAG_REAL_DETONATION_PROOF"),
        "ai_provider_matrix": os.getenv("SHESHNAAG_AI_PROVIDER_PROOF"),
        "capability_audit": os.getenv("SHESHNAAG_CAPABILITY_AUDIT_PROOF"),
        "stix_taxii": os.getenv("SHESHNAAG_STIX_TAXII_PROOF"),
        "autonomous_agent": os.getenv("SHESHNAAG_AUTONOMOUS_AGENT_PROOF"),
        "load_rehearsal": os.getenv("SHESHNAAG_LOAD_REHEARSAL_PROOF"),
    }
    missing_proofs = [name for name, path in required_proofs.items() if not path or not Path(path).exists()]
    blockers.extend(f"missing_proof.{name}" for name in missing_proofs)
    real_detonation_proof = required_proofs.get("real_detonation")
    if real_detonation_proof and Path(real_detonation_proof).exists():
        proof_text = Path(real_detonation_proof).read_text(encoding="utf-8", errors="replace")
        required_markers = [
            "PASS: V4 real detonation E2E completed",
            "snapshot",
            "egress",
            "pcap",
            "zeek",
        ]
        missing_markers = [marker for marker in required_markers if marker.lower() not in proof_text.lower()]
        if missing_markers:
            blockers.append("proof.real_detonation_incomplete")
    else:
        missing_markers = []

    return {
        "generated_at_epoch": int(time.time()),
        "status": _status(not blockers),
        "blockers": blockers,
        "repo": {
            "duplicate_artifacts": duplicate_artifacts,
            "git_status": git_output,
        },
        "docker_compose": {
            "env_file": compose_env,
            "status": "ok" if compose_rc == 0 else "failed",
            "output": compose_output[-4000:],
        },
        "ops_health": health if health is not None else {"error": health_error},
        "required_proofs": required_proofs,
        "missing_proofs": missing_proofs,
        "real_detonation_required_markers_missing": missing_markers,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check full V4 beta launch gates.")
    parser.add_argument("--api", default=os.getenv("SHESHNAAG_API", "http://127.0.0.1:8000"))
    parser.add_argument("--compose-env", default=os.getenv("SHESHNAAG_COMPOSE_ENV", ".env.example"))
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)

    report = build_report(args.api, args.compose_env)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
