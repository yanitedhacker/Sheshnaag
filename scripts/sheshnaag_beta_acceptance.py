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

from app.services.proof_receipts import verify_proof_receipt

ROOT = Path(__file__).resolve().parents[1]

P0_INTEGRITY_TESTS = (
    "tests/unit/test_capability_policy.py::test_legacy_tenant_only_artifact_cannot_authorize_exact_action",
    "tests/unit/test_capability_policy.py::test_production_cosign_does_not_fall_back_when_sigstore_is_missing",
    "tests/unit/test_authorization_workflow.py::test_requester_cannot_decide_their_own_request",
    "tests/unit/test_authorization_workflow.py::test_single_independent_approval_issues_bound_artifact",
    "tests/unit/test_autonomous_agent_fail_closed.py::test_policy_exception_denies_before_tools_ai_or_events",
    "tests/unit/test_autonomous_agent_fail_closed.py::test_run_flush_failure_raises_and_creates_no_replay_entry",
    "tests/integration/test_autonomous_routes.py::test_autonomous_commit_failure_returns_503",
    "tests/integration/test_autonomous_routes.py::test_run_autonomous_agent_returns_only_committed_completion",
    "tests/unit/test_disclosure_export_controls.py::test_bundle_excludes_raw_logs_and_redacts_included_payloads",
    "tests/unit/test_autonomous_replay_bounds.py::test_autonomous_replay_has_hard_service_limit_and_tenant_scope",
    "tests/integration/test_autonomous_routes.py::test_autonomous_replay_limit_is_bounded_by_api",
)


def _run(
    argv: list[str],
    *,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> tuple[int, str]:
    command_env = os.environ.copy()
    if env:
        command_env.update(env)
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        env=command_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def _find_duplicate_artifacts() -> list[str]:
    ignored_parts = {
        ".git",
        ".pytest_cache",
        "__pycache__",
        "dist",
        "node_modules",
    }

    def included(path: Path) -> bool:
        relative_parts = path.relative_to(ROOT).parts
        return not any(
            part in ignored_parts or part.startswith(".venv")
            for part in relative_parts
        )

    return sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("* 2.*")
        if included(path)
    )


def _run_p0_integrity_tests() -> dict[str, Any]:
    returncode, output = _run(
        [sys.executable, "-m", "pytest", "-q", *P0_INTEGRITY_TESTS],
        timeout=180,
        env={"RUN_INTEGRATION_TESTS": "1"},
    )
    return {
        "status": "ok" if returncode == 0 else "failed",
        "returncode": returncode,
        "tests": list(P0_INTEGRITY_TESTS),
        "output": output[-12000:],
    }


def _fetch_json(url: str, *, timeout: int = 10) -> dict[str, Any]:
    with urlopen(url, timeout=timeout) as response:  # noqa: S310 - operator-supplied local URL
        return json.loads(response.read().decode("utf-8"))


def _status(value: bool) -> str:
    return "ok" if value else "blocked"


def _verify_proof_claims(
    required_proofs: dict[str, str | None],
    *,
    expected_git_commit: str,
    trusted_fingerprint: str | None,
) -> dict[str, Any]:
    """Build a fail-closed claim ledger from pinned signed receipts."""

    blockers: list[str] = []
    claims: dict[str, Any] = {}
    missing_proofs: list[str] = []
    trusted = (trusted_fingerprint or "").strip().lower()
    if not trusted:
        blockers.append("proof_trust_root_missing")

    for proof_class, configured_path in required_proofs.items():
        if not configured_path or not Path(configured_path).is_file():
            missing_proofs.append(proof_class)
            blockers.append(f"missing_proof.{proof_class}")
            claims[proof_class] = {
                "status": "missing",
                "receipt_path": configured_path,
                "errors": ["receipt.path_missing"],
            }
            continue

        if not trusted:
            claims[proof_class] = {
                "status": "blocked",
                "receipt_path": configured_path,
                "errors": ["receipt.trust_root_missing"],
            }
            continue

        verification = verify_proof_receipt(
            configured_path,
            expected_proof_class=proof_class,
            expected_git_commit=expected_git_commit,
            trusted_fingerprint=trusted,
        )
        verified = verification["status"] == "ok"
        claims[proof_class] = {
            "receipt_path": configured_path,
            "verification_status": verification["status"],
            "errors": verification["errors"],
            "proof_class": verification["proof_class"],
            "artifact_count": verification["artifact_count"],
            "status": "verified" if verified else "blocked",
        }
        if not verified:
            blockers.append(f"proof.{proof_class}.invalid")

    return {
        "status": _status(not blockers),
        "blockers": blockers,
        "missing_proofs": missing_proofs,
        "trusted_fingerprint": trusted or None,
        "expected_git_commit": expected_git_commit,
        "claims": claims,
    }


def build_report(api: str, compose_env: str) -> dict[str, Any]:
    blockers: list[str] = []
    p0_integrity = _run_p0_integrity_tests()
    if p0_integrity["status"] != "ok":
        blockers.append("p0_integrity_tests")

    duplicate_artifacts = _find_duplicate_artifacts()
    if duplicate_artifacts:
        blockers.append("duplicate_artifacts")

    compose_rc, compose_output = _run(["docker", "compose", "--env-file", compose_env, "config"], timeout=90)
    if compose_rc != 0:
        blockers.append("docker_compose_config")

    git_rc, git_output = _run(["git", "status", "--short"], timeout=30)
    if git_rc != 0:
        blockers.append("git_status")
    revision_rc, git_revision = _run(["git", "rev-parse", "HEAD"], timeout=30)
    if revision_rc != 0:
        blockers.append("git_revision")

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
    claim_ledger = _verify_proof_claims(
        required_proofs,
        expected_git_commit=git_revision if revision_rc == 0 else "",
        trusted_fingerprint=os.getenv("SHESHNAAG_PROOF_TRUST_FINGERPRINT"),
    )
    blockers.extend(claim_ledger["blockers"])

    return {
        "generated_at_epoch": int(time.time()),
        "status": _status(not blockers),
        "blockers": blockers,
        "p0_integrity": p0_integrity,
        "repo": {
            "duplicate_artifacts": duplicate_artifacts,
            "git_status": git_output,
            "git_revision": git_revision if revision_rc == 0 else None,
        },
        "docker_compose": {
            "env_file": compose_env,
            "status": "ok" if compose_rc == 0 else "failed",
            "output": compose_output[-4000:],
        },
        "ops_health": health if health is not None else {"error": health_error},
        "required_proofs": required_proofs,
        "missing_proofs": claim_ledger["missing_proofs"],
        "claim_ledger": claim_ledger,
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
