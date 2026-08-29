"""Tests for executable P0 checks in the beta acceptance gate."""

from __future__ import annotations

import json

import scripts.sheshnaag_beta_acceptance as acceptance
from app.services.proof_receipts import build_signed_receipt, generate_proof_key


def test_duplicate_scan_ignores_dependency_and_build_directories(
    monkeypatch,
    tmp_path,
):
    duplicate = tmp_path / "src" / "report 2.json"
    ignored = [
        tmp_path / ".venv-v2" / "lib" / "package 2.py",
        tmp_path / "frontend" / "node_modules" / "package 2.js",
        tmp_path / "frontend" / "dist" / "chunk 2.js",
        tmp_path / ".pytest_cache" / "result 2.json",
    ]
    duplicate.parent.mkdir(parents=True)
    duplicate.write_text("{}", encoding="utf-8")
    for path in ignored:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ignored", encoding="utf-8")
    monkeypatch.setattr(acceptance, "ROOT", tmp_path)

    assert acceptance._find_duplicate_artifacts() == ["src/report 2.json"]


def test_p0_integrity_gate_executes_named_behavior_tests(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(argv, *, timeout=60, env=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        captured["env"] = env
        return 0, "8 passed in 1.00s"

    monkeypatch.setattr(acceptance, "_run", fake_run)

    result = acceptance._run_p0_integrity_tests()

    assert result["status"] == "ok"
    assert result["returncode"] == 0
    assert result["output"] == "8 passed in 1.00s"
    assert captured["argv"][:4] == [
        acceptance.sys.executable,
        "-m",
        "pytest",
        "-q",
    ]
    assert captured["env"] == {"RUN_INTEGRATION_TESTS": "1"}
    assert set(acceptance.P0_INTEGRITY_TESTS).issubset(set(captured["argv"]))


def test_p0_integrity_gate_blocks_on_test_failure(monkeypatch):
    monkeypatch.setattr(
        acceptance,
        "_run",
        lambda argv, *, timeout=60, env=None: (1, "1 failed, 7 passed"),
    )

    result = acceptance._run_p0_integrity_tests()

    assert result == {
        "status": "failed",
        "returncode": 1,
        "tests": list(acceptance.P0_INTEGRITY_TESTS),
        "output": "1 failed, 7 passed",
    }


def _signed_proof(tmp_path):
    artifact = tmp_path / "agent-runtime.log"
    artifact.write_text("committed run 42\n", encoding="utf-8")
    key_path = tmp_path / "proof.key"
    key = generate_proof_key(key_path)
    receipt = build_signed_receipt(
        proof_class="autonomous_agent",
        status="passed",
        subject={
            "system": "sheshnaag",
            "git_commit": "c" * 40,
            "deployment_profile": "design_partner_beta",
        },
        checks=[{"id": "committed_run", "status": "passed", "detail": "run 42"}],
        artifact_paths=[artifact],
        base_dir=tmp_path,
        private_key_path=key_path,
        issuer="acceptance-test",
        issued_at="2026-08-29T12:00:00Z",
    )
    receipt_path = tmp_path / "autonomous-agent.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    return receipt_path, key


def test_claim_ledger_accepts_only_pinned_signed_receipt(tmp_path):
    receipt_path, key = _signed_proof(tmp_path)

    result = acceptance._verify_proof_claims(
        {"autonomous_agent": str(receipt_path)},
        expected_git_commit="c" * 40,
        trusted_fingerprint=key["fingerprint"],
    )

    assert result["status"] == "ok"
    assert result["blockers"] == []
    assert result["missing_proofs"] == []
    assert result["claims"]["autonomous_agent"]["status"] == "verified"


def test_claim_ledger_rejects_file_presence_without_valid_receipt(tmp_path):
    fake_proof = tmp_path / "proof.txt"
    fake_proof.write_text("PASS: trust me\n", encoding="utf-8")

    result = acceptance._verify_proof_claims(
        {"real_detonation": str(fake_proof)},
        expected_git_commit="c" * 40,
        trusted_fingerprint="f" * 64,
    )

    assert result["status"] == "blocked"
    assert result["blockers"] == ["proof.real_detonation.invalid"]
    assert result["claims"]["real_detonation"]["status"] == "blocked"


def test_claim_ledger_blocks_when_trust_root_is_not_pinned(tmp_path):
    receipt_path, _key = _signed_proof(tmp_path)

    result = acceptance._verify_proof_claims(
        {"autonomous_agent": str(receipt_path)},
        expected_git_commit="c" * 40,
        trusted_fingerprint=None,
    )

    assert result["status"] == "blocked"
    assert result["blockers"] == ["proof_trust_root_missing"]
    assert result["claims"]["autonomous_agent"]["errors"] == [
        "receipt.trust_root_missing"
    ]
