"""Tests for executable P0 checks in the beta acceptance gate."""

from __future__ import annotations

from io import BytesIO
import json
from urllib.error import HTTPError

import scripts.sheshnaag_beta_acceptance as acceptance
from app.services.proof_receipts import build_signed_receipt, generate_proof_key


def test_fetch_json_preserves_structured_http_error_body(monkeypatch):
    payload = {
        "api": "ok",
        "beta": {"status": "blocked", "blockers": ["lab_deps.kvm"]},
    }
    response_error = HTTPError(
        "http://127.0.0.1:8000/api/v4/ops/health",
        503,
        "Service Unavailable",
        hdrs=None,
        fp=BytesIO(json.dumps(payload).encode("utf-8")),
    )

    def raise_structured_health_error(*_args, **_kwargs):
        raise response_error

    monkeypatch.setattr(acceptance, "urlopen", raise_structured_health_error)

    assert acceptance._fetch_json(response_error.url) == payload


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


def test_report_never_emits_docker_compose_secret_output(monkeypatch):
    secret = "beta-database-password-must-not-leak"

    def fake_run(argv, *, timeout=60, env=None):
        if argv[:3] == ["docker", "compose", "--env-file"]:
            return 0, f"POSTGRES_PASSWORD: {secret}"
        if argv == ["git", "status", "--short"]:
            return 0, ""
        if argv == ["git", "rev-parse", "HEAD"]:
            return 0, "c" * 40
        if argv[:3] == [acceptance.sys.executable, "-m", "pytest"]:
            return 0, "18 passed"
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(acceptance, "_run", fake_run)
    monkeypatch.setattr(acceptance, "_find_duplicate_artifacts", lambda: [])
    monkeypatch.setattr(
        acceptance,
        "_fetch_json",
        lambda _url: {"api": "ok", "beta": {"status": "ok", "blockers": []}},
    )
    monkeypatch.setattr(
        acceptance,
        "_verify_proof_claims",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "blockers": [],
            "missing_proofs": [],
            "claims": {},
        },
    )

    report = acceptance.build_report("http://127.0.0.1:8000", ".env.example")

    assert secret not in json.dumps(report)
    assert report["docker_compose"]["output"] == "validated"


def test_main_prints_summary_without_sensitive_report_values(monkeypatch, capsys):
    secret = "private-proof-path-must-not-reach-stdout"
    monkeypatch.setattr(
        acceptance,
        "build_report",
        lambda _api, _compose_env: {
            "status": "ok",
            "blockers": [],
            "required_proofs": {"real_detonation": secret},
        },
    )

    assert acceptance.main([]) == 0

    stdout = capsys.readouterr().out
    assert secret not in stdout
    assert json.loads(stdout) == {
        "blocker_count": 0,
        "blockers": [],
        "report_path": None,
        "status": "ok",
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
