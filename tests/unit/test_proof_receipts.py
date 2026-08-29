"""Tests for signed, artifact-bound beta proof receipts."""

from __future__ import annotations

import base64
import json

from app.services.proof_receipts import (
    build_signed_receipt,
    generate_proof_key,
    verify_proof_receipt,
)


def _write_receipt(
    tmp_path,
    *,
    status: str = "passed",
    deployment_profile: str = "design_partner_beta",
):
    artifact = tmp_path / "runtime.log"
    artifact.write_text("bounded runtime evidence\n", encoding="utf-8")
    key_path = tmp_path / "proof.key"
    key = generate_proof_key(key_path)
    receipt = build_signed_receipt(
        proof_class="autonomous_agent",
        status=status,
        subject={
            "system": "sheshnaag",
            "git_commit": "a" * 40,
            "deployment_profile": deployment_profile,
        },
        checks=[
            {
                "id": "exact_action_run_committed",
                "status": "passed" if status == "passed" else "blocked",
                "detail": "HTTP response matched a durable run row.",
            }
        ],
        artifact_paths=[artifact],
        base_dir=tmp_path,
        private_key_path=key_path,
        issuer="test-suite",
        issued_at="2026-08-29T12:00:00Z",
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt_path, artifact, key


def test_signed_receipt_verifies_class_commit_trust_and_artifact(tmp_path):
    receipt_path, _artifact, key = _write_receipt(tmp_path)

    result = verify_proof_receipt(
        receipt_path,
        expected_proof_class="autonomous_agent",
        expected_git_commit="a" * 40,
        trusted_fingerprint=key["fingerprint"],
    )

    assert result["status"] == "ok"
    assert result["errors"] == []
    assert result["proof_class"] == "autonomous_agent"
    assert result["artifact_count"] == 1


def test_receipt_rejects_changed_evidence_artifact(tmp_path):
    receipt_path, artifact, key = _write_receipt(tmp_path)
    artifact.write_text("changed after signing\n", encoding="utf-8")

    result = verify_proof_receipt(
        receipt_path,
        expected_proof_class="autonomous_agent",
        expected_git_commit="a" * 40,
        trusted_fingerprint=key["fingerprint"],
    )

    assert result["status"] == "blocked"
    assert result["errors"] == [
        "artifact.runtime.log.size_mismatch",
        "artifact.runtime.log.sha256_mismatch",
    ]


def test_receipt_rejects_signature_tamper(tmp_path):
    receipt_path, _artifact, key = _write_receipt(tmp_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    signature = base64.b64decode(receipt["integrity"]["signature"])
    receipt["integrity"]["signature"] = base64.b64encode(bytes([signature[0] ^ 1]) + signature[1:]).decode("ascii")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = verify_proof_receipt(
        receipt_path,
        expected_proof_class="autonomous_agent",
        expected_git_commit="a" * 40,
        trusted_fingerprint=key["fingerprint"],
    )

    assert result["status"] == "blocked"
    assert "receipt.signature_invalid" in result["errors"]


def test_receipt_rejects_wrong_class_commit_and_trust_root(tmp_path):
    receipt_path, _artifact, _key = _write_receipt(tmp_path)

    result = verify_proof_receipt(
        receipt_path,
        expected_proof_class="real_detonation",
        expected_git_commit="b" * 40,
        trusted_fingerprint="0" * 64,
    )

    assert result["status"] == "blocked"
    assert result["errors"] == [
        "receipt.proof_class_mismatch",
        "receipt.git_commit_mismatch",
        "receipt.untrusted_signer",
    ]


def test_cryptographically_valid_blocked_receipt_does_not_pass(tmp_path):
    receipt_path, _artifact, key = _write_receipt(tmp_path, status="blocked")

    result = verify_proof_receipt(
        receipt_path,
        expected_proof_class="autonomous_agent",
        expected_git_commit="a" * 40,
        trusted_fingerprint=key["fingerprint"],
    )

    assert result["status"] == "blocked"
    assert result["errors"] == ["receipt.status.blocked"]


def test_beta_verifier_rejects_local_development_receipt(tmp_path):
    receipt_path, _artifact, key = _write_receipt(
        tmp_path,
        deployment_profile="local_dev",
    )

    result = verify_proof_receipt(
        receipt_path,
        expected_proof_class="autonomous_agent",
        expected_git_commit="a" * 40,
        trusted_fingerprint=key["fingerprint"],
    )

    assert result["status"] == "blocked"
    assert result["errors"] == ["receipt.deployment_profile_mismatch"]
