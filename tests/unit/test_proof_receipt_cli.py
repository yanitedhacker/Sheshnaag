"""Operator CLI tests for beta proof receipts."""

from __future__ import annotations

import json

import scripts.sheshnaag_proof_receipt as cli


def test_cli_keygen_create_and_verify_receipt(tmp_path, capsys):
    key_path = tmp_path / "proof.key"
    artifact = tmp_path / "runtime.log"
    receipt_path = tmp_path / "autonomous-agent.json"
    artifact.write_text("durable run id=42\n", encoding="utf-8")

    assert cli.main(["keygen", "--key", str(key_path)]) == 0
    key = json.loads(capsys.readouterr().out)

    assert cli.main(
        [
            "create",
            "--proof-class",
            "autonomous_agent",
            "--status",
            "passed",
            "--git-commit",
            "d" * 40,
            "--deployment-profile",
            "design_partner_beta",
            "--artifact",
            str(artifact),
            "--check",
            "durable_run=passed",
            "--key",
            str(key_path),
            "--issuer",
            "test-operator",
            "--issued-at",
            "2026-08-29T12:00:00Z",
            "--output",
            str(receipt_path),
        ]
    ) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["receipt_path"] == str(receipt_path)

    assert cli.main(
        [
            "verify",
            "--receipt",
            str(receipt_path),
            "--proof-class",
            "autonomous_agent",
            "--git-commit",
            "d" * 40,
            "--trusted-fingerprint",
            key["fingerprint"],
        ]
    ) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["status"] == "ok"


def test_cli_verify_returns_nonzero_for_tampered_artifact(tmp_path, capsys):
    key_path = tmp_path / "proof.key"
    artifact = tmp_path / "runtime.log"
    receipt_path = tmp_path / "agent.json"
    artifact.write_text("first\n", encoding="utf-8")
    cli.main(["keygen", "--key", str(key_path)])
    key = json.loads(capsys.readouterr().out)
    cli.main(
        [
            "create",
            "--proof-class",
            "autonomous_agent",
            "--git-commit",
            "e" * 40,
            "--deployment-profile",
            "design_partner_beta",
            "--artifact",
            str(artifact),
            "--check",
            "durable_run=passed",
            "--key",
            str(key_path),
            "--issuer",
            "test-operator",
            "--output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()
    artifact.write_text("changed\n", encoding="utf-8")

    result = cli.main(
        [
            "verify",
            "--receipt",
            str(receipt_path),
            "--proof-class",
            "autonomous_agent",
            "--git-commit",
            "e" * 40,
            "--trusted-fingerprint",
            key["fingerprint"],
        ]
    )

    assert result == 1
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
