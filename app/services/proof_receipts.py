"""Signed beta proof receipts with pinned trust and artifact verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROOF_SCHEMA_VERSION = "sheshnaag.beta-proof.v1"
PROOF_CLASSES = frozenset(
    {
        "real_detonation",
        "ai_provider_matrix",
        "capability_audit",
        "stix_taxii",
        "autonomous_agent",
        "load_rehearsal",
    }
)
PROOF_STATUSES = frozenset({"passed", "blocked", "failed"})
MAX_RECEIPT_BYTES = 1024 * 1024


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _public_material(private_key: Ed25519PrivateKey) -> tuple[bytes, str]:
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public_raw, hashlib.sha256(public_raw).hexdigest()


def generate_proof_key(path: str | Path) -> dict[str, str]:
    """Create or load a local Ed25519 proof key and return public metadata."""

    key_path = Path(path)
    if key_path.exists():
        private_key = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    else:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(private_raw)
        os.chmod(key_path, 0o600)

    public_raw, fingerprint = _public_material(private_key)
    return {
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "fingerprint": fingerprint,
        "key_path": str(key_path),
    }


def _artifact_record(path: Path, *, base_dir: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"proof_artifact_symlink:{path}")
    resolved_base = base_dir.resolve()
    resolved = path.resolve(strict=True)
    try:
        relative = resolved.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError(f"proof_artifact_outside_base:{path}") from exc
    if not resolved.is_file():
        raise ValueError(f"proof_artifact_not_file:{path}")
    return {
        "path": relative.as_posix(),
        "sha256": _sha256_file(resolved),
        "byte_size": resolved.stat().st_size,
    }


def build_signed_receipt(
    *,
    proof_class: str,
    status: str,
    subject: Mapping[str, Any],
    checks: Iterable[Mapping[str, Any]],
    artifact_paths: Iterable[str | Path],
    base_dir: str | Path,
    private_key_path: str | Path,
    issuer: str,
    issued_at: str,
) -> dict[str, Any]:
    """Build one signed receipt for one bounded proof class."""

    if proof_class not in PROOF_CLASSES:
        raise ValueError(f"unknown_proof_class:{proof_class}")
    if status not in PROOF_STATUSES:
        raise ValueError(f"invalid_proof_status:{status}")
    if not issuer.strip():
        raise ValueError("proof_issuer_required")
    if not issued_at.endswith("Z"):
        raise ValueError("proof_issued_at_must_be_utc")

    check_rows = [dict(check) for check in checks]
    if not check_rows:
        raise ValueError("proof_checks_required")
    if status == "passed" and any(row.get("status") != "passed" for row in check_rows):
        raise ValueError("passed_receipt_contains_nonpassing_check")

    root = Path(base_dir)
    artifacts = [
        _artifact_record(Path(path), base_dir=root)
        for path in artifact_paths
    ]
    if not artifacts:
        raise ValueError("proof_artifacts_required")

    body: dict[str, Any] = {
        "schema_version": PROOF_SCHEMA_VERSION,
        "proof_class": proof_class,
        "status": status,
        "subject": dict(subject),
        "checks": check_rows,
        "artifacts": artifacts,
        "issuer": issuer.strip(),
        "issued_at": issued_at,
    }
    canonical = _canonical_json(body)
    private_key = Ed25519PrivateKey.from_private_bytes(Path(private_key_path).read_bytes())
    public_raw, fingerprint = _public_material(private_key)
    body["integrity"] = {
        "algorithm": "ed25519",
        "payload_sha256": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "key_fingerprint": fingerprint,
        "signature": base64.b64encode(private_key.sign(canonical)).decode("ascii"),
    }
    return body


def _blocked(errors: list[str], *, proof_class: str | None = None, artifact_count: int = 0) -> dict[str, Any]:
    return {
        "status": "blocked",
        "errors": errors,
        "proof_class": proof_class,
        "artifact_count": artifact_count,
    }


def verify_proof_receipt(
    receipt_path: str | Path,
    *,
    expected_proof_class: str,
    expected_git_commit: str,
    trusted_fingerprint: str,
    expected_deployment_profile: str = "design_partner_beta",
) -> dict[str, Any]:
    """Verify receipt trust, subject, signature, and every evidence artifact."""

    path = Path(receipt_path)
    errors: list[str] = []
    try:
        if path.is_symlink():
            return _blocked(["receipt.symlink_not_allowed"])
        raw = path.read_bytes()
        if len(raw) > MAX_RECEIPT_BYTES:
            return _blocked(["receipt.too_large"])
        receipt = json.loads(raw)
        if not isinstance(receipt, dict):
            return _blocked(["receipt.not_object"])
    except (OSError, json.JSONDecodeError) as exc:
        return _blocked([f"receipt.unreadable.{exc.__class__.__name__}"])

    proof_class = receipt.get("proof_class")
    artifacts = receipt.get("artifacts")
    artifact_count = len(artifacts) if isinstance(artifacts, list) else 0

    if receipt.get("schema_version") != PROOF_SCHEMA_VERSION:
        errors.append("receipt.schema_version")
    if proof_class != expected_proof_class:
        errors.append("receipt.proof_class_mismatch")
    subject = receipt.get("subject")
    if not isinstance(subject, dict) or subject.get("git_commit") != expected_git_commit:
        errors.append("receipt.git_commit_mismatch")
    if (
        not isinstance(subject, dict)
        or subject.get("deployment_profile") != expected_deployment_profile
    ):
        errors.append("receipt.deployment_profile_mismatch")

    integrity = receipt.get("integrity")
    if not isinstance(integrity, dict):
        return _blocked(errors + ["receipt.integrity_missing"], proof_class=proof_class, artifact_count=artifact_count)
    if integrity.get("key_fingerprint") != trusted_fingerprint:
        errors.append("receipt.untrusted_signer")
    if receipt.get("status") != "passed":
        errors.append(f"receipt.status.{receipt.get('status', 'missing')}")

    body = {key: value for key, value in receipt.items() if key != "integrity"}
    canonical = _canonical_json(body)
    expected_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if integrity.get("payload_sha256") != expected_digest:
        errors.append("receipt.payload_digest_mismatch")

    try:
        public_raw = base64.b64decode(integrity.get("public_key", ""), validate=True)
        actual_fingerprint = hashlib.sha256(public_raw).hexdigest()
        if actual_fingerprint != integrity.get("key_fingerprint"):
            errors.append("receipt.public_key_fingerprint_mismatch")
        signature = base64.b64decode(integrity.get("signature", ""), validate=True)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, canonical)
    except (ValueError, TypeError, InvalidSignature):
        errors.append("receipt.signature_invalid")

    if not isinstance(artifacts, list) or not artifacts:
        errors.append("receipt.artifacts_missing")
    else:
        base_dir = path.parent.resolve()
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                errors.append("artifact.invalid_record")
                continue
            name = str(artifact.get("path", "missing"))
            relative = Path(name)
            error_prefix = f"artifact.{name}"
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"{error_prefix}.path_invalid")
                continue
            candidate = base_dir / relative
            if candidate.is_symlink():
                errors.append(f"{error_prefix}.symlink_not_allowed")
                continue
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(base_dir)
            except (OSError, ValueError):
                errors.append(f"{error_prefix}.missing_or_outside")
                continue
            if not resolved.is_file():
                errors.append(f"{error_prefix}.not_file")
                continue
            if resolved.stat().st_size != artifact.get("byte_size"):
                errors.append(f"{error_prefix}.size_mismatch")
            if _sha256_file(resolved) != artifact.get("sha256"):
                errors.append(f"{error_prefix}.sha256_mismatch")

    if errors:
        return _blocked(errors, proof_class=proof_class, artifact_count=artifact_count)
    return {
        "status": "ok",
        "errors": [],
        "proof_class": proof_class,
        "artifact_count": artifact_count,
    }
