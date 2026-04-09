"""Attestation helpers for run and bundle manifests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.config import settings
from app.lab.interfaces import AttestationSigner


class HashAttestationSigner(AttestationSigner):
    """Deterministic local signer with a pluggable dev backend."""

    def sign(self, *, payload: Dict[str, Any], signer: str) -> Dict[str, str]:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        backend = "hmac-sha256" if settings.secret_key else "local-sha256"
        if settings.secret_key:
            signature_digest = hmac.new(
                settings.secret_key.encode("utf-8"),
                serialized.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            signature = f"hmac-sha256:{signature_digest}"
        else:
            signature = f"local-sha256:{digest}"
        return {
            "sha256": digest,
            "signature": signature,
            "signer": signer,
            "algorithm": "sha256",
            "backend": backend,
        }

    def verify(self, *, payload: Dict[str, Any], signature: str) -> bool:
        """Verify a previously produced signature."""
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        if signature == f"local-sha256:{digest}":
            return True
        if settings.secret_key and signature.startswith("hmac-sha256:"):
            expected = hmac.new(
                settings.secret_key.encode("utf-8"),
                serialized.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(signature.split(":", 1)[1], expected)
        return False


class Ed25519AttestationSigner(AttestationSigner):
    """Local file-backed Ed25519 signer for provenance-rich manifests."""

    def __init__(self, *, private_key_path: str, public_key: str, fingerprint: str) -> None:
        self.private_key_path = private_key_path
        self.public_key = public_key
        self.fingerprint = fingerprint

    @staticmethod
    def ensure_key_material(private_key_path: str) -> Dict[str, str]:
        path = Path(private_key_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raw_private = path.read_bytes()
            private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
        else:
            private_key = Ed25519PrivateKey.generate()
            raw_private = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            path.write_bytes(raw_private)

        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "public_key": base64.b64encode(public_raw).decode("ascii"),
            "fingerprint": hashlib.sha256(public_raw).hexdigest(),
            "key_path": str(path),
        }

    def sign(self, *, payload: Dict[str, Any], signer: str) -> Dict[str, str]:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        private_key = self._load_private_key()
        signature_raw = private_key.sign(serialized.encode("utf-8"))
        signature = f"ed25519:{base64.b64encode(signature_raw).decode('ascii')}"
        return {
            "sha256": digest,
            "signature": signature,
            "signer": signer,
            "algorithm": "ed25519",
            "backend": "local-ed25519",
            "fingerprint": self.fingerprint,
            "public_key": self.public_key,
        }

    def verify(self, *, payload: Dict[str, Any], signature: str) -> bool:
        if not signature.startswith("ed25519:"):
            return False
        serialized = json.dumps(payload, sort_keys=True, default=str)
        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key.encode("ascii")))
            public_key.verify(base64.b64decode(signature.split(":", 1)[1]), serialized.encode("utf-8"))
            return True
        except Exception:  # noqa: BLE001 - verification failures are expected control flow
            return False

    def _load_private_key(self) -> Ed25519PrivateKey:
        raw_private = Path(self.private_key_path).read_bytes()
        return Ed25519PrivateKey.from_private_bytes(raw_private)
