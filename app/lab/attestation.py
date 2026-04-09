"""Attestation helpers for run and bundle manifests."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict

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
