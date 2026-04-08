"""Attestation helpers for run and bundle manifests."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from app.lab.interfaces import AttestationSigner


class HashAttestationSigner(AttestationSigner):
    """Simple deterministic signer for local-first manifests."""

    def sign(self, *, payload: Dict[str, Any], signer: str) -> Dict[str, str]:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return {
            "sha256": digest,
            "signature": f"local-sha256:{digest}",
            "signer": signer,
        }
