"""Unit tests for the bundled MITRE ATT&CK metadata."""

from __future__ import annotations

import json
from pathlib import Path

from app.services.attack_mapper import TECHNIQUE_TACTICS, _ATTACK_BUNDLE_PATH


def test_bundle_file_exists():
    assert _ATTACK_BUNDLE_PATH.exists()


def test_bundle_techniques_have_required_fields():
    bundle = json.loads(_ATTACK_BUNDLE_PATH.read_text(encoding="utf-8"))
    techniques = bundle.get("techniques") or []
    assert techniques, "ATT&CK bundle must declare at least one technique"
    for record in techniques:
        assert record.get("technique_id"), record
        assert record.get("name"), record
        assert record.get("tactic"), record


def test_bundle_overrides_fallback_tactics():
    # The bundle provides tactic info for canonical techniques used by the
    # rule-based mapper.
    for tid in ("T1055", "T1059.001", "T1071.001", "T1547.001"):
        assert TECHNIQUE_TACTICS.get(tid)
