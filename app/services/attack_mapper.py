"""Deterministic ATT&CK technique mapping for behavior findings.

The mapper produces ``BehaviorFinding.payload.attack_techniques`` entries
through three paths, in order:

1. Deterministic rules over the raw telemetry payload (always on).
2. The bundled MITRE ATT&CK metadata in
   ``app/data/attack/enterprise-attack.json`` (refreshable via
   ``scripts/v4/fetch_attack_data.py``).
3. An optional LLM fallback (``llm_fallback=True``), gated on
   ``ATTACK_MAPPER_LLM_PROVIDER`` so beta tests stay deterministic by
   default.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

from app.models.malware_lab import BehaviorFinding
from app.models.sheshnaag import LabRun

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TechniqueMatch:
    technique_id: str
    confidence: float
    source: str
    rationale: str
    tactic: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "confidence": self.confidence,
            "source": self.source,
            "rationale": self.rationale,
            "tactic": self.tactic,
        }


_ATTACK_BUNDLE_PATH = Path(__file__).resolve().parents[1] / "data" / "attack" / "enterprise-attack.json"


def _load_bundle() -> dict[str, str]:
    """Return ``technique_id -> tactic`` from the bundled ATT&CK metadata."""

    try:
        if not _ATTACK_BUNDLE_PATH.exists():
            return {}
        bundle = json.loads(_ATTACK_BUNDLE_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to load ATT&CK bundle from %s: %s", _ATTACK_BUNDLE_PATH, exc)
        return {}
    return {
        str(item["technique_id"]): str(item.get("tactic") or "Unknown")
        for item in bundle.get("techniques", [])
        if item.get("technique_id")
    }


# Bundled tactic lookup overrides the prior hardcoded map and falls back to
# the original literal table when the bundle is missing.
_BUNDLED_TACTICS = _load_bundle()
_FALLBACK_TACTICS = {
    "T1055": "Defense Evasion",
    "T1055.008": "Defense Evasion",
    "T1055.012": "Defense Evasion",
    "T1059.001": "Execution",
    "T1059.004": "Execution",
    "T1071.001": "Command and Control",
    "T1071.004": "Command and Control",
    "T1105": "Command and Control",
    "T1547.001": "Persistence",
}
TECHNIQUE_TACTICS = {**_FALLBACK_TACTICS, **_BUNDLED_TACTICS}


class AttackMapper:
    """Attach MITRE ATT&CK technique tags to V4 behavior findings."""

    def __init__(self, session: Session, *, llm_fallback: Optional[bool] = None) -> None:
        self.session = session
        # ``llm_fallback`` defaults to the env var so production can flip the
        # toggle without redeploying. Tests pass ``llm_fallback=False``
        # explicitly to keep mapping deterministic.
        if llm_fallback is None:
            llm_fallback = os.getenv("ATTACK_MAPPER_LLM_FALLBACK", "").strip().lower() in {"1", "true", "yes"}
        self.llm_fallback = bool(llm_fallback)

    def map_finding(self, finding: BehaviorFinding) -> list[dict[str, Any]]:
        matches = [item.to_dict() for item in self._rule_matches(finding)]
        if matches or not self.llm_fallback:
            return self._dedupe(matches)

        # LLM fallback: only fires when rule matches were empty AND the
        # operator opted in. The fallback summarises the finding payload
        # via the configured ATT&CK mapper provider and parses out
        # technique IDs from a JSON-only response. Failures keep the empty
        # match set so callers degrade to "no mapping" rather than a hard
        # error.
        try:
            llm_matches = self._llm_match_finding(finding)
        except Exception as exc:  # pragma: no cover - depends on provider
            logger.warning("LLM fallback failed for finding %s: %s", finding.id, exc)
            llm_matches = []
        return self._dedupe(llm_matches)

    def _llm_match_finding(self, finding: BehaviorFinding) -> list[dict[str, Any]]:
        provider = os.getenv("ATTACK_MAPPER_LLM_PROVIDER", "").strip().lower()
        if not provider:
            return []
        try:
            from app.services.ai_provider_harness import AIProviderHarness
        except Exception:
            return []
        harness = AIProviderHarness()

        prompt = (
            "You map malware-lab behavior findings to MITRE ATT&CK techniques.\n"
            "Return JSON only: {\"techniques\": [{\"technique_id\": \"T...\", \"confidence\": 0..1, \"rationale\": \"...\"}]}\n"
            "Use only techniques in the supplied bundle. Reply with empty list when uncertain.\n\n"
            f"Finding type: {finding.finding_type}\n"
            f"Title: {finding.title}\n"
            f"Severity: {finding.severity}\n"
            f"Payload: {json.dumps(finding.payload or {}, default=str, sort_keys=True)[:2000]}\n"
        )
        grounding = {
            "items": [
                {
                    "kind": "attack_bundle",
                    "title": "MITRE ATT&CK technique catalog",
                    "summary": ", ".join(sorted(TECHNIQUE_TACTICS.keys())[:50]),
                }
            ]
        }
        try:
            response = harness.run(
                provider_key=provider,
                capability="attack_mapping",
                prompt=prompt,
                grounding=grounding,
            )
        except Exception as exc:  # pragma: no cover - depends on provider
            logger.warning("AIProviderHarness.run failed: %s", exc)
            return []
        text = ((response or {}).get("draft") or {}).get("text") or response.get("text") or ""
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            return []
        out: list[dict[str, Any]] = []
        for item in (parsed.get("techniques") or [])[:10]:
            technique_id = str(item.get("technique_id") or "").strip()
            if not technique_id or technique_id not in TECHNIQUE_TACTICS:
                continue
            out.append(
                {
                    "technique_id": technique_id,
                    "confidence": float(item.get("confidence") or 0.5),
                    "source": f"llm:{provider}",
                    "rationale": str(item.get("rationale") or "")[:280],
                    "tactic": TECHNIQUE_TACTICS.get(technique_id, "Unknown"),
                }
            )
        return out

    def map_run(self, run: LabRun) -> None:
        findings = (
            self.session.query(BehaviorFinding)
            .filter(BehaviorFinding.tenant_id == run.tenant_id, BehaviorFinding.run_id == run.id)
            .all()
        )
        for finding in findings:
            mapped = self.map_finding(finding)
            if not mapped:
                continue
            payload = dict(finding.payload or {})
            existing = payload.get("attack_techniques") or []
            payload["attack_techniques"] = self._dedupe([*self._normalize(existing), *mapped])
            finding.payload = payload
        self.session.flush()

    def _rule_matches(self, finding: BehaviorFinding) -> Iterable[TechniqueMatch]:
        payload = finding.payload or {}
        raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
        finding_type = (finding.finding_type or "").lower()
        title = (finding.title or "").lower()
        source = str(payload.get("source") or "").lower()
        plugin = str(payload.get("plugin") or raw.get("plugin") or "").lower()
        syscall = str(raw.get("syscall") or raw.get("type") or "").lower()
        command = " ".join(
            str(raw.get(key) or "") for key in ("command", "cmdline", "process", "path", "argv", "args")
        ).lower()
        rule_name = str(raw.get("rule") or raw.get("name") or "").lower()

        if source == "volatility" or finding_type.startswith("memory:"):
            if "malfind" in plugin or "malfind" in finding_type:
                yield self._match("T1055.012", 0.9, "rule", "Volatility malfind indicates process hollowing/injection.")
            if "hollowfind" in plugin or "hollowfind" in finding_type:
                yield self._match("T1055.012", 0.88, "rule", "Volatility hollowfind indicates process hollowing.")
            if "netscan" in plugin or "netscan" in finding_type:
                yield self._match("T1071.001", 0.72, "rule", "Memory network artifact suggests web protocol C2.")

        if source == "ebpf" or finding_type.startswith("ebpf:"):
            if "ptrace" in syscall or "ptrace" in finding_type:
                yield self._match("T1055.008", 0.82, "rule", "ptrace attach behavior maps to ptrace system call injection.")
            if "execve" in syscall or "exec" in finding_type:
                if "powershell" in command or " -enc" in command or " -encodedcommand" in command:
                    yield self._match("T1059.001", 0.8, "rule", "Encoded PowerShell execution maps to PowerShell command interpreter.")
                if any(shell in command for shell in ("bash", "/sh", " zsh", "python -c", "perl -e")):
                    yield self._match("T1059.004", 0.74, "rule", "Shell interpreter execution maps to Unix shell.")
            if "connect" in syscall or "network" in title:
                yield self._match("T1071.001", 0.64, "rule", "Runtime network activity maps to application-layer C2.")

        if source == "yara" or finding_type == "static:yara":
            technique = "T1055" if "shellcode" in rule_name or "cobalt" in rule_name else "T1105"
            yield self._match(technique, 0.66, "rule", "Static YARA hit maps to known malware capability.")

        if "dns" in finding_type or "beacon" in title:
            yield self._match("T1071.004", 0.62, "rule", "Beaconing or DNS behavior maps to DNS application-layer C2.")

    def _match(self, technique_id: str, confidence: float, source: str, rationale: str) -> TechniqueMatch:
        return TechniqueMatch(
            technique_id=technique_id,
            confidence=confidence,
            source=source,
            rationale=rationale,
            tactic=TECHNIQUE_TACTICS.get(technique_id, "Unknown"),
        )

    @staticmethod
    def _normalize(items: Any) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        if not isinstance(items, list):
            return normalized
        for item in items:
            if isinstance(item, str):
                normalized.append(
                    {
                        "technique_id": item,
                        "confidence": 0.5,
                        "source": "legacy",
                        "rationale": "Existing string technique tag.",
                        "tactic": TECHNIQUE_TACTICS.get(item, "Unknown"),
                    }
                )
            elif isinstance(item, dict) and item.get("technique_id"):
                technique_id = str(item["technique_id"])
                normalized.append(
                    {
                        **item,
                        "technique_id": technique_id,
                        "confidence": float(item.get("confidence") or 0.5),
                        "tactic": str(item.get("tactic") or TECHNIQUE_TACTICS.get(technique_id, "Unknown")),
                    }
                )
        return normalized

    @classmethod
    def _dedupe(cls, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id: dict[str, dict[str, Any]] = {}
        for item in cls._normalize(items):
            technique_id = str(item["technique_id"])
            if technique_id not in by_id or float(item.get("confidence") or 0) > float(by_id[technique_id].get("confidence") or 0):
                by_id[technique_id] = item
        return list(by_id.values())
