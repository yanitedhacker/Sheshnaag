"""Deterministic ATT&CK technique mapping for behavior findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.models.malware_lab import BehaviorFinding
from app.models.sheshnaag import LabRun


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


TECHNIQUE_TACTICS = {
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


class AttackMapper:
    """Attach MITRE ATT&CK technique tags to V4 behavior findings."""

    def __init__(self, session: Session, *, llm_fallback: bool = False) -> None:
        self.session = session
        self.llm_fallback = llm_fallback

    def map_finding(self, finding: BehaviorFinding) -> list[dict[str, Any]]:
        matches = [item.to_dict() for item in self._rule_matches(finding)]
        if matches or not self.llm_fallback:
            return self._dedupe(matches)

        # Intentionally conservative for beta: LLM fallback is opt-in and
        # tests keep it disabled so mapping remains deterministic.
        return []

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
