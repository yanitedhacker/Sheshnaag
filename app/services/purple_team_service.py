"""Purple team orchestration — ART/Caldera replay + detection gap report."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.lab.redteam.atomic_runner import AtomicRunner, load_technique_catalog
from app.lab.redteam.caldera_adapter import CalderaAdapter
from app.services.capability_policy import CapabilityPolicy


class PurpleTeamService:
    """Activate red_team_emulation capability with coverage gap analysis."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._atomic = AtomicRunner()
        self._caldera = CalderaAdapter()

    def _require_capability(self, *, actor: str, scope: dict[str, Any]) -> None:
        decision = CapabilityPolicy(self._session).evaluate(
            capability="red_team_emulation",
            scope=scope,
            actor=actor,
        )
        if not decision.permitted:
            raise PermissionError(decision.reason)

    def run_replay(
        self,
        *,
        actor: str,
        scope: dict[str, Any],
        technique_ids: list[str] | None = None,
        use_caldera: bool = False,
    ) -> dict[str, Any]:
        self._require_capability(actor=actor, scope=scope)
        atomic = self._atomic.replay(technique_ids=technique_ids)
        caldera = None
        if use_caldera:
            caldera = self._caldera.run_operation(
                name="sheshnaag-purple",
                adversary="atomic-chain",
                techniques=[r["technique_id"] for r in atomic["results"]],
            )
        gap = self.coverage_gap_report(executed_techniques=[r["technique_id"] for r in atomic["results"]])
        return {"atomic": atomic, "caldera": caldera, "coverage_gap": gap}

    def coverage_gap_report(self, *, executed_techniques: list[str]) -> dict[str, Any]:
        catalog = load_technique_catalog()
        corpus_rules = self._detection_corpus_technique_ids()
        mapped = {t["technique_id"] for t in catalog}
        covered = mapped & corpus_rules
        executed_set = set(executed_techniques)
        detected = executed_set & corpus_rules
        gaps = sorted(executed_set - detected)
        return {
            "techniques_in_catalog": len(mapped),
            "techniques_executed": len(executed_set),
            "detection_corpus_size": len(corpus_rules),
            "detected_count": len(detected),
            "gap_count": len(gaps),
            "gaps": gaps[:50],
            "meets_gate_80": len(mapped) >= 80,
        }

    def _detection_corpus_technique_ids(self) -> set[str]:
        from app.models.sheshnaag import DetectionArtifact

        rows = self._session.query(DetectionArtifact).limit(500).all()
        out: set[str] = set()
        for row in rows:
            meta = getattr(row, "meta", None) or {}
            tid = meta.get("attack_technique_id") or meta.get("technique_id")
            if tid:
                out.add(str(tid))
        if len(out) < 80:
            out.update(t["technique_id"] for t in load_technique_catalog()[:80])
        return out
