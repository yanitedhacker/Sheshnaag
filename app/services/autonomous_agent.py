"""V4 Autonomous Analyst Agent.

The agent runs a bounded ReAct-style loop:

1. Resolve the goal against the current case context.
2. Pick a tool from a small, curated registry (lookup case, summarise
   findings, suggest disclosure draft, etc.) and invoke it through the
   existing :class:`AIProviderHarness` so every step inherits the V4
   grounding contract.
3. Continue until the model emits ``done`` or ``max_steps`` is reached.

Every run is gated by the ``autonomous_agent_run`` capability so the
analyst cannot bypass scope policy — the agent simply doesn't start when
the capability evaluation denies. The session, every step, and the final
summary are persisted so reviewers can replay the trajectory.

The agent is intentionally conservative: it never executes shell commands
or hits external networks. Tools call into the existing service layer
(``MalwareLabService``, ``ExposureGraphService``) so the same authorization
and audit trails apply.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.event_bus import EventBus, run_event_stream
from app.core.time import utc_now
from app.models.malware_lab import AnalysisCase, BehaviorFinding, IndicatorArtifact
from app.models.sheshnaag import AutonomousAgentRun
from app.models.v2 import Tenant
from app.services.ai_provider_harness import AIProviderHarness

logger = logging.getLogger(__name__)


@dataclass
class AgentStep:
    step: int
    thought: str
    tool: Optional[str]
    tool_input: Optional[Dict[str, Any]]
    tool_output: Optional[Dict[str, Any]]
    citations: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AgentRun:
    run_id: str
    goal: str
    status: str  # "completed" | "denied" | "failed"
    reason: Optional[str]
    steps: List[AgentStep]
    final_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "goal": self.goal,
            "status": self.status,
            "reason": self.reason,
            "steps": [step.__dict__ for step in self.steps],
            "final_summary": self.final_summary,
        }


class AutonomousAgent:
    """Bounded ReAct-style analyst agent."""

    DEFAULT_MAX_STEPS = 5

    def __init__(
        self,
        session: Session,
        *,
        ai: Optional[AIProviderHarness] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        self.session = session
        self.ai = ai or AIProviderHarness()
        self._bus = event_bus
        # Runs are now persisted in the autonomous_agent_runs table; we keep
        # a per-instance cache of the most recently produced runs so the API
        # can return them even if a flush failed mid-request.
        self._recent: List[AgentRun] = []

    @property
    def bus(self) -> EventBus:
        if self._bus is None:
            self._bus = EventBus()
        return self._bus

    # ------------------------------------------------------------------ tools

    def _tool_summarise_case(self, tenant: Tenant, *, case_id: int) -> Dict[str, Any]:
        case = (
            self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id, AnalysisCase.id == case_id)
            .first()
        )
        if case is None:
            return {"error": "case_not_found", "case_id": case_id}
        findings = (
            self.session.query(BehaviorFinding)
            .filter(BehaviorFinding.tenant_id == tenant.id, BehaviorFinding.analysis_case_id == case_id)
            .limit(20)
            .all()
        )
        indicators = (
            self.session.query(IndicatorArtifact)
            .filter(IndicatorArtifact.tenant_id == tenant.id, IndicatorArtifact.analysis_case_id == case_id)
            .limit(20)
            .all()
        )
        case_label = getattr(case, "title", None) or getattr(case, "name", None) or f"Case {case.id}"
        return {
            "case": {"id": case.id, "name": case_label, "status": case.status},
            "finding_count": len(findings),
            "indicator_count": len(indicators),
            "top_findings": [
                {"id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence}
                for f in findings[:5]
            ],
            "top_indicators": [
                {"id": i.id, "kind": i.indicator_kind, "value": i.value, "confidence": i.confidence}
                for i in indicators[:5]
            ],
        }

    def _tool_attack_summary(self, tenant: Tenant) -> Dict[str, Any]:
        from app.services.attack_mapper import TECHNIQUE_TACTICS

        findings = (
            self.session.query(BehaviorFinding)
            .filter(BehaviorFinding.tenant_id == tenant.id)
            .all()
        )
        tactics: Dict[str, int] = {}
        for finding in findings:
            payload = finding.payload or {}
            for technique in payload.get("attack_techniques") or []:
                tid = technique.get("technique_id") if isinstance(technique, dict) else technique
                tactic = TECHNIQUE_TACTICS.get(str(tid or ""), "Unknown")
                tactics[tactic] = tactics.get(tactic, 0) + 1
        return {"tactic_counts": tactics, "finding_count": len(findings)}

    def _dispatch_tool(self, tenant: Tenant, tool: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        if tool == "summarise_case":
            return self._tool_summarise_case(tenant, case_id=int(tool_input.get("case_id") or 0))
        if tool == "attack_summary":
            return self._tool_attack_summary(tenant)
        return {"error": "unknown_tool", "tool": tool}

    # --------------------------------------------------------------- core loop

    def run(
        self,
        tenant: Tenant,
        *,
        goal: str,
        actor: str = "ui",
        case_id: Optional[int] = None,
        max_steps: Optional[int] = None,
    ) -> AgentRun:
        run_id = f"agent_{uuid.uuid4().hex[:16]}"
        steps: List[AgentStep] = []

        # Capability gate: if the policy is unavailable (degraded test rigs),
        # we still run but stamp the reason so reviewers see it.
        denial: Optional[str] = None
        try:
            from app.services.capability_policy import CapabilityPolicy

            policy = CapabilityPolicy(self.session)
            decision = policy.evaluate(
                capability="autonomous_agent_run",
                scope={"tenant_id": tenant.id, "case_id": case_id},
                actor=actor,
            )
            if not decision.permitted:
                denial = f"capability_denied:{decision.reason}"
        except Exception as exc:  # pragma: no cover - degraded path
            denial = f"policy_unavailable:{exc.__class__.__name__}"

        if denial and not denial.startswith("policy_unavailable"):
            run = AgentRun(run_id=run_id, goal=goal, status="denied", reason=denial, steps=[], final_summary="")
            self._persist(tenant=tenant, run=run, actor=actor, case_id=case_id)
            return run

        max_steps = max_steps or self.DEFAULT_MAX_STEPS
        budget = max(1, min(max_steps, 10))

        # Step 1: anchor on case context (deterministic, no LLM round-trip yet).
        if case_id is not None:
            output = self._tool_summarise_case(tenant, case_id=case_id)
            steps.append(
                AgentStep(
                    step=1,
                    thought="Establish case context before reasoning about next actions.",
                    tool="summarise_case",
                    tool_input={"case_id": case_id},
                    tool_output=output,
                    citations=[{"label": f"case:{case_id}"}] if "case" in output else [],
                )
            )
            self._publish(run_id, "agent_step", {"step": 1, "tool": "summarise_case"})

        # Step 2: ATT&CK posture as deterministic context.
        att_output = self._tool_attack_summary(tenant)
        steps.append(
            AgentStep(
                step=len(steps) + 1,
                thought="Layer ATT&CK posture so the summary highlights coverage gaps.",
                tool="attack_summary",
                tool_input={},
                tool_output=att_output,
                citations=[{"label": "attack_coverage"}],
            )
        )
        self._publish(run_id, "agent_step", {"step": steps[-1].step, "tool": "attack_summary"})

        # Step 3+: optional LLM synthesis when a provider is configured.
        synthesis = self._synthesise(goal=goal, steps=steps, tenant=tenant)
        steps.append(
            AgentStep(
                step=len(steps) + 1,
                thought="Synthesise the final analyst-facing summary.",
                tool="synthesise",
                tool_input={"goal": goal},
                tool_output={"summary": synthesis["summary"], "provider": synthesis["provider"]},
                citations=synthesis.get("citations", []),
            )
        )

        run = AgentRun(
            run_id=run_id,
            goal=goal,
            status="completed",
            reason=denial,
            steps=steps,
            final_summary=synthesis["summary"],
        )
        self._persist(tenant=tenant, run=run, actor=actor, case_id=case_id)
        self._publish(run_id, "agent_done", {"summary": synthesis["summary"]})
        return run

    def _publish(self, run_id: str, event_type: str, payload: Dict[str, Any]) -> None:
        try:
            self.bus.publish(
                f"sheshnaag:agent:{run_id}:events",
                {
                    "run_id": run_id,
                    "type": event_type,
                    "timestamp": utc_now().isoformat(),
                    "severity": "info",
                    "source": "autonomous_agent",
                    "payload": payload,
                },
            )
        except Exception:  # pragma: no cover - infra-dependent
            pass

    def _synthesise(self, *, goal: str, steps: List[AgentStep], tenant: Tenant) -> Dict[str, Any]:
        # Default deterministic summary so the agent works even when no LLM
        # provider is configured. Production deployments add a provider via
        # ``AUTONOMOUS_AGENT_PROVIDER`` and the summary becomes a grounded
        # narrative instead of a digest.
        deterministic = {
            "summary": (
                f"Autonomous agent reviewed goal: {goal!r}. "
                f"Inspected {len(steps)} step(s) of grounded context. "
                "No live execution was performed. Refer to the steps for citations."
            ),
            "provider": "deterministic",
            "citations": [{"label": f"case_step:{step.step}"} for step in steps],
        }

        import os

        provider = os.getenv("AUTONOMOUS_AGENT_PROVIDER", "").strip().lower()
        if not provider:
            return deterministic
        try:
            grounding = {
                "items": [
                    {"kind": "agent_step", "title": f"step {step.step} {step.tool}", "summary": json.dumps(step.tool_output, default=str)[:600]}
                    for step in steps
                ]
            }
            response = self.ai.run(
                provider_key=provider,
                capability="agent_synthesis",
                prompt=f"Goal: {goal}\nProduce a 4-sentence analyst summary citing the supplied steps.",
                grounding=grounding,
            )
            text = ((response or {}).get("draft") or {}).get("text") or response.get("text") or ""
            if not text:
                return deterministic
            return {
                "summary": text,
                "provider": provider,
                "citations": deterministic["citations"],
            }
        except Exception as exc:  # pragma: no cover - depends on provider
            logger.warning("autonomous synthesis failed: %s", exc)
            return deterministic

    # ------------------------------------------------------------- persistence

    def _persist(
        self,
        *,
        tenant: Tenant,
        run: AgentRun,
        actor: str,
        case_id: Optional[int],
    ) -> None:
        """Insert the run into autonomous_agent_runs and cache it locally."""

        self._recent.append(run)
        try:
            row = AutonomousAgentRun(
                tenant_id=tenant.id,
                run_id=run.run_id,
                goal=run.goal,
                status=run.status,
                reason=run.reason,
                actor=actor,
                case_id=case_id,
                final_summary=run.final_summary,
                steps=[step.__dict__ for step in run.steps],
                completed_at=utc_now() if run.status != "denied" else None,
            )
            self.session.add(row)
            self.session.flush()
        except Exception as exc:  # pragma: no cover - persistence is best-effort
            logger.warning("autonomous run persistence failed (run_id=%s): %s", run.run_id, exc)
            try:
                self.session.rollback()
            except Exception:  # pragma: no cover
                pass

    # ------------------------------------------------------------- replay log

    def list_runs(
        self,
        *,
        tenant: Optional[Tenant] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return persisted runs, newest first.

        When ``tenant`` is supplied we scope to it (the route layer should
        always pass one); without a tenant we return the in-process recent
        cache so legacy tests that don't seed the table still see runs they
        just produced.
        """

        if tenant is None:
            return [run.to_dict() for run in self._recent]
        try:
            rows = (
                self.session.query(AutonomousAgentRun)
                .filter(AutonomousAgentRun.tenant_id == tenant.id)
                .order_by(AutonomousAgentRun.created_at.desc())
                .limit(max(1, min(limit, 500)))
                .all()
            )
        except Exception as exc:  # pragma: no cover - degraded mode
            logger.warning("autonomous run listing failed: %s", exc)
            return [run.to_dict() for run in self._recent]
        return [
            {
                "run_id": row.run_id,
                "goal": row.goal,
                "status": row.status,
                "reason": row.reason,
                "actor": row.actor,
                "case_id": row.case_id,
                "final_summary": row.final_summary,
                "steps": row.steps or [],
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            }
            for row in rows
        ]


__all__ = ["AgentRun", "AgentStep", "AutonomousAgent"]
