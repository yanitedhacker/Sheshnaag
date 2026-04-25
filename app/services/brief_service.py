"""Per-tenant scheduled briefing service.

Generates a structured snapshot for the period (default last 24h):

* counts of new indicators / findings / cases / autonomous-agent runs
* top severities and ATT&CK tactics seen in findings
* most-recent KEV-flagged CVEs ingested
* a short narrative summary suitable for dashboard rendering

The output is persisted as a `ScheduledBrief` row and returned. The
narrative is deterministic so the brief works without an LLM provider;
when ``BRIEF_LLM_PROVIDER`` is set we ask the harness for a polished
version, but the structured payload is always the source of truth.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
)
from app.models.sheshnaag import AutonomousAgentRun, ScheduledBrief
from app.models.v2 import KEVEntry, Tenant

logger = logging.getLogger(__name__)


class BriefService:
    """Build and persist tenant briefings."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def generate_brief(
        self,
        tenant: Tenant,
        *,
        brief_type: str = "daily",
        period_hours: int = 24,
    ) -> ScheduledBrief:
        period_end = utc_now()
        period_start = period_end - timedelta(hours=max(1, period_hours))

        new_indicators = (
            self.session.query(IndicatorArtifact)
            .filter(
                IndicatorArtifact.tenant_id == tenant.id,
                IndicatorArtifact.created_at >= period_start,
            )
            .order_by(desc(IndicatorArtifact.created_at))
            .all()
        )
        new_findings = (
            self.session.query(BehaviorFinding)
            .filter(
                BehaviorFinding.tenant_id == tenant.id,
                BehaviorFinding.created_at >= period_start,
            )
            .order_by(desc(BehaviorFinding.created_at))
            .all()
        )
        new_cases = (
            self.session.query(AnalysisCase)
            .filter(
                AnalysisCase.tenant_id == tenant.id,
                AnalysisCase.created_at >= period_start,
            )
            .order_by(desc(AnalysisCase.created_at))
            .all()
        )
        agent_runs = (
            self.session.query(AutonomousAgentRun)
            .filter(
                AutonomousAgentRun.tenant_id == tenant.id,
                AutonomousAgentRun.created_at >= period_start,
            )
            .order_by(desc(AutonomousAgentRun.created_at))
            .all()
        )

        severity_counts: Dict[str, int] = {}
        attack_techniques: Dict[str, int] = {}
        for f in new_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            for tech in (f.payload or {}).get("attack_techniques", []) or []:
                tid = tech.get("technique_id") if isinstance(tech, dict) else tech
                if tid:
                    attack_techniques[str(tid)] = attack_techniques.get(str(tid), 0) + 1

        recent_kev = (
            self.session.query(KEVEntry)
            .order_by(desc(KEVEntry.id))
            .limit(5)
            .all()
        )

        payload: Dict[str, Any] = {
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat(),
                "hours": period_hours,
            },
            "counts": {
                "new_indicators": len(new_indicators),
                "new_findings": len(new_findings),
                "new_cases": len(new_cases),
                "agent_runs": len(agent_runs),
            },
            "severity_counts": severity_counts,
            "top_attack_techniques": sorted(
                attack_techniques.items(), key=lambda kv: kv[1], reverse=True
            )[:10],
            "top_findings": [
                {"id": f.id, "title": f.title, "severity": f.severity, "case_id": f.analysis_case_id}
                for f in new_findings[:5]
            ],
            "top_cases": [
                {"id": c.id, "title": c.title, "status": c.status} for c in new_cases[:5]
            ],
            "agent_run_status": [
                {"run_id": r.run_id, "status": r.status, "goal": r.goal[:120]}
                for r in agent_runs[:5]
            ],
            "recent_kev_intel": [
                {
                    "cve_id": k.cve_id,
                    "vendor_project": k.vendor_project,
                    "product": k.product,
                }
                for k in recent_kev
            ],
        }

        narrative = self._build_narrative(tenant, payload)
        # Optional LLM polish (not required, never source of truth).
        provider = os.getenv("BRIEF_LLM_PROVIDER", "").strip().lower()
        if provider:
            try:
                from app.services.ai_provider_harness import AIProviderHarness

                grounding = {
                    "items": [
                        {
                            "kind": "brief_payload",
                            "title": "structured snapshot",
                            "summary": str(payload)[:1500],
                        }
                    ]
                }
                response = AIProviderHarness().run(
                    provider_key=provider,
                    capability="brief_summary",
                    prompt=(
                        "Produce a 3-sentence analyst brief from the supplied snapshot. "
                        "Cite numbers verbatim; do not invent IOCs."
                    ),
                    grounding=grounding,
                )
                text = ((response or {}).get("draft") or {}).get("text") or response.get("text") or ""
                if text:
                    narrative = text
            except Exception as exc:  # pragma: no cover - provider-dependent
                logger.warning("brief LLM polish failed: %s", exc)

        row = ScheduledBrief(
            tenant_id=tenant.id,
            brief_type=brief_type,
            summary=narrative,
            payload=payload,
            generated_at=period_end,
            period_start=period_start,
            period_end=period_end,
        )
        self.session.add(row)
        self.session.flush()
        return row

    @staticmethod
    def _build_narrative(tenant: Tenant, payload: Dict[str, Any]) -> str:
        c = payload["counts"]
        sev = payload["severity_counts"]
        sev_summary = ", ".join(f"{k}:{v}" for k, v in sorted(sev.items())) or "no new findings"
        top = payload.get("top_attack_techniques") or []
        attack_str = (
            "Top ATT&CK: " + ", ".join(f"{tid}({n})" for tid, n in top[:3])
            if top
            else "No ATT&CK techniques observed"
        )
        return (
            f"Tenant {tenant.slug}: {c['new_cases']} new cases, "
            f"{c['new_findings']} findings ({sev_summary}), "
            f"{c['new_indicators']} indicators, {c['agent_runs']} autonomous-agent runs "
            f"in the last {payload['period']['hours']}h. {attack_str}."
        )

    # -------------------------------------------------------------- read APIs

    def latest(self, tenant: Tenant, *, brief_type: Optional[str] = None) -> Optional[ScheduledBrief]:
        q = self.session.query(ScheduledBrief).filter(ScheduledBrief.tenant_id == tenant.id)
        if brief_type:
            q = q.filter(ScheduledBrief.brief_type == brief_type)
        return q.order_by(desc(ScheduledBrief.generated_at)).first()

    def list_briefs(
        self,
        tenant: Tenant,
        *,
        limit: int = 20,
        brief_type: Optional[str] = None,
    ) -> List[ScheduledBrief]:
        q = self.session.query(ScheduledBrief).filter(ScheduledBrief.tenant_id == tenant.id)
        if brief_type:
            q = q.filter(ScheduledBrief.brief_type == brief_type)
        return q.order_by(desc(ScheduledBrief.generated_at)).limit(max(1, min(limit, 200))).all()


def serialize_brief(row: ScheduledBrief) -> Dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "brief_type": row.brief_type,
        "summary": row.summary,
        "payload": row.payload or {},
        "generated_at": row.generated_at.isoformat() if row.generated_at else None,
        "period_start": row.period_start.isoformat() if row.period_start else None,
        "period_end": row.period_end.isoformat() if row.period_end else None,
    }
