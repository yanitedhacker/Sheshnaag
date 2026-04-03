"""Actionable risk scoring and workbench summaries."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.patch import AssetPatch, Patch
from app.models.risk_score import RiskScore
from app.models.v2 import NetworkExposure, Tenant, VexStatement
from app.patch_optimizer.engine import PatchOptimizer
from app.services.governance_service import GovernanceService
from app.services.graph_service import ExposureGraphService
from app.services.intel_service import ThreatIntelService


class WorkbenchService:
    """Build tenant-scoped remediation actions with evidence and citations."""

    def __init__(self, session: Session):
        self.session = session
        self.optimizer = PatchOptimizer(session)
        self.graph_service = ExposureGraphService(session)
        self.intel_service = ThreatIntelService(session)
        self.governance_service = GovernanceService(session)

    def get_summary(
        self,
        tenant: Tenant,
        *,
        limit: int = 10,
        scenario: Optional[dict] = None,
    ) -> Dict[str, object]:
        """Return ranked remediation actions for a tenant."""
        scenario = scenario or {}

        patch_ids = [
            row.patch_id
            for row in (
                self.session.query(AssetPatch.patch_id)
                .join(Asset, Asset.id == AssetPatch.asset_id)
                .filter(Asset.tenant_id == tenant.id)
                .distinct()
                .all()
            )
        ]

        approval_map = self.governance_service.get_latest_patch_approval_map(tenant, patch_ids)
        feedback_map = self.governance_service.get_latest_feedback_map(tenant, [f"patch:{patch_id}" for patch_id in patch_ids])

        actions = [
            self._build_patch_action(
                tenant,
                patch_id,
                scenario=scenario,
                approval=approval_map.get(patch_id),
                feedback=feedback_map.get(f"patch:{patch_id}"),
            )
            for patch_id in patch_ids
        ]
        actions = [action for action in actions if action is not None]
        actions.sort(key=lambda item: item["actionable_risk_score"], reverse=True)

        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "generated_at": datetime.utcnow().isoformat(),
            "count": len(actions),
            "summary": {
                "exposed_assets": self._count_exposed_assets(tenant),
                "crown_jewel_assets": self._count_crown_jewel_assets(tenant),
                "top_actionable_risk_score": actions[0]["actionable_risk_score"] if actions else 0,
            },
            "actions": actions[:limit],
        }

    def _build_patch_action(self, tenant: Tenant, patch_id: str, *, scenario: dict, approval=None, feedback=None) -> Optional[dict]:
        patch = self.session.query(Patch).filter(Patch.patch_id == patch_id).first()
        if patch is None:
            return None

        decision = self.optimizer.compute_decision_for_patch(
            patch_id,
            delay_days=int(scenario.get("delay_days", 0) or 0),
        )
        mappings = (
            self.session.query(AssetPatch, Asset)
            .join(Asset, Asset.id == AssetPatch.asset_id)
            .filter(AssetPatch.patch_id == patch_id, Asset.tenant_id == tenant.id)
            .all()
        )
        assets = [asset for _, asset in mappings]
        cves = list(patch.cves or [])

        latest_risk = self._latest_risk_by_cve_id([cve.id for cve in cves])
        kev_map = self.intel_service.get_kev_map([cve.cve_id for cve in cves])
        epss_map = self.intel_service.get_latest_epss_map([cve.cve_id for cve in cves])
        attack_paths = self.graph_service.get_attack_paths(tenant, limit=25)

        base_patch = float(decision.priority_score)
        base_risk = max((float(latest_risk.get(cve.id).overall_score) / 100.0 for cve in cves if latest_risk.get(cve.id)), default=0.0)
        epss_score = max((float(epss_map.get(cve.cve_id.upper()).score) for cve in cves if epss_map.get(cve.cve_id.upper())), default=0.0)
        kev_flag = any(cve.cve_id.upper() in kev_map for cve in cves)
        exploit_flag = any(cve.exploit_available for cve in cves)
        public_exposure = self._public_exposure_signal(assets)
        crown_jewel = any(asset.is_crown_jewel for asset in assets)
        criticality_signal = max((self._criticality_score(asset.criticality or asset.business_criticality) for asset in assets), default=0.4)
        lateral_signal = 1.0 if any(path for path in attack_paths["paths"] if any(asset.name in path["labels"] for asset in assets)) else 0.0
        time_pressure = float(decision.axes.TPM)
        public_weight = float(scenario.get("public_exposure_weight", 1.0) or 1.0)
        crown_weight = float(scenario.get("crown_jewel_weight", 1.0) or 1.0)
        compensating_controls = bool(scenario.get("compensating_controls"))
        vex_summary = self._vex_summary(tenant, assets=assets, cves=cves)

        score = (
            0.22 * base_patch
            + 0.18 * base_risk
            + 0.16 * epss_score
            + 0.12 * (1.0 if kev_flag else 0.0)
            + 0.10 * (1.0 if exploit_flag else 0.0)
            + 0.10 * min(1.0, public_exposure * public_weight)
            + 0.07 * min(1.0, criticality_signal * crown_weight)
            + 0.05 * (1.0 if crown_jewel else 0.0)
            + 0.05 * time_pressure
            + 0.05 * lateral_signal
        )

        if compensating_controls:
            score *= 0.82

        if vex_summary["status"] == "resolved":
            score *= 0.28
        elif vex_summary["status"] == "affected":
            score += 0.05

        score += self.governance_service.feedback_adjustment(feedback) / 100.0
        score = round(min(100.0, max(0.0, score * 100.0)), 2)
        confidence = round(
            min(
                0.95,
                (
                    0.45
                    + (0.07 * self._signal_count(kev_flag, exploit_flag, public_exposure > 0, crown_jewel, epss_score > 0, base_risk > 0))
                )
                * self.governance_service.feedback_confidence_multiplier(feedback),
            ),
            2,
        )
        if vex_summary["status"] == "under_investigation":
            confidence = round(max(0.3, confidence - 0.08), 2)
        confidence_band = {
            "lower": round(max(0.0, score - (1.0 - confidence) * 20.0), 2),
            "upper": round(min(100.0, score + (1.0 - confidence) * 12.0), 2),
        }

        recommended_action = self._recommended_action(score, decision.decision)
        if approval and approval.approval_state == "rejected" and score >= 70:
            recommended_action = "ESCALATE_CHANGE_BOARD"
        evidence, citations = self._build_evidence_and_citations(
            patch=patch,
            cves=cves,
            assets=assets,
            decision=decision,
            kev_map=kev_map,
            epss_map=epss_map,
            public_exposure=public_exposure > 0,
            attack_paths=attack_paths["paths"],
            approval=approval,
            feedback=feedback,
            vex_summary=vex_summary,
        )

        related_paths = [
            path for path in attack_paths["paths"] if any(label in {cve.cve_id for cve in cves} for label in path["labels"])
        ]

        return {
            "action_id": f"patch:{patch.patch_id}",
            "action_type": "patch",
            "title": f"Patch {patch.patch_id}",
            "entity_refs": self._entity_refs(patch, cves, assets),
            "actionable_risk_score": score,
            "recommended_action": recommended_action,
            "confidence": confidence,
            "confidence_band": confidence_band,
            "attack_path_count": len(related_paths),
            "attack_path_preview": [path["summary"] for path in related_paths[:2]],
            "expected_risk_reduction": round(float(decision.expected_risk_reduction), 3),
            "operational_cost_score": round(float(decision.axes.PCS), 3),
            "justification": decision.justification,
            "approval_state": approval.approval_state if approval else "pending_review",
            "approval_summary": self._approval_summary(approval),
            "feedback_summary": self._feedback_summary(feedback),
            "signals": {
                "kev": kev_flag,
                "epss": round(epss_score, 3),
                "public_exposure": public_exposure > 0,
                "crown_jewel": crown_jewel,
                "exploit_available": exploit_flag,
                "vex_status": vex_summary["status"],
            },
            "evidence": evidence,
            "citations": citations,
        }

    def _latest_risk_by_cve_id(self, cve_ids: Sequence[int]) -> Dict[int, RiskScore]:
        if not cve_ids:
            return {}

        scores = (
            self.session.query(RiskScore)
            .filter(RiskScore.cve_id.in_(cve_ids))
            .order_by(desc(RiskScore.created_at))
            .all()
        )
        latest: Dict[int, RiskScore] = {}
        for score in scores:
            if score.cve_id not in latest:
                latest[score.cve_id] = score
        return latest

    def _public_exposure_signal(self, assets: Sequence[Asset]) -> float:
        asset_ids = [asset.id for asset in assets]
        if not asset_ids:
            return 0.0
        count = (
            self.session.query(NetworkExposure)
            .filter(NetworkExposure.asset_id.in_(asset_ids), NetworkExposure.is_public.is_(True))
            .count()
        )
        return min(1.0, count / max(1, len(asset_ids)))

    @staticmethod
    def _criticality_score(value: Optional[str]) -> float:
        mapping = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}
        return mapping.get((value or "medium").lower(), 0.5)

    @staticmethod
    def _signal_count(*signals: object) -> int:
        return sum(1 for signal in signals if signal)

    @staticmethod
    def _recommended_action(score: float, fallback: str) -> str:
        if score >= 85:
            return "PATCH_NOW"
        if score >= 65:
            return "SCHEDULE_THIS_WEEK"
        if score >= 45:
            return "PLAN_WINDOW"
        if fallback in {"PATCH_NOW", "SCHEDULE", "DEFER"}:
            return fallback
        return "MONITOR"

    def _build_evidence_and_citations(
        self,
        *,
        patch: Patch,
        cves,
        assets: Sequence[Asset],
        decision,
        kev_map,
        epss_map,
        public_exposure: bool,
        attack_paths: List[dict],
        approval,
        feedback,
        vex_summary,
    ) -> tuple[list[dict], list[dict]]:
        evidence: List[dict] = []
        citations: Dict[str, dict] = {}

        if public_exposure:
            evidence.append(
                {
                    "kind": "exposure",
                    "title": "Internet-exposed asset path",
                    "summary": "At least one affected asset has a public-facing network exposure, increasing initial access risk.",
                    "severity": "high",
                }
            )

        for cve in cves:
            kev = kev_map.get(cve.cve_id.upper())
            if kev:
                evidence.append(
                    {
                        "kind": "intel",
                        "title": f"{cve.cve_id} is in CISA KEV",
                        "summary": kev.short_description,
                        "severity": "critical",
                    }
                )
                citations[kev.source_url] = {"label": "CISA KEV", "url": kev.source_url}

            epss = epss_map.get(cve.cve_id.upper())
            if epss:
                evidence.append(
                    {
                        "kind": "intel",
                        "title": f"EPSS score for {cve.cve_id}",
                        "summary": f"Latest EPSS score is {epss.score:.3f} with percentile {epss.percentile or 0:.3f}.",
                        "severity": "medium" if epss.score < 0.7 else "high",
                    }
                )
                if epss.source_url:
                    citations[epss.source_url] = {"label": "FIRST EPSS", "url": epss.source_url}

        if decision.justification:
            evidence.append(
                {
                    "kind": "optimizer",
                    "title": "Patch decision rationale",
                    "summary": "; ".join(decision.justification[:3]),
                    "severity": "medium",
                }
            )

        if attack_paths:
            top_path = attack_paths[0]
            evidence.append(
                {
                    "kind": "graph",
                    "title": "Attack path present in exposure graph",
                    "summary": top_path["summary"],
                    "severity": "high",
                }
            )

        for cve in cves:
            for document in self.intel_service.get_knowledge_documents(cve_id=cve.id, limit=3):
                if document.source_url:
                    citations[document.source_url] = {"label": document.source_label or document.document_type, "url": document.source_url}

        if vex_summary["status"] != "unknown":
            evidence.append(
                {
                    "kind": "vex",
                    "title": f"VEX posture: {vex_summary['status']}",
                    "summary": vex_summary["summary"],
                    "severity": "medium" if vex_summary["status"] == "under_investigation" else ("low" if vex_summary["status"] == "resolved" else "high"),
                }
            )

        if feedback is not None:
            evidence.append(
                {
                    "kind": "analyst",
                    "title": f"Analyst feedback: {feedback.feedback_type}",
                    "summary": feedback.note or "Manual analyst feedback has been recorded for this recommendation.",
                    "severity": "medium",
                }
            )

        if approval is not None:
            evidence.append(
                {
                    "kind": "governance",
                    "title": f"Approval status: {approval.approval_state}",
                    "summary": approval.note or f"{approval.approval_type} recorded for maintenance window {approval.maintenance_window or 'TBD'}.",
                    "severity": "medium",
                }
            )

        if patch.advisory_url:
            citations[patch.advisory_url] = {"label": "Vendor Advisory", "url": patch.advisory_url}

        return evidence, list(citations.values())

    def _vex_summary(self, tenant: Tenant, *, assets: Sequence[Asset], cves) -> dict:
        component_ids = [
            link.software_component_id
            for asset in assets
            for link in asset.software_components
        ]
        if not component_ids:
            return {"status": "unknown", "summary": "No component inventory was available for VEX evaluation."}

        cve_ids = [cve.cve_id.upper() for cve in cves]
        statements = (
            self.session.query(VexStatement)
            .filter(
                VexStatement.tenant_id == tenant.id,
                VexStatement.software_component_id.in_(component_ids),
                VexStatement.cve_id.in_(cve_ids),
            )
            .all()
        )
        if not statements:
            return {"status": "unknown", "summary": "No VEX statement has been imported for the affected components."}

        statuses = {statement.status.lower() for statement in statements}
        if statuses.issubset({"fixed", "not_affected"}):
            return {"status": "resolved", "summary": "Imported VEX states indicate the affected components are fixed or not affected."}
        if "affected" in statuses:
            return {"status": "affected", "summary": "Imported VEX confirms the vulnerable component is affected in this tenant."}
        if "under_investigation" in statuses:
            return {"status": "under_investigation", "summary": "Imported VEX leaves exploitability under investigation, so confidence is slightly reduced."}
        return {"status": "unknown", "summary": "VEX statements exist but did not clearly resolve exploitability."}

    @staticmethod
    def _approval_summary(approval) -> Optional[dict]:
        if approval is None:
            return None
        return {
            "approval_type": approval.approval_type,
            "approval_state": approval.approval_state,
            "maintenance_window": approval.maintenance_window,
            "decided_by": approval.decided_by,
            "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
            "note": approval.note,
        }

    @staticmethod
    def _feedback_summary(feedback) -> Optional[dict]:
        if feedback is None:
            return None
        return {
            "feedback_type": feedback.feedback_type,
            "note": feedback.note,
            "created_at": feedback.created_at.isoformat() if feedback.created_at else None,
        }

    @staticmethod
    def _entity_refs(patch: Patch, cves, assets: Sequence[Asset]) -> list[dict]:
        refs = [{"type": "patch", "id": patch.patch_id, "label": patch.patch_id}]
        refs.extend({"type": "cve", "id": cve.cve_id, "label": cve.cve_id} for cve in cves)
        refs.extend({"type": "asset", "id": str(asset.id), "label": asset.name} for asset in assets)
        return refs

    def _count_exposed_assets(self, tenant: Tenant) -> int:
        return (
            self.session.query(NetworkExposure.asset_id)
            .filter(NetworkExposure.tenant_id == tenant.id, NetworkExposure.is_public.is_(True))
            .distinct()
            .count()
        )

    def _count_crown_jewel_assets(self, tenant: Tenant) -> int:
        return self.session.query(Asset).filter(Asset.tenant_id == tenant.id, Asset.is_crown_jewel.is_(True)).count()
