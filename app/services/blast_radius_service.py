"""Malware-analysis blast-radius correlation service."""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetVulnerability
from app.models.cve import CVE
from app.models.malware_lab import AnalysisCase, BehaviorFinding, IndicatorArtifact
from app.models.risk_score import RiskScore
from app.models.sheshnaag import EvidenceArtifact
from app.models.v2 import AssetSoftware, NetworkExposure, Service, SoftwareComponent, Tenant


class BlastRadiusService:
    """Correlate observed malware behavior with tenant asset context."""

    def __init__(self, session: Session):
        self.session = session

    def case_blast_radius(self, tenant: Tenant, *, case_id: int, depth: int = 1) -> Dict[str, Any]:
        case = (
            self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id, AnalysisCase.id == case_id)
            .first()
        )
        if case is None:
            raise ValueError("Analysis case not found.")

        findings = (
            self.session.query(BehaviorFinding)
            .filter(BehaviorFinding.tenant_id == tenant.id, BehaviorFinding.analysis_case_id == case.id)
            .order_by(desc(BehaviorFinding.confidence))
            .all()
        )
        indicators = (
            self.session.query(IndicatorArtifact)
            .filter(IndicatorArtifact.tenant_id == tenant.id, IndicatorArtifact.analysis_case_id == case.id)
            .order_by(desc(IndicatorArtifact.confidence))
            .all()
        )
        evidence_rows = (
            self.session.query(EvidenceArtifact)
            .filter(EvidenceArtifact.run_id.in_([row.run_id for row in findings if row.run_id is not None] or [-1]))
            .all()
        )

        matched_assets = self._match_assets(tenant, indicators=indicators, findings=findings)
        affected_assets = [self._asset_payload(asset, indicators, findings) for asset in matched_assets]
        impact_paths = self._impact_paths(tenant, matched_assets, indicators, depth=max(1, min(int(depth or 1), 2)))
        recommended_actions = self._recommended_actions(affected_assets, indicators, findings)
        confidence = self._overall_confidence(affected_assets, indicators, findings)

        return {
            "case": {
                "id": case.id,
                "title": case.title,
                "status": case.status,
                "priority": case.priority,
            },
            "affected_assets": affected_assets,
            "indicators": [self._indicator_payload(row) for row in indicators],
            "findings": [self._finding_payload(row) for row in findings],
            "evidence_links": [
                {
                    "id": row.id,
                    "run_id": row.run_id,
                    "artifact_kind": row.artifact_kind,
                    "title": row.title,
                    "storage_path": row.storage_path,
                }
                for row in evidence_rows
            ],
            "impact_paths": impact_paths,
            "recommended_actions": recommended_actions,
            "confidence": confidence,
        }

    def _match_assets(
        self,
        tenant: Tenant,
        *,
        indicators: List[IndicatorArtifact],
        findings: List[BehaviorFinding],
    ) -> List[Asset]:
        assets_by_id: Dict[int, Asset] = {}
        values = {str(row.value).lower() for row in indicators if row.value}
        for asset in self.session.query(Asset).filter(Asset.tenant_id == tenant.id, Asset.is_active.is_(True)).all():
            haystack = {
                str(asset.name or "").lower(),
                str(asset.hostname or "").lower(),
                str(asset.ip_address or "").lower(),
            }
            haystack.update(str(tag).lower() for tag in (asset.tags or []))
            if values.intersection(haystack):
                assets_by_id[asset.id] = asset

        domains = [row.value for row in indicators if row.indicator_kind in {"domain", "host", "url"}]
        ips = [row.value for row in indicators if row.indicator_kind in {"ip", "ipv4", "ipv6"}]
        if domains or ips:
            exposure_query = self.session.query(NetworkExposure).filter(NetworkExposure.tenant_id == tenant.id)
            filters = []
            if domains:
                filters.append(NetworkExposure.hostname.in_(domains))
            if ips:
                filters.append(NetworkExposure.hostname.in_(ips))
            for exposure in exposure_query.filter(or_(*filters)).all() if filters else []:
                if exposure.asset:
                    assets_by_id[exposure.asset.id] = exposure.asset

        cve_ids = set()
        for finding in findings:
            payload = finding.payload or {}
            for key in ("cve_id", "cves"):
                value = payload.get(key)
                if isinstance(value, list):
                    cve_ids.update(str(item).upper() for item in value)
                elif value:
                    cve_ids.add(str(value).upper())
        if cve_ids:
            cves = self.session.query(CVE).filter(CVE.cve_id.in_(sorted(cve_ids))).all()
            for av in self.session.query(AssetVulnerability).filter(AssetVulnerability.cve_id.in_([cve.id for cve in cves])).all():
                if av.asset and av.asset.tenant_id == tenant.id:
                    assets_by_id[av.asset.id] = av.asset

        return sorted(assets_by_id.values(), key=lambda item: (item.is_crown_jewel is not True, item.name or ""))

    def _asset_payload(self, asset: Asset, indicators: List[IndicatorArtifact], findings: List[BehaviorFinding]) -> Dict[str, Any]:
        vulns = self.session.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset.id).all()
        cve_rows = self.session.query(CVE).filter(CVE.id.in_([row.cve_id for row in vulns] or [-1])).all()
        risk_rows = (
            self.session.query(RiskScore)
            .filter(RiskScore.cve_id.in_([row.id for row in cve_rows] or [-1]))
            .order_by(desc(RiskScore.overall_score))
            .all()
        )
        return {
            "asset_id": asset.id,
            "name": asset.name,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "asset_type": asset.asset_type,
            "environment": asset.environment,
            "criticality": asset.criticality or asset.business_criticality,
            "is_crown_jewel": bool(asset.is_crown_jewel),
            "matched_indicators": [self._indicator_payload(row) for row in indicators if self._indicator_matches_asset(row, asset)],
            "matched_findings": [self._finding_payload(row) for row in findings],
            "open_cves": [
                {
                    "cve_id": cve.cve_id,
                    "cvss_v3_score": cve.cvss_v3_score,
                    "exploit_available": bool(cve.exploit_available),
                    "risk_score": next((risk.overall_score for risk in risk_rows if risk.cve_id == cve.id), None),
                }
                for cve in cve_rows
            ],
            "services": [
                {"id": svc.id, "name": svc.name, "internet_exposed": bool(svc.internet_exposed)}
                for svc in self.session.query(Service).filter(Service.asset_id == asset.id).all()
            ],
        }

    @staticmethod
    def _indicator_matches_asset(indicator: IndicatorArtifact, asset: Asset) -> bool:
        value = str(indicator.value or "").lower()
        return value in {
            str(asset.name or "").lower(),
            str(asset.hostname or "").lower(),
            str(asset.ip_address or "").lower(),
        }

    def _impact_paths(self, tenant: Tenant, assets: List[Asset], indicators: List[IndicatorArtifact], *, depth: int) -> List[Dict[str, Any]]:
        paths = []
        for asset in assets:
            services = self.session.query(Service).filter(Service.asset_id == asset.id).all()
            if not services:
                paths.append({"asset_id": asset.id, "path": [asset.name], "reason": "indicator_or_cve_match"})
            for service in services:
                path = [asset.name, service.name]
                if depth > 1 and service.upstream_service:
                    path.append(service.upstream_service.name)
                paths.append({"asset_id": asset.id, "service_id": service.id, "path": path, "reason": "service_dependency"})
        return paths

    @staticmethod
    def _recommended_actions(assets: List[Dict[str, Any]], indicators: List[IndicatorArtifact], findings: List[BehaviorFinding]) -> List[Dict[str, Any]]:
        actions = []
        if indicators:
            actions.append({"action": "block_indicators", "priority": "high", "count": len(indicators)})
        if assets:
            actions.append({"action": "isolate_or_monitor_assets", "priority": "high", "asset_ids": [row["asset_id"] for row in assets]})
        if any((finding.payload or {}).get("attack_techniques") for finding in findings):
            actions.append({"action": "deploy_attack_mapped_detections", "priority": "medium"})
        return actions

    @staticmethod
    def _overall_confidence(assets: List[Dict[str, Any]], indicators: List[IndicatorArtifact], findings: List[BehaviorFinding]) -> float:
        signals = [row.confidence for row in indicators] + [row.confidence for row in findings]
        base = sum(signals) / len(signals) if signals else 0.0
        if assets:
            base = max(base, 0.55)
        return round(min(0.99, base), 3)

    @staticmethod
    def _indicator_payload(row: IndicatorArtifact) -> Dict[str, Any]:
        return {
            "id": row.id,
            "kind": row.indicator_kind,
            "value": row.value,
            "confidence": row.confidence,
            "source": row.source,
        }

    @staticmethod
    def _finding_payload(row: BehaviorFinding) -> Dict[str, Any]:
        return {
            "id": row.id,
            "run_id": row.run_id,
            "finding_type": row.finding_type,
            "title": row.title,
            "severity": row.severity,
            "confidence": row.confidence,
            "attack_techniques": (row.payload or {}).get("attack_techniques") or [],
        }
