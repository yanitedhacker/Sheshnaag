"""Seed realistic demo data for the public read-only tenant."""

from __future__ import annotations

from datetime import datetime, timedelta
from app.core.time import utc_now

from sqlalchemy.orm import Session

from app.core.tenancy import get_or_create_demo_tenant
from app.models.asset import Asset, AssetVulnerability
from app.models.cve import AffectedProduct, CVE
from app.models.patch import AssetPatch, Patch
from app.models.risk_score import RiskScore
from app.models.v2 import (
    AnalystFeedback,
    AssetSoftware,
    IdentityPrincipal,
    KnowledgeDocument,
    NetworkExposure,
    PatchApproval,
    Service,
    SoftwareComponent,
)
from app.services.governance_service import GovernanceService
from app.services.graph_service import ExposureGraphService
from app.services.intel_service import ThreatIntelService
from app.services.knowledge_service import KnowledgeRetrievalService
from app.services.workbench_service import WorkbenchService


class DemoSeedService:
    """Populate the demo-public tenant with a coherent v2 scenario."""

    def __init__(self, session: Session):
        self.session = session
        self.intel = ThreatIntelService(session)
        self.graph = ExposureGraphService(session)
        self.governance = GovernanceService(session)
        self.knowledge = KnowledgeRetrievalService(session)

    def seed(self) -> None:
        """Idempotently populate demo data and graph state."""
        tenant = get_or_create_demo_tenant(self.session)

        if self.session.query(Asset).filter(Asset.tenant_id == tenant.id).count() == 0:
            self._seed_global_cves()
            assets = self._seed_assets(tenant.id)
            services = self._seed_services(tenant.id, assets)
            components = self._seed_components(tenant.id)
            self._link_asset_software(assets, services, components)
            self._seed_network_exposures(tenant.id, assets, services)
            self._seed_identities(tenant.id, assets)
            self._seed_patches_and_vulns(assets)

        self.intel.seed_demo_intel()
        self.graph.rebuild_graph(tenant)
        self._seed_governance_artifacts(tenant)
        self._seed_recommendation_documents(tenant)
        self.knowledge.reindex_documents()

    def _seed_global_cves(self) -> None:
        now = utc_now()
        cves = [
            {
                "cve_id": "CVE-2024-10001",
                "description": "Remote code execution in the public API gateway allows unauthenticated attackers to execute code via crafted requests.",
                "published_date": now - timedelta(days=21),
                "last_modified_date": now - timedelta(days=2),
                "cvss_v3_score": 9.8,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "cwe_id": "CWE-94",
                "exploit_available": True,
                "exploit_count": 3,
                "source": "DEMO",
            },
            {
                "cve_id": "CVE-2024-10002",
                "description": "SSRF in the internal payments API can be chained to reach sensitive metadata services from adjacent workloads.",
                "published_date": now - timedelta(days=38),
                "last_modified_date": now - timedelta(days=6),
                "cvss_v3_score": 8.1,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "LOW",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "LOW",
                "availability_impact": "LOW",
                "cwe_id": "CWE-918",
                "exploit_available": False,
                "exploit_count": 1,
                "source": "DEMO",
            },
            {
                "cve_id": "CVE-2024-10003",
                "description": "Authentication bypass in the admin portal enables session creation without valid credentials for privileged workflows.",
                "published_date": now - timedelta(days=14),
                "last_modified_date": now - timedelta(days=1),
                "cvss_v3_score": 9.1,
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "LOW",
                "cwe_id": "CWE-287",
                "exploit_available": True,
                "exploit_count": 2,
                "source": "DEMO",
            },
        ]

        affected_products = {
            "CVE-2024-10001": [("acme", "edge-gateway", "4.2.1")],
            "CVE-2024-10002": [("acme", "payments-api", "2.3.0")],
            "CVE-2024-10003": [("acme", "admin-portal", "7.5.0")],
        }

        scores = {
            "CVE-2024-10001": (92.5, 0.94, "CRITICAL"),
            "CVE-2024-10002": (70.4, 0.62, "HIGH"),
            "CVE-2024-10003": (88.7, 0.9, "CRITICAL"),
        }

        for item in cves:
            cve = self.session.query(CVE).filter(CVE.cve_id == item["cve_id"]).first()
            if cve is None:
                cve = CVE(**item)
                self.session.add(cve)
                self.session.flush()
            else:
                for key, value in item.items():
                    setattr(cve, key, value)

            for vendor, product, version in affected_products[item["cve_id"]]:
                existing = (
                    self.session.query(AffectedProduct)
                    .filter(AffectedProduct.cve_id == cve.id, AffectedProduct.vendor == vendor, AffectedProduct.product == product)
                    .first()
                )
                if existing is None:
                    self.session.add(
                        AffectedProduct(
                            cve_id=cve.id,
                            vendor=vendor,
                            product=product,
                            version=version,
                            cpe_uri=f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
                        )
                    )

            overall, exploit_prob, level = scores[item["cve_id"]]
            existing_score = (
                self.session.query(RiskScore)
                .filter(RiskScore.cve_id == cve.id)
                .order_by(RiskScore.created_at.desc())
                .first()
            )
            if existing_score is None:
                self.session.add(
                    RiskScore(
                        cve_id=cve.id,
                        overall_score=overall,
                        exploit_probability=exploit_prob,
                        impact_score=min(100.0, (cve.cvss_v3_score or 0.0) * 10.0),
                        exposure_score=65.0,
                        temporal_score=70.0,
                        risk_level=level,
                        priority_rank=1,
                        confidence_score=0.82,
                        confidence_band_lower=max(0.0, exploit_prob - 0.08),
                        confidence_band_upper=min(1.0, exploit_prob + 0.06),
                        top_features=[
                            {"feature": "public_exposure", "contribution": 0.31},
                            {"feature": "exploit_available", "contribution": 0.27},
                            {"feature": "cvss_v3_score", "contribution": 0.22},
                        ],
                        explanation="Demo seeded risk score blending exploit likelihood, severity, and exposure context.",
                        model_version="demo-v2",
                    )
                )

    def _seed_assets(self, tenant_id: int) -> dict[str, Asset]:
        definitions = [
            {
                "key": "edge",
                "name": "edge-gateway-01",
                "asset_type": "gateway",
                "hostname": "edge-gateway-01.demo.local",
                "environment": "production",
                "criticality": "critical",
                "business_criticality": "high",
                "is_crown_jewel": False,
                "installed_software": [{"vendor": "acme", "product": "edge-gateway", "version": "4.2.1"}],
                "owner": "platform",
            },
            {
                "key": "admin",
                "name": "identity-admin-01",
                "asset_type": "application",
                "hostname": "identity-admin-01.demo.local",
                "environment": "production",
                "criticality": "high",
                "business_criticality": "critical",
                "is_crown_jewel": True,
                "installed_software": [{"vendor": "acme", "product": "admin-portal", "version": "7.5.0"}],
                "owner": "identity",
            },
            {
                "key": "payments",
                "name": "payments-core-01",
                "asset_type": "application",
                "hostname": "payments-core-01.demo.local",
                "environment": "production",
                "criticality": "critical",
                "business_criticality": "critical",
                "is_crown_jewel": True,
                "installed_software": [{"vendor": "acme", "product": "payments-api", "version": "2.3.0"}],
                "owner": "payments",
            },
        ]

        assets: dict[str, Asset] = {}
        for item in definitions:
            asset = self.session.query(Asset).filter(Asset.tenant_id == tenant_id, Asset.name == item["name"]).first()
            if asset is None:
                asset = Asset(tenant_id=tenant_id, **{k: v for k, v in item.items() if k != "key"})
                self.session.add(asset)
                self.session.flush()
            assets[item["key"]] = asset
        return assets

    def _seed_services(self, tenant_id: int, assets: dict[str, Asset]) -> dict[str, Service]:
        definitions = [
            {
                "key": "gateway",
                "asset_id": assets["edge"].id,
                "name": "Public API Gateway",
                "slug": "public-api-gateway",
                "service_type": "gateway",
                "environment": "production",
                "owner": "platform",
                "business_criticality": "high",
                "internet_exposed": True,
                "description": "Internet-facing gateway for customer APIs.",
            },
            {
                "key": "admin_portal",
                "asset_id": assets["admin"].id,
                "name": "Admin Portal",
                "slug": "admin-portal",
                "service_type": "webapp",
                "environment": "production",
                "owner": "identity",
                "business_criticality": "critical",
                "internet_exposed": True,
                "description": "Privileged administrative workflows for identity and access.",
            },
            {
                "key": "payments_api",
                "asset_id": assets["payments"].id,
                "name": "Payments API",
                "slug": "payments-api",
                "service_type": "api",
                "environment": "production",
                "owner": "payments",
                "business_criticality": "critical",
                "internet_exposed": False,
                "description": "Internal payments processing API.",
            },
        ]

        services: dict[str, Service] = {}
        for item in definitions:
            service = self.session.query(Service).filter(Service.tenant_id == tenant_id, Service.slug == item["slug"]).first()
            if service is None:
                service = Service(tenant_id=tenant_id, **{k: v for k, v in item.items() if k != "key"})
                self.session.add(service)
                self.session.flush()
            services[item["key"]] = service

        if services["gateway"].upstream_service_id is None:
            services["gateway"].upstream_service_id = services["payments_api"].id
        if services["admin_portal"].upstream_service_id is None:
            services["admin_portal"].upstream_service_id = services["payments_api"].id
        return services

    def _seed_components(self, tenant_id: int) -> dict[str, SoftwareComponent]:
        definitions = [
            {"key": "edge", "vendor": "acme", "name": "edge-gateway", "version": "4.2.1", "purl": "pkg:generic/acme/edge-gateway@4.2.1"},
            {"key": "admin", "vendor": "acme", "name": "admin-portal", "version": "7.5.0", "purl": "pkg:generic/acme/admin-portal@7.5.0"},
            {"key": "payments", "vendor": "acme", "name": "payments-api", "version": "2.3.0", "purl": "pkg:generic/acme/payments-api@2.3.0"},
        ]
        components: dict[str, SoftwareComponent] = {}
        for item in definitions:
            component = (
                self.session.query(SoftwareComponent)
                .filter(
                    SoftwareComponent.tenant_id == tenant_id,
                    SoftwareComponent.name == item["name"],
                    SoftwareComponent.version == item["version"],
                )
                .first()
            )
            if component is None:
                component = SoftwareComponent(
                    tenant_id=tenant_id,
                    vendor=item["vendor"],
                    name=item["name"],
                    version=item["version"],
                    purl=item["purl"],
                    component_type="service",
                    meta={"bom_ref": item["key"]},
                )
                self.session.add(component)
                self.session.flush()
            components[item["key"]] = component
        return components

    def _link_asset_software(self, assets: dict[str, Asset], services: dict[str, Service], components: dict[str, SoftwareComponent]) -> None:
        mappings = [
            (assets["edge"].id, components["edge"].id, services["gateway"].id),
            (assets["admin"].id, components["admin"].id, services["admin_portal"].id),
            (assets["payments"].id, components["payments"].id, services["payments_api"].id),
        ]
        for asset_id, component_id, service_id in mappings:
            existing = (
                self.session.query(AssetSoftware)
                .filter(
                    AssetSoftware.asset_id == asset_id,
                    AssetSoftware.software_component_id == component_id,
                    AssetSoftware.service_id == service_id,
                )
                .first()
            )
            if existing is None:
                self.session.add(
                    AssetSoftware(
                        asset_id=asset_id,
                        software_component_id=component_id,
                        service_id=service_id,
                        discovered_by="demo_seed",
                    )
                )

    def _seed_network_exposures(self, tenant_id: int, assets: dict[str, Asset], services: dict[str, Service]) -> None:
        definitions = [
            (assets["edge"].id, services["gateway"].id, "api.demo.cve-radar.local", 443),
            (assets["admin"].id, services["admin_portal"].id, "admin.demo.cve-radar.local", 8443),
        ]
        for asset_id, service_id, hostname, port in definitions:
            existing = (
                self.session.query(NetworkExposure)
                .filter(NetworkExposure.tenant_id == tenant_id, NetworkExposure.asset_id == asset_id, NetworkExposure.service_id == service_id)
                .first()
            )
            if existing is None:
                self.session.add(
                    NetworkExposure(
                        tenant_id=tenant_id,
                        asset_id=asset_id,
                        service_id=service_id,
                        hostname=hostname,
                        protocol="tcp",
                        port=port,
                        exposure_type="public",
                        is_public=True,
                    )
                )

    def _seed_identities(self, tenant_id: int, assets: dict[str, Asset]) -> None:
        identities = [
            ("svc-admin-sync", assets["admin"].id, "service_account", "admin", True, True),
            ("svc-payments-batch", assets["payments"].id, "service_account", "power_user", False, False),
        ]
        for name, asset_id, principal_type, privilege_level, can_admin, can_lateral_move in identities:
            existing = (
                self.session.query(IdentityPrincipal)
                .filter(IdentityPrincipal.tenant_id == tenant_id, IdentityPrincipal.name == name)
                .first()
            )
            if existing is None:
                self.session.add(
                    IdentityPrincipal(
                        tenant_id=tenant_id,
                        asset_id=asset_id,
                        name=name,
                        principal_type=principal_type,
                        privilege_level=privilege_level,
                        can_admin=can_admin,
                        can_lateral_move=can_lateral_move,
                    )
                )

    def _seed_patches_and_vulns(self, assets: dict[str, Asset]) -> None:
        cves = {
            cve.cve_id: cve
            for cve in self.session.query(CVE).filter(CVE.cve_id.in_(["CVE-2024-10001", "CVE-2024-10002", "CVE-2024-10003"])).all()
        }

        patch_specs = [
            {
                "patch_id": "PATCH-ACME-EDGE-4.2.3",
                "vendor": "acme",
                "affected_software": "edge-gateway",
                "requires_reboot": False,
                "estimated_downtime_minutes": 15,
                "rollback_complexity": 0.2,
                "historical_failure_rate": 0.04,
                "change_risk_score": 0.2,
                "released_at": utc_now() - timedelta(days=7),
                "source": "demo_seed",
                "advisory_url": "https://example.com/advisories/public-api-gateway",
                "cves": ["CVE-2024-10001"],
                "asset_keys": ["edge"],
                "maintenance_window": "Sat 02:00-04:00",
            },
            {
                "patch_id": "PATCH-ACME-IDENTITY-7.5.2",
                "vendor": "acme",
                "affected_software": "admin-portal",
                "requires_reboot": True,
                "estimated_downtime_minutes": 25,
                "rollback_complexity": 0.35,
                "historical_failure_rate": 0.08,
                "change_risk_score": 0.4,
                "released_at": utc_now() - timedelta(days=4),
                "source": "demo_seed",
                "advisory_url": "https://example.com/advisories/admin-portal-auth-bypass",
                "cves": ["CVE-2024-10003"],
                "asset_keys": ["admin"],
                "maintenance_window": "Sun 01:00-03:00",
            },
            {
                "patch_id": "PATCH-ACME-PAYMENTS-2.3.1",
                "vendor": "acme",
                "affected_software": "payments-api",
                "requires_reboot": False,
                "estimated_downtime_minutes": 20,
                "rollback_complexity": 0.25,
                "historical_failure_rate": 0.03,
                "change_risk_score": 0.3,
                "released_at": utc_now() - timedelta(days=10),
                "source": "demo_seed",
                "advisory_url": "https://example.com/advisories/payments-api-ssrf",
                "cves": ["CVE-2024-10002"],
                "asset_keys": ["payments"],
                "maintenance_window": "Sat 04:00-05:00",
            },
        ]

        for spec in patch_specs:
            patch = self.session.query(Patch).filter(Patch.patch_id == spec["patch_id"]).first()
            if patch is None:
                patch = Patch(
                    patch_id=spec["patch_id"],
                    vendor=spec["vendor"],
                    affected_software=spec["affected_software"],
                    requires_reboot=spec["requires_reboot"],
                    estimated_downtime_minutes=spec["estimated_downtime_minutes"],
                    rollback_complexity=spec["rollback_complexity"],
                    historical_failure_rate=spec["historical_failure_rate"],
                    change_risk_score=spec["change_risk_score"],
                    released_at=spec["released_at"],
                    source=spec["source"],
                    advisory_url=spec["advisory_url"],
                )
                patch.cves = [cves[cve_id] for cve_id in spec["cves"]]
                self.session.add(patch)
                self.session.flush()

            for asset_key in spec["asset_keys"]:
                asset = assets[asset_key]
                vuln = (
                    self.session.query(AssetVulnerability)
                    .filter(AssetVulnerability.asset_id == asset.id, AssetVulnerability.cve_id == cves[spec["cves"][0]].id)
                    .first()
                )
                if vuln is None:
                    self.session.add(
                        AssetVulnerability(
                            asset_id=asset.id,
                            cve_id=cves[spec["cves"][0]].id,
                            status="open",
                            detection_source="demo_seed",
                            detected_date=utc_now() - timedelta(days=3),
                        )
                    )

                mapping = (
                    self.session.query(AssetPatch)
                    .filter(AssetPatch.asset_id == asset.id, AssetPatch.patch_id == patch.patch_id)
                    .first()
                )
                if mapping is None:
                    self.session.add(
                        AssetPatch(
                            asset_id=asset.id,
                            patch_id=patch.patch_id,
                            maintenance_window=spec["maintenance_window"],
                            environment=asset.environment,
                            status="recommended",
                        )
                    )

    def _seed_governance_artifacts(self, tenant) -> None:
        approvals = [
            {
                "patch_id": "PATCH-ACME-EDGE-4.2.3",
                "action_id": "patch:PATCH-ACME-EDGE-4.2.3",
                "approval_type": "emergency_window",
                "approval_state": "approved",
                "maintenance_window": "Sat 02:00-04:00",
                "note": "Approved for the next change window because the public edge service is internet-facing.",
                "decided_by": "demo-cab",
            },
            {
                "patch_id": "PATCH-ACME-IDENTITY-7.5.2",
                "action_id": "patch:PATCH-ACME-IDENTITY-7.5.2",
                "approval_type": "signoff",
                "approval_state": "pending",
                "maintenance_window": "Sun 01:00-03:00",
                "note": "Awaiting identity service owner confirmation before rollout.",
                "decided_by": "demo-cab",
            },
        ]
        for item in approvals:
            existing = (
                self.session.query(PatchApproval)
                .filter(PatchApproval.tenant_id == tenant.id, PatchApproval.patch_id == item["patch_id"], PatchApproval.approval_state == item["approval_state"])
                .first()
            )
            if existing is None:
                self.governance.create_patch_approval(tenant, **item)

        feedback_items = [
            {
                "action_id": "patch:PATCH-ACME-EDGE-4.2.3",
                "feedback_type": "confirm",
                "note": "Security engineering confirmed this remains the top emergency change after reviewing current exposure.",
            },
            {
                "action_id": "patch:PATCH-ACME-PAYMENTS-2.3.1",
                "feedback_type": "deprioritize",
                "note": "Compensating controls lower urgency until the Saturday payments window opens.",
            },
        ]
        for item in feedback_items:
            existing = (
                self.session.query(AnalystFeedback)
                .filter(AnalystFeedback.tenant_id == tenant.id, AnalystFeedback.action_id == item["action_id"], AnalystFeedback.feedback_type == item["feedback_type"])
                .first()
            )
            if existing is None:
                self.governance.submit_feedback(tenant, **item)

    def _seed_recommendation_documents(self, tenant) -> None:
        workbench = WorkbenchService(self.session).get_summary(tenant, limit=3)
        for action in workbench["actions"]:
            title = f"Recommendation note: {action['title']}"
            existing = (
                self.session.query(KnowledgeDocument)
                .filter(
                    KnowledgeDocument.tenant_id == tenant.id,
                    KnowledgeDocument.document_type == "recommendation-note",
                    KnowledgeDocument.title == title,
                )
                .first()
            )
            content = (
                f"{action['title']} is currently ranked at {action['actionable_risk_score']}. "
                f"Recommended action is {action['recommended_action']}. "
                f"Supporting evidence: "
                + " ".join(item["summary"] for item in action["evidence"][:3])
            )
            if existing is None:
                self.session.add(
                    KnowledgeDocument(
                        tenant_id=tenant.id,
                        document_type="recommendation-note",
                        title=title,
                        content=content,
                        source_label="Threat Radar",
                        source_url=f"action://{action['action_id']}",
                        meta={"action_id": action["action_id"]},
                    )
                )
            else:
                existing.content = content
                existing.meta = {"action_id": action["action_id"]}
