"""SBOM and VEX import helpers for private tenants."""

from __future__ import annotations

from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.cve import CVE
from app.models.v2 import AssetSoftware, KnowledgeDocument, Service, SoftwareComponent, Tenant, VexStatement
from app.services.graph_service import ExposureGraphService
from app.services.knowledge_service import KnowledgeRetrievalService


class ImportService:
    """Import CycloneDX-like SBOM and VEX payloads into the normalized inventory."""

    def __init__(self, session: Session):
        self.session = session
        self.graph = ExposureGraphService(session)
        self.knowledge = KnowledgeRetrievalService(session)

    def import_sbom(
        self,
        tenant: Tenant,
        *,
        document: dict,
        asset_id: Optional[int] = None,
        service_id: Optional[int] = None,
    ) -> Dict[str, object]:
        """Import a CycloneDX-style software inventory document."""
        components = document.get("components", [])
        asset = None
        if asset_id is not None:
            asset = self.session.query(Asset).filter(Asset.id == asset_id, Asset.tenant_id == tenant.id).first()

        created = 0
        linked = 0
        services_created = 0
        dependencies_linked = 0
        documents_created = 0
        service_map, services_created = self._ensure_services(tenant, document=document, asset_id=asset_id)

        for item in components:
            name = item.get("name")
            if not name:
                continue

            component = (
                self.session.query(SoftwareComponent)
                .filter(
                    SoftwareComponent.tenant_id == tenant.id,
                    SoftwareComponent.name == name,
                    SoftwareComponent.version == item.get("version"),
                    SoftwareComponent.vendor == item.get("publisher"),
                )
                .first()
            )
            if component is None:
                component = SoftwareComponent(
                    tenant_id=tenant.id,
                    vendor=item.get("publisher"),
                    name=name,
                    version=item.get("version"),
                    purl=item.get("purl"),
                    cpe=item.get("cpe"),
                    component_type=item.get("type") or "application",
                    meta={"bom_ref": item.get("bom-ref")},
                )
                self.session.add(component)
                self.session.flush()
                created += 1

            if item.get("description"):
                documents_created += self._upsert_component_note(tenant, component, item)

            if asset is not None:
                existing_link = (
                    self.session.query(AssetSoftware)
                    .filter(
                        AssetSoftware.asset_id == asset.id,
                        AssetSoftware.software_component_id == component.id,
                        AssetSoftware.service_id == service_id,
                    )
                    .first()
                )
                if existing_link is None:
                    self.session.add(
                        AssetSoftware(
                            asset_id=asset.id,
                            software_component_id=component.id,
                            service_id=service_id,
                            discovered_by="sbom_import",
                            meta={"bom_ref": item.get("bom-ref")},
                        )
                    )
                    linked += 1

        dependencies_linked = self._link_dependencies(tenant, document=document, service_map=service_map)
        sbom_note_ids = [
            row[0]
            for row in self.session.query(KnowledgeDocument.id)
            .filter(KnowledgeDocument.tenant_id == tenant.id, KnowledgeDocument.document_type == "sbom-note")
            .all()
        ]
        self.knowledge.reindex_documents(document_ids=sbom_note_ids)
        self.graph.rebuild_graph(tenant)

        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug},
            "components_processed": len(components),
            "components_created": created,
            "asset_links_created": linked,
            "services_created": services_created,
            "dependencies_linked": dependencies_linked,
            "knowledge_documents_created": documents_created,
        }

    def import_vex(self, tenant: Tenant, *, document: dict) -> Dict[str, object]:
        """Import VEX-like vulnerability status statements."""
        vulnerabilities = document.get("vulnerabilities", [])
        statements = document.get("statements", [])
        created = 0
        updated = 0

        for vuln in vulnerabilities:
            cve_id = (vuln.get("id") or "").upper()
            if not cve_id:
                continue
            affects = vuln.get("affects", []) or vuln.get("products", [])
            status = self._normalize_vex_status(
                vuln.get("analysis", {}).get("state")
                or vuln.get("analysis", {}).get("status")
                or vuln.get("status")
                or "under_investigation"
            )
            justification = (
                vuln.get("analysis", {}).get("detail")
                or vuln.get("analysis", {}).get("justification")
                or vuln.get("justification")
            )

            component_ids = self._match_components(tenant, affects)
            for component_id in component_ids:
                created_delta, updated_delta = self._upsert_vex_statement(
                    tenant,
                    component_id=component_id,
                    cve_id=cve_id,
                    status=status,
                    justification=justification,
                    source_url=(vuln.get("source", {}) or {}).get("url"),
                    raw_data=vuln,
                )
                created += created_delta
                updated += updated_delta

        for statement in statements:
            vulnerability = statement.get("vulnerability", {}) or {}
            cve_id = (vulnerability.get("name") or statement.get("cve") or "").upper()
            if not cve_id:
                continue
            products = statement.get("products", [])
            component_ids = self._match_components(tenant, products)
            status = self._normalize_vex_status(statement.get("status") or "under_investigation")
            justification = statement.get("justification") or statement.get("impact_statement") or statement.get("action_statement")
            for component_id in component_ids:
                created_delta, updated_delta = self._upsert_vex_statement(
                    tenant,
                    component_id=component_id,
                    cve_id=cve_id,
                    status=status,
                    justification=justification,
                    source_url=document.get("@id"),
                    raw_data=statement,
                )
                created += created_delta
                updated += updated_delta

        self.graph.rebuild_graph(tenant)

        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug},
            "vulnerabilities_processed": len(vulnerabilities) + len(statements),
            "statements_created": created,
            "statements_updated": updated,
        }

    def _ensure_services(self, tenant: Tenant, *, document: dict, asset_id: Optional[int]) -> tuple[Dict[str, Service], int]:
        service_defs = []
        metadata_component = (document.get("metadata") or {}).get("component")
        if metadata_component and metadata_component.get("type") in {"application", "service"}:
            service_defs.append(metadata_component)
        service_defs.extend(document.get("services", []) or [])

        service_map: Dict[str, Service] = {}
        created = 0
        for item in service_defs:
            name = item.get("name")
            if not name:
                continue
            bom_ref = item.get("bom-ref") or item.get("bom_ref") or item.get("@id") or name
            service = (
                self.session.query(Service)
                .filter(Service.tenant_id == tenant.id, Service.slug == self._slugify(name))
                .first()
            )
            if service is None:
                service = Service(
                    tenant_id=tenant.id,
                    asset_id=asset_id,
                    name=name,
                    slug=self._slugify(name),
                    service_type=item.get("type") or "application",
                    environment=((document.get("metadata") or {}).get("lifecycles", [{}])[0] or {}).get("name"),
                    owner=((item.get("provider") or {}).get("name") if isinstance(item.get("provider"), dict) else None),
                    business_criticality="high" if item.get("x-trust-boundary") else "medium",
                    internet_exposed=False,
                    description=item.get("description"),
                    meta={"bom_ref": bom_ref},
                )
                self.session.add(service)
                self.session.flush()
                created += 1
            service_map[bom_ref] = service
        return service_map, created

    def _link_dependencies(self, tenant: Tenant, *, document: dict, service_map: Dict[str, Service]) -> int:
        count = 0
        dependencies = document.get("dependencies", []) or []
        for dependency in dependencies:
            ref = dependency.get("ref")
            service = service_map.get(ref)
            if service is None:
                continue
            depends_on = dependency.get("dependsOn", []) or dependency.get("depends_on", [])
            upstream = next((service_map.get(item) for item in depends_on if service_map.get(item)), None)
            if upstream and service.upstream_service_id != upstream.id:
                service.upstream_service_id = upstream.id
                count += 1
        return count

    def _upsert_component_note(self, tenant: Tenant, component: SoftwareComponent, item: dict) -> int:
        title = f"SBOM note: {component.name} {component.version or ''}".strip()
        existing = (
            self.session.query(KnowledgeDocument)
            .filter(
                KnowledgeDocument.tenant_id == tenant.id,
                KnowledgeDocument.document_type == "sbom-note",
                KnowledgeDocument.title == title,
            )
            .first()
        )
        payload = {
            "tenant_id": tenant.id,
            "document_type": "sbom-note",
            "title": title,
            "content": item.get("description"),
            "source_label": "CycloneDX SBOM",
            "source_url": item.get("purl") or item.get("bom-ref"),
            "meta": {"component_id": component.id},
        }
        if existing is None:
            self.session.add(KnowledgeDocument(**payload))
            return 1
        for key, value in payload.items():
            setattr(existing, key, value)
        return 0

    def _upsert_vex_statement(
        self,
        tenant: Tenant,
        *,
        component_id: int,
        cve_id: str,
        status: str,
        justification: Optional[str],
        source_url: Optional[str],
        raw_data: dict,
    ) -> tuple[int, int]:
        statement = (
            self.session.query(VexStatement)
            .filter(
                VexStatement.tenant_id == tenant.id,
                VexStatement.software_component_id == component_id,
                VexStatement.cve_id == cve_id,
            )
            .first()
        )
        if statement is None:
            statement = VexStatement(
                tenant_id=tenant.id,
                software_component_id=component_id,
                cve_id=cve_id,
                status=status,
                justification=justification,
                source_url=source_url,
                raw_data=raw_data,
            )
            self.session.add(statement)
            return 1, 0

        statement.status = status
        statement.justification = justification
        statement.source_url = source_url
        statement.raw_data = raw_data
        return 0, 1

    def _match_components(self, tenant: Tenant, affects: List[dict]) -> List[int]:
        ids: List[int] = []
        for item in affects:
            ref = item.get("ref") or item.get("bom-ref") or item.get("@id") or ""
            query = self.session.query(SoftwareComponent).filter(SoftwareComponent.tenant_id == tenant.id)
            component = None
            if ref:
                component = next(
                    (
                        candidate
                        for candidate in query.all()
                        if (candidate.meta or {}).get("bom_ref") == ref
                    ),
                    None,
                )
            if component is None and item.get("name"):
                component = query.filter(SoftwareComponent.name == item.get("name"), SoftwareComponent.version == item.get("version")).first()
            if component is not None:
                ids.append(component.id)
        return ids

    @staticmethod
    def _normalize_vex_status(status: str) -> str:
        normalized = (status or "under_investigation").lower().strip()
        mapping = {
            "not_affected": "not_affected",
            "fixed": "fixed",
            "resolved": "fixed",
            "affected": "affected",
            "exploitable": "affected",
            "under_investigation": "under_investigation",
            "in_triage": "under_investigation",
        }
        return mapping.get(normalized, normalized)

    @staticmethod
    def _slugify(value: str) -> str:
        return "-".join(part for part in value.lower().replace("/", " ").split() if part)
