"""Exposure graph construction and attack-path queries."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

from app.core.cache import cache_get_json, cache_set_json
from app.models.asset import Asset, AssetVulnerability
from app.models.cve import AffectedProduct, CVE
from app.models.patch import AssetPatch, Patch
from app.models.v2 import (
    ExposureGraphEdge,
    ExposureGraphNode,
    IdentityPrincipal,
    NetworkExposure,
    Service,
    SoftwareComponent,
    Tenant,
    VexStatement,
)


class ExposureGraphService:
    """Build and query persisted tenant exposure graphs."""

    GRAPH_CACHE_SECONDS = 180

    def __init__(self, session: Session):
        self.session = session

    def rebuild_graph(self, tenant: Tenant) -> Dict[str, int]:
        """Rebuild persisted graph nodes and edges for a tenant."""
        self.session.query(ExposureGraphEdge).filter(ExposureGraphEdge.tenant_id == tenant.id).delete(synchronize_session=False)
        self.session.query(ExposureGraphNode).filter(ExposureGraphNode.tenant_id == tenant.id).delete(synchronize_session=False)
        self.session.flush()

        assets = self.session.query(Asset).filter(Asset.tenant_id == tenant.id, Asset.is_active.is_(True)).all()
        asset_ids = [asset.id for asset in assets]

        services = self.session.query(Service).filter(Service.tenant_id == tenant.id).all()
        identities = self.session.query(IdentityPrincipal).filter(IdentityPrincipal.tenant_id == tenant.id).all()
        exposures = self.session.query(NetworkExposure).filter(NetworkExposure.tenant_id == tenant.id).all()

        components = (
            self.session.query(SoftwareComponent)
            .filter(SoftwareComponent.tenant_id == tenant.id)
            .all()
        )

        open_vulns = (
            self.session.query(AssetVulnerability)
            .filter(AssetVulnerability.asset_id.in_(asset_ids), AssetVulnerability.status == "open")
            .all()
            if asset_ids
            else []
        )
        cve_ids = {row.cve_id for row in open_vulns}
        cves = self.session.query(CVE).filter(CVE.id.in_(cve_ids)).all() if cve_ids else []

        patches = (
            self.session.query(Patch)
            .join(AssetPatch, AssetPatch.patch_id == Patch.patch_id)
            .filter(AssetPatch.asset_id.in_(asset_ids))
            .all()
            if asset_ids
            else []
        )

        node_map: Dict[str, ExposureGraphNode] = {}

        def add_node(node_type: str, node_key: str, label: str, metadata: Optional[dict] = None) -> ExposureGraphNode:
            node = ExposureGraphNode(
                tenant_id=tenant.id,
                node_type=node_type,
                node_key=node_key,
                label=label,
                meta=metadata or {},
            )
            self.session.add(node)
            self.session.flush()
            node_map[node_key] = node
            return node

        for asset in assets:
            public_count = sum(1 for exposure in exposures if exposure.asset_id == asset.id and exposure.is_public)
            add_node(
                "asset",
                f"asset:{asset.id}",
                asset.name,
                {
                    "criticality": asset.criticality,
                    "business_criticality": asset.business_criticality,
                    "is_crown_jewel": bool(asset.is_crown_jewel),
                    "public_exposure_count": public_count,
                },
            )

        for service in services:
            add_node(
                "service",
                f"service:{service.id}",
                service.name,
                {
                    "service_type": service.service_type,
                    "internet_exposed": bool(service.internet_exposed),
                    "business_criticality": service.business_criticality,
                },
            )

        for component in components:
            add_node(
                "software_component",
                f"component:{component.id}",
                f"{component.vendor or 'unknown'} {component.name} {component.version or ''}".strip(),
                {
                    "vendor": component.vendor,
                    "name": component.name,
                    "version": component.version,
                },
            )

        for identity in identities:
            add_node(
                "identity",
                f"identity:{identity.id}",
                identity.name,
                {
                    "principal_type": identity.principal_type,
                    "can_admin": bool(identity.can_admin),
                    "can_lateral_move": bool(identity.can_lateral_move),
                },
            )

        for cve in cves:
            add_node(
                "cve",
                f"cve:{cve.id}",
                cve.cve_id,
                {
                    "cve_id": cve.cve_id,
                    "cvss_v3_score": cve.cvss_v3_score,
                    "exploit_available": bool(cve.exploit_available),
                },
            )

        for patch in patches:
            add_node(
                "patch",
                f"patch:{patch.patch_id}",
                patch.patch_id,
                {
                    "requires_reboot": bool(patch.requires_reboot),
                    "downtime_minutes": patch.estimated_downtime_minutes,
                },
            )

        edges: List[Tuple[str, str, str, float, dict]] = []

        for service in services:
            if service.asset_id:
                edges.append((f"asset:{service.asset_id}", f"service:{service.id}", "runs", 1.0, {}))
            if service.upstream_service_id:
                edges.append((f"service:{service.id}", f"service:{service.upstream_service_id}", "reachable_from", 1.2, {}))

        for exposure in exposures:
            if exposure.service_id:
                edges.append(
                    (
                        f"asset:{exposure.asset_id}",
                        f"service:{exposure.service_id}",
                        "exposes",
                        1.8 if exposure.is_public else 1.0,
                        {
                            "port": exposure.port,
                            "protocol": exposure.protocol,
                            "is_public": exposure.is_public,
                            "hostname": exposure.hostname,
                        },
                    )
                )

        component_cves = self._component_cve_map(component_ids=[component.id for component in components], asset_ids=asset_ids)
        for component_id, mapped_cves in component_cves.items():
            for cve in mapped_cves:
                edges.append((f"component:{component_id}", f"cve:{cve.id}", "contains_vulnerability", 1.6, {}))

        for asset in assets:
            for asset_link in asset.software_components:
                if asset_link.service_id:
                    edges.append((f"service:{asset_link.service_id}", f"component:{asset_link.software_component_id}", "depends_on", 1.0, {}))
                else:
                    edges.append((f"asset:{asset.id}", f"component:{asset_link.software_component_id}", "depends_on", 1.0, {}))

        for identity in identities:
            if identity.asset_id:
                edges.append((f"identity:{identity.id}", f"asset:{identity.asset_id}", "authenticates_to", 1.4, {}))
                if identity.can_lateral_move:
                    for service in services:
                        if service.asset_id == identity.asset_id and service.internet_exposed:
                            edges.append(
                                (
                                    f"service:{service.id}",
                                    f"identity:{identity.id}",
                                    "reachable_from",
                                    1.5,
                                    {"reason": "credential theft / lateral movement path"},
                                )
                            )

        for patch in patches:
            for cve in patch.cves or []:
                if f"cve:{cve.id}" in node_map:
                    edges.append((f"cve:{cve.id}", f"patch:{patch.patch_id}", "mitigated_by", 1.0, {}))

        for from_key, to_key, edge_type, weight, metadata in edges:
            from_node = node_map.get(from_key)
            to_node = node_map.get(to_key)
            if from_node is None or to_node is None:
                continue
            self.session.add(
                ExposureGraphEdge(
                    tenant_id=tenant.id,
                    from_node_id=from_node.id,
                    to_node_id=to_node.id,
                    edge_type=edge_type,
                    weight=weight,
                    meta=metadata or {},
                )
            )

        self.session.flush()
        return {"nodes": len(node_map), "edges": len(edges)}

    def get_attack_paths(
        self,
        tenant: Tenant,
        *,
        asset_id: Optional[int] = None,
        cve_id: Optional[str] = None,
        limit: int = 5,
    ) -> Dict[str, object]:
        """Return graph snapshot and top attack paths for the tenant."""
        cache_key = f"cve-radar:v2:graph:{tenant.id}:{asset_id or 'all'}:{cve_id or 'all'}:{limit}"
        cached = cache_get_json(cache_key)
        if cached is not None:
            return {**cached, "cached": True}

        node_count = self.session.query(ExposureGraphNode).filter(ExposureGraphNode.tenant_id == tenant.id).count()
        if node_count == 0:
            self.rebuild_graph(tenant)

        nodes = self.session.query(ExposureGraphNode).filter(ExposureGraphNode.tenant_id == tenant.id).all()
        edges = self.session.query(ExposureGraphEdge).filter(ExposureGraphEdge.tenant_id == tenant.id).all()

        node_by_id = {node.id: node for node in nodes}
        adjacency: Dict[int, List[Tuple[int, ExposureGraphEdge]]] = defaultdict(list)
        for edge in edges:
            adjacency[edge.from_node_id].append((edge.to_node_id, edge))

        start_nodes = [
            node
            for node in nodes
            if node.node_type == "service"
            and (
                bool((node.meta or {}).get("internet_exposed"))
                or bool((node.meta or {}).get("public_exposure_count"))
            )
        ]
        if not start_nodes:
            start_nodes = [node for node in nodes if node.node_type == "asset" and (node.meta or {}).get("public_exposure_count")]

        if cve_id:
            target_nodes = [node for node in nodes if node.node_type == "cve" and (node.meta or {}).get("cve_id") == cve_id.upper()]
        elif asset_id is not None:
            target_nodes = [node for node in nodes if node.node_type == "asset" and node.node_key == f"asset:{asset_id}"]
        else:
            target_nodes = [node for node in nodes if node.node_type == "cve"]

        target_ids = {node.id for node in target_nodes}
        top_paths = self._search_paths(node_by_id, adjacency, [node.id for node in start_nodes], target_ids, limit=limit)

        payload = {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "nodes": [self._serialize_node(node) for node in nodes],
            "edges": [self._serialize_edge(edge) for edge in edges],
            "paths": top_paths,
        }
        cache_set_json(cache_key, payload, ex=self.GRAPH_CACHE_SECONDS)
        return {**payload, "cached": False}

    def count_paths_to_cves(self, tenant: Tenant, cve_ids: Sequence[str]) -> int:
        """Convenience helper for recommendation ranking."""
        if not cve_ids:
            return 0
        result = self.get_attack_paths(tenant, limit=20)
        wanted = {c.upper() for c in cve_ids}
        return sum(1 for path in result["paths"] if any(label in wanted for label in path.get("labels", [])))

    def _component_cve_map(self, *, component_ids: List[int], asset_ids: List[int]) -> Dict[int, List[CVE]]:
        if not component_ids:
            return {}

        blocked_statuses = {"not_affected", "fixed"}
        blocked_pairs = {
            (statement.software_component_id, statement.cve_id.upper())
            for statement in self.session.query(VexStatement)
            .filter(VexStatement.software_component_id.in_(component_ids))
            .all()
            if statement.status in blocked_statuses
        }

        open_vulns = (
            self.session.query(AssetVulnerability, CVE)
            .join(CVE, CVE.id == AssetVulnerability.cve_id)
            .filter(AssetVulnerability.asset_id.in_(asset_ids), AssetVulnerability.status == "open")
            .all()
            if asset_ids
            else []
        )
        by_component: Dict[int, List[CVE]] = defaultdict(list)

        components = self.session.query(SoftwareComponent).filter(SoftwareComponent.id.in_(component_ids)).all()
        component_index = {component.id: component for component in components}
        affected_products = self.session.query(AffectedProduct).all()

        for component_id, component in component_index.items():
            matching_cves: Dict[int, CVE] = {}
            for vuln, cve in open_vulns:
                if cve.id not in matching_cves:
                    matching_cves[cve.id] = cve

            for affected in affected_products:
                vendor_match = component.vendor and affected.vendor and component.vendor.lower() == affected.vendor.lower()
                product_match = affected.product and component.name.lower() == affected.product.lower()
                if vendor_match and product_match:
                    cve = self.session.query(CVE).filter(CVE.id == affected.cve_id).first()
                    if cve:
                        matching_cves[cve.id] = cve

            filtered = [
                cve
                for cve in matching_cves.values()
                if (component_id, cve.cve_id.upper()) not in blocked_pairs
            ]
            by_component[component_id] = filtered

        return by_component

    def _search_paths(
        self,
        node_by_id: Dict[int, ExposureGraphNode],
        adjacency: Dict[int, List[Tuple[int, ExposureGraphEdge]]],
        start_ids: List[int],
        target_ids: set[int],
        *,
        limit: int,
        max_depth: int = 6,
    ) -> List[dict]:
        paths: List[dict] = []

        for start_id in start_ids:
            queue = deque([(start_id, [start_id], [], 0.0)])
            while queue:
                current, node_path, edge_path, score = queue.popleft()
                if len(node_path) > max_depth:
                    continue
                if current in target_ids and len(node_path) > 1:
                    labels = [node_by_id[node_id].label for node_id in node_path]
                    paths.append(
                        {
                            "score": round(score, 3),
                            "node_ids": node_path,
                            "labels": labels,
                            "edge_types": [edge.edge_type for edge in edge_path],
                            "summary": " -> ".join(labels),
                        }
                    )
                    continue

                for next_id, edge in adjacency.get(current, []):
                    if next_id in node_path:
                        continue
                    next_score = score + float(edge.weight or 1.0)
                    if (node_by_id[next_id].meta or {}).get("is_crown_jewel"):
                        next_score += 1.0
                    if node_by_id[next_id].node_type == "cve" and (node_by_id[next_id].meta or {}).get("exploit_available"):
                        next_score += 0.8
                    queue.append((next_id, node_path + [next_id], edge_path + [edge], next_score))

        paths.sort(key=lambda item: item["score"], reverse=True)
        return paths[:limit]

    @staticmethod
    def _serialize_node(node: ExposureGraphNode) -> dict:
        return {
            "id": node.id,
            "node_type": node.node_type,
            "node_key": node.node_key,
            "label": node.label,
            "metadata": node.meta or {},
        }

    @staticmethod
    def _serialize_edge(edge: ExposureGraphEdge) -> dict:
        return {
            "id": edge.id,
            "from_node_id": edge.from_node_id,
            "to_node_id": edge.to_node_id,
            "edge_type": edge.edge_type,
            "weight": edge.weight,
            "metadata": edge.meta or {},
        }
