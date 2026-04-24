"""Exposure graph construction and attack-path queries.

The graph uses one persisted node/edge model (:class:`ExposureGraphNode`,
:class:`ExposureGraphEdge`). Nodes represent tenant assets, services,
software components, identities, CVEs, patches, and — as of V4 Phase C
slice 4 — malware-lab indicators, findings, and specimens. Edges carry a
deterministic weight used by the attack-path search.

IOC pivot vocabulary (V4 Phase C slice 4):

- ``ioc_to_finding`` — weight = finding.confidence
- ``ioc_to_specimen`` — weight = 0.9 (direct provenance)
- ``ioc_to_cve`` — weight = 0.5 (inferred co-reference)
- ``ioc_to_asset`` — weight = 0.6 (observed on asset)
- ``ioc_cooccurs_with`` — weight = shared_cases / max(case_count_a, case_count_b)
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sqlalchemy.orm import Session

from app.core.cache import cache_get_json, cache_set_json
from app.models.asset import Asset, AssetVulnerability
from app.models.cve import AffectedProduct, CVE
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
)
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


#: Edge kinds introduced by the V4 Phase C slice-4 IOC pivot extension.
IOC_EDGE_KINDS: frozenset[str] = frozenset(
    {
        "ioc_to_finding",
        "ioc_to_specimen",
        "ioc_to_cve",
        "ioc_to_asset",
        "ioc_cooccurs_with",
    }
)

#: Node types introduced alongside the IOC pivot graph.
IOC_NODE_TYPES: frozenset[str] = frozenset(
    {"indicator", "finding", "specimen"}
)

#: Deterministic weights for non-confidence-driven IOC edges.
_IOC_TO_SPECIMEN_WEIGHT = 0.9
_IOC_TO_CVE_WEIGHT = 0.5
_IOC_TO_ASSET_WEIGHT = 0.6


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
        cache_key = f"sheshnaag:v2:graph:{tenant.id}:{asset_id or 'all'}:{cve_id or 'all'}:{limit}"
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

    # ------------------------------------------------------------------
    # V4 Phase C slice 4 — IOC pivot graph
    # ------------------------------------------------------------------

    def rebuild_ioc_graph(
        self,
        tenant: Tenant,
        *,
        case_id: Optional[int] = None,
    ) -> Dict[str, int]:
        """Build or refresh indicator-centric nodes and edges for ``tenant``.

        This incrementally overlays IOC pivot nodes / edges on top of the
        existing exposure graph. Existing indicator nodes and all IOC-kind
        edges for the tenant (optionally scoped to a single case) are removed
        and rewritten from the current canonical state of
        ``IndicatorArtifact`` / ``BehaviorFinding`` / ``Specimen`` /
        ``AnalysisCase`` tables. The base exposure-graph nodes and edges
        produced by :meth:`rebuild_graph` are preserved.

        Parameters
        ----------
        tenant:
            The tenant whose IOC overlay to rebuild.
        case_id:
            Optional. When given, only indicators belonging to that analysis
            case are (re)materialized; cross-case co-occurrence edges will
            still reflect the case's indicators against whichever IOC nodes
            remain in the tenant graph.

        Returns
        -------
        dict
            ``{"nodes": <n_indicator_nodes>, "edges": <n_ioc_edges>}``.
        """

        indicator_query = self.session.query(IndicatorArtifact).filter(
            IndicatorArtifact.tenant_id == tenant.id
        )
        if case_id is not None:
            indicator_query = indicator_query.filter(
                IndicatorArtifact.analysis_case_id == case_id
            )
        indicators: List[IndicatorArtifact] = indicator_query.all()
        indicator_ids = {ind.id for ind in indicators}

        # ---- remove the stale slice ----------------------------------------
        # Pull all nodes we need to consider for deletion. Any edge of an
        # IOC kind whose endpoint indicator is in scope is rewritten below.
        existing_nodes = (
            self.session.query(ExposureGraphNode)
            .filter(ExposureGraphNode.tenant_id == tenant.id)
            .all()
        )
        existing_node_by_key: Dict[str, ExposureGraphNode] = {
            node.node_key: node for node in existing_nodes
        }
        existing_node_by_id: Dict[int, ExposureGraphNode] = {
            node.id: node for node in existing_nodes
        }

        indicator_node_keys_in_scope = {
            f"indicator:{ind.id}" for ind in indicators
        }

        ioc_edge_ids_to_delete: List[int] = []
        for edge in (
            self.session.query(ExposureGraphEdge)
            .filter(
                ExposureGraphEdge.tenant_id == tenant.id,
                ExposureGraphEdge.edge_type.in_(sorted(IOC_EDGE_KINDS)),
            )
            .all()
        ):
            from_node = existing_node_by_id.get(edge.from_node_id)
            to_node = existing_node_by_id.get(edge.to_node_id)
            if case_id is None:
                ioc_edge_ids_to_delete.append(edge.id)
                continue
            # case-scoped rebuild — only drop edges incident on in-scope indicators
            if (
                from_node is not None
                and from_node.node_key in indicator_node_keys_in_scope
            ) or (
                to_node is not None
                and to_node.node_key in indicator_node_keys_in_scope
            ):
                ioc_edge_ids_to_delete.append(edge.id)

        if ioc_edge_ids_to_delete:
            self.session.query(ExposureGraphEdge).filter(
                ExposureGraphEdge.id.in_(ioc_edge_ids_to_delete)
            ).delete(synchronize_session="fetch")

        # Indicator/finding/specimen nodes in scope are recreated fresh.
        stale_node_ids: List[int] = []
        for node in existing_nodes:
            if node.node_type not in IOC_NODE_TYPES:
                continue
            if case_id is None:
                stale_node_ids.append(node.id)
                continue
            if node.node_key in indicator_node_keys_in_scope:
                stale_node_ids.append(node.id)
        if stale_node_ids:
            # Edges that reference these nodes (even non-IOC-kind ones) must
            # go first to satisfy FK constraints. Use ``fetch`` so the
            # identity map is expired for the deleted rows.
            self.session.query(ExposureGraphEdge).filter(
                ExposureGraphEdge.tenant_id == tenant.id,
                (
                    ExposureGraphEdge.from_node_id.in_(stale_node_ids)
                    | ExposureGraphEdge.to_node_id.in_(stale_node_ids)
                ),
            ).delete(synchronize_session="fetch")
            self.session.query(ExposureGraphNode).filter(
                ExposureGraphNode.id.in_(stale_node_ids)
            ).delete(synchronize_session="fetch")

        self.session.flush()
        # Expire any cached ORM state so the subsequent re-read sees the
        # post-delete world rather than a stale identity-map view.
        self.session.expire_all()

        # ---- refresh cache of nodes after deletion -------------------------
        existing_nodes = (
            self.session.query(ExposureGraphNode)
            .filter(ExposureGraphNode.tenant_id == tenant.id)
            .all()
        )
        node_by_key: Dict[str, ExposureGraphNode] = {
            node.node_key: node for node in existing_nodes
        }

        def ensure_node(
            node_type: str,
            node_key: str,
            label: str,
            metadata: Optional[dict] = None,
        ) -> ExposureGraphNode:
            existing = node_by_key.get(node_key)
            if existing is not None:
                return existing
            node = ExposureGraphNode(
                tenant_id=tenant.id,
                node_type=node_type,
                node_key=node_key,
                label=label,
                meta=metadata or {},
            )
            self.session.add(node)
            self.session.flush()
            node_by_key[node_key] = node
            return node

        # ---- gather dependent rows -----------------------------------------
        findings_by_case: Dict[int, List[BehaviorFinding]] = defaultdict(list)
        findings_by_id: Dict[int, BehaviorFinding] = {}
        if indicators:
            case_ids_needed = {ind.analysis_case_id for ind in indicators}
            for finding in (
                self.session.query(BehaviorFinding)
                .filter(
                    BehaviorFinding.tenant_id == tenant.id,
                    BehaviorFinding.analysis_case_id.in_(case_ids_needed),
                )
                .all()
            ):
                findings_by_case[finding.analysis_case_id].append(finding)
                findings_by_id[finding.id] = finding

        specimens_by_id: Dict[int, Specimen] = {
            spec.id: spec
            for spec in self.session.query(Specimen)
            .filter(Specimen.tenant_id == tenant.id)
            .all()
        }

        cases_by_id: Dict[int, AnalysisCase] = {
            case.id: case
            for case in self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id)
            .all()
        }

        assets_by_id: Dict[int, Asset] = {
            asset.id: asset
            for asset in self.session.query(Asset)
            .filter(Asset.tenant_id == tenant.id)
            .all()
        }

        cves_by_id: Dict[str, CVE] = {
            cve.cve_id.upper(): cve
            for cve in self.session.query(CVE).all()
        }

        # For co-occurrence we need the full case-membership map for every
        # *logical* indicator in the tenant (identified by ``(kind, value)``
        # — the same IOC may be represented by multiple rows across cases).
        # We collapse rows to their canonical identity so the formula
        # ``shared / max(total_cases)`` matches the architecture spec.
        tenant_indicators: List[IndicatorArtifact] = (
            self.session.query(IndicatorArtifact)
            .filter(IndicatorArtifact.tenant_id == tenant.id)
            .all()
        )
        indicator_by_id: Dict[int, IndicatorArtifact] = {
            ind.id: ind for ind in tenant_indicators
        }
        # canonical identity -> set of case ids the IOC appears in
        cases_per_identity: Dict[str, Set[int]] = defaultdict(set)
        # canonical identity -> set of indicator-row ids sharing that identity
        rows_per_identity: Dict[str, Set[int]] = defaultdict(set)
        for ind in tenant_indicators:
            identity_key = self._indicator_value_key(ind)
            cases_per_identity[identity_key].add(ind.analysis_case_id)
            rows_per_identity[identity_key].add(ind.id)

        # ---- materialize indicator / finding / specimen nodes --------------
        edges_created = 0

        for ind in indicators:
            ind_key = f"indicator:{ind.id}"
            ensure_node(
                "indicator",
                ind_key,
                ind.value,
                {
                    "indicator_kind": ind.indicator_kind,
                    "value": ind.value,
                    "status": ind.status,
                    "confidence": float(ind.confidence or 0.0),
                    "analysis_case_id": ind.analysis_case_id,
                },
            )

        for case_id_key, case_findings in findings_by_case.items():
            for finding in case_findings:
                f_key = f"finding:{finding.id}"
                ensure_node(
                    "finding",
                    f_key,
                    finding.title,
                    {
                        "finding_type": finding.finding_type,
                        "severity": finding.severity,
                        "confidence": float(finding.confidence or 0.0),
                        "analysis_case_id": finding.analysis_case_id,
                        "run_id": finding.run_id,
                    },
                )

        # Specimen nodes are created lazily when an indicator references a
        # specimen through its payload or case linkage.
        def ensure_specimen_node(specimen: Specimen) -> ExposureGraphNode:
            spec_key = f"specimen:{specimen.id}"
            return ensure_node(
                "specimen",
                spec_key,
                specimen.name,
                {
                    "specimen_kind": specimen.specimen_kind,
                    "risk_level": specimen.risk_level,
                    "status": specimen.status,
                },
            )

        # ---- emit edges ----------------------------------------------------
        def add_edge(
            from_key: str,
            to_key: str,
            edge_type: str,
            weight: float,
            metadata: Optional[dict] = None,
        ) -> bool:
            from_node = node_by_key.get(from_key)
            to_node = node_by_key.get(to_key)
            if from_node is None or to_node is None:
                return False
            self.session.add(
                ExposureGraphEdge(
                    tenant_id=tenant.id,
                    from_node_id=from_node.id,
                    to_node_id=to_node.id,
                    edge_type=edge_type,
                    weight=float(weight),
                    meta=metadata or {},
                )
            )
            return True

        for ind in indicators:
            ind_key = f"indicator:{ind.id}"
            payload = ind.payload or {}

            # ioc_to_finding -------------------------------------------------
            finding_ids_linked: Set[int] = set()
            # explicit link via payload
            for raw_fid in self._iter_ints(payload.get("finding_ids")):
                finding_ids_linked.add(raw_fid)
            # fallback: all findings in the same case
            if not finding_ids_linked:
                for finding in findings_by_case.get(ind.analysis_case_id, []):
                    finding_ids_linked.add(finding.id)
            for fid in finding_ids_linked:
                finding = findings_by_id.get(fid)
                if finding is None:
                    continue
                weight = float(finding.confidence or 0.0)
                if add_edge(
                    ind_key,
                    f"finding:{finding.id}",
                    "ioc_to_finding",
                    weight,
                    {
                        "finding_id": finding.id,
                        "case_id": finding.analysis_case_id,
                    },
                ):
                    edges_created += 1

            # ioc_to_specimen ------------------------------------------------
            specimen_ids_linked: Set[int] = set()
            for raw_sid in self._iter_ints(payload.get("specimen_ids")):
                specimen_ids_linked.add(raw_sid)
            case = cases_by_id.get(ind.analysis_case_id)
            if case is not None:
                for raw_sid in self._iter_ints(case.specimen_ids):
                    specimen_ids_linked.add(raw_sid)
            for sid in specimen_ids_linked:
                specimen = specimens_by_id.get(sid)
                if specimen is None:
                    continue
                ensure_specimen_node(specimen)
                if add_edge(
                    ind_key,
                    f"specimen:{specimen.id}",
                    "ioc_to_specimen",
                    _IOC_TO_SPECIMEN_WEIGHT,
                    {"specimen_id": specimen.id},
                ):
                    edges_created += 1

            # ioc_to_cve -----------------------------------------------------
            cve_refs: Set[str] = set()
            for raw_ref in self._iter_strings(payload.get("cve_ids")):
                cve_refs.add(raw_ref.upper())
            for raw_ref in self._iter_strings(payload.get("cves")):
                cve_refs.add(raw_ref.upper())
            # If indicator value itself looks like a CVE id, co-reference it.
            if ind.indicator_kind == "cve" or (
                isinstance(ind.value, str) and ind.value.upper().startswith("CVE-")
            ):
                cve_refs.add(ind.value.upper())
            for cve_ref in cve_refs:
                cve = cves_by_id.get(cve_ref)
                if cve is None:
                    continue
                cve_key = f"cve:{cve.id}"
                # materialize the CVE node if the base graph hasn't yet.
                ensure_node(
                    "cve",
                    cve_key,
                    cve.cve_id,
                    {
                        "cve_id": cve.cve_id,
                        "cvss_v3_score": cve.cvss_v3_score,
                        "exploit_available": bool(cve.exploit_available),
                    },
                )
                if add_edge(
                    ind_key,
                    cve_key,
                    "ioc_to_cve",
                    _IOC_TO_CVE_WEIGHT,
                    {"cve_id": cve.cve_id},
                ):
                    edges_created += 1

            # ioc_to_asset ---------------------------------------------------
            asset_ids_linked: Set[int] = set()
            for raw_aid in self._iter_ints(payload.get("asset_ids")):
                asset_ids_linked.add(raw_aid)
            # Also try to match by hostname/ip value when the kind is suggestive.
            if isinstance(ind.value, str):
                needle = ind.value.strip().lower()
                if ind.indicator_kind in {"ipv4", "ipv6", "ip", "hostname", "domain"}:
                    for asset in assets_by_id.values():
                        hostname = (asset.hostname or "").strip().lower()
                        ip_address = (asset.ip_address or "").strip().lower()
                        if needle and (needle == hostname or needle == ip_address):
                            asset_ids_linked.add(asset.id)
            for aid in asset_ids_linked:
                asset = assets_by_id.get(aid)
                if asset is None:
                    continue
                asset_key = f"asset:{asset.id}"
                ensure_node(
                    "asset",
                    asset_key,
                    asset.name,
                    {
                        "criticality": asset.criticality,
                        "business_criticality": asset.business_criticality,
                        "is_crown_jewel": bool(asset.is_crown_jewel),
                    },
                )
                if add_edge(
                    ind_key,
                    asset_key,
                    "ioc_to_asset",
                    _IOC_TO_ASSET_WEIGHT,
                    {"asset_id": asset.id},
                ):
                    edges_created += 1

        # ---- co-occurrence edges (undirected, emitted in canonical order) --
        #
        # Two logical indicators (``(kind, value)`` pairs) co-occur when
        # they share at least one analysis case. Weight is
        # ``shared / max(total_cases_left, total_cases_right)``. Because a
        # single logical IOC may be represented by multiple rows, we emit
        # the edge between the *minimum-id* row for each identity — one
        # canonical node pair per logical IOC pair.
        canonical_row_per_identity: Dict[str, int] = {
            identity: min(row_ids)
            for identity, row_ids in rows_per_identity.items()
            if row_ids
        }
        considered_identities = sorted(canonical_row_per_identity.keys())
        seen_pairs: Set[Tuple[int, int]] = set()
        for i, left_identity in enumerate(considered_identities):
            left_cases = cases_per_identity.get(left_identity, set())
            if not left_cases:
                continue
            left_row_id = canonical_row_per_identity[left_identity]
            for right_identity in considered_identities[i + 1 :]:
                right_cases = cases_per_identity.get(right_identity, set())
                shared = left_cases & right_cases
                if not shared:
                    continue
                denom = max(len(left_cases), len(right_cases))
                if denom == 0:
                    continue
                weight = len(shared) / denom
                right_row_id = canonical_row_per_identity[right_identity]
                if left_row_id == right_row_id:
                    continue
                pair = (
                    min(left_row_id, right_row_id),
                    max(left_row_id, right_row_id),
                )
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                # When performing a case-scoped rebuild, only emit pairs
                # where at least one endpoint's logical IOC participates
                # in the in-scope case.
                if case_id is not None:
                    left_in_scope = any(
                        rid in indicator_ids
                        for rid in rows_per_identity[left_identity]
                    )
                    right_in_scope = any(
                        rid in indicator_ids
                        for rid in rows_per_identity[right_identity]
                    )
                    if not (left_in_scope or right_in_scope):
                        continue
                metadata = {
                    "shared_cases": sorted(shared),
                    "case_count_left": len(left_cases),
                    "case_count_right": len(right_cases),
                    "left_identity": left_identity,
                    "right_identity": right_identity,
                }
                if add_edge(
                    f"indicator:{left_row_id}",
                    f"indicator:{right_row_id}",
                    "ioc_cooccurs_with",
                    weight,
                    metadata,
                ):
                    edges_created += 1
                if add_edge(
                    f"indicator:{right_row_id}",
                    f"indicator:{left_row_id}",
                    "ioc_cooccurs_with",
                    weight,
                    metadata,
                ):
                    edges_created += 1

        self.session.flush()
        indicator_nodes = sum(
            1 for key in node_by_key if key.startswith("indicator:")
        )
        return {"nodes": indicator_nodes, "edges": edges_created}

    def ioc_neighborhood(
        self,
        tenant: Tenant,
        *,
        indicator_value: str,
        depth: int = 2,
    ) -> Dict[str, object]:
        """Return a subgraph of nodes reachable from ``indicator_value`` within ``depth`` hops.

        Uses the undirected adjacency of the persisted graph so pivots
        traverse ``ioc_cooccurs_with`` and other edges symmetrically. The
        result contains the nodes, edges, and the starting indicator node
        (if it exists).
        """

        if depth < 0:
            raise ValueError("depth must be >= 0")
        needle = (indicator_value or "").strip()
        if not needle:
            raise ValueError("indicator_value is required")

        start_nodes = (
            self.session.query(ExposureGraphNode)
            .filter(
                ExposureGraphNode.tenant_id == tenant.id,
                ExposureGraphNode.node_type == "indicator",
                ExposureGraphNode.label == needle,
            )
            .all()
        )
        if not start_nodes:
            return {
                "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
                "indicator_value": indicator_value,
                "root_node_ids": [],
                "nodes": [],
                "edges": [],
                "depth": depth,
            }

        nodes = (
            self.session.query(ExposureGraphNode)
            .filter(ExposureGraphNode.tenant_id == tenant.id)
            .all()
        )
        edges = (
            self.session.query(ExposureGraphEdge)
            .filter(ExposureGraphEdge.tenant_id == tenant.id)
            .all()
        )
        node_by_id: Dict[int, ExposureGraphNode] = {node.id: node for node in nodes}

        undirected: Dict[int, List[Tuple[int, ExposureGraphEdge]]] = defaultdict(list)
        for edge in edges:
            undirected[edge.from_node_id].append((edge.to_node_id, edge))
            undirected[edge.to_node_id].append((edge.from_node_id, edge))

        reachable_ids: Set[int] = set()
        reachable_edge_ids: Set[int] = set()
        frontier: deque[Tuple[int, int]] = deque(
            (node.id, 0) for node in start_nodes
        )
        for node in start_nodes:
            reachable_ids.add(node.id)
        while frontier:
            current_id, distance = frontier.popleft()
            if distance >= depth:
                continue
            for neighbor_id, edge in undirected.get(current_id, []):
                reachable_edge_ids.add(edge.id)
                if neighbor_id not in reachable_ids:
                    reachable_ids.add(neighbor_id)
                    frontier.append((neighbor_id, distance + 1))

        slice_nodes = [node_by_id[nid] for nid in reachable_ids if nid in node_by_id]
        slice_edges = [edge for edge in edges if edge.id in reachable_edge_ids]

        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "indicator_value": indicator_value,
            "root_node_ids": [node.id for node in start_nodes],
            "nodes": [self._serialize_node(node) for node in slice_nodes],
            "edges": [self._serialize_edge(edge) for edge in slice_edges],
            "depth": depth,
        }

    def attack_paths_for_ioc(
        self,
        tenant: Tenant,
        *,
        indicator_value: str,
        top_k: int = 10,
    ) -> Dict[str, object]:
        """Return top attack paths that originate at the given indicator.

        Reuses :meth:`_search_paths` with the indicator node(s) as starting
        points and crown-jewel / exploit-available assets and CVEs as
        targets. IOC edges participate in traversal just like base edges.
        """

        if top_k <= 0:
            raise ValueError("top_k must be > 0")
        needle = (indicator_value or "").strip()
        if not needle:
            raise ValueError("indicator_value is required")

        nodes = (
            self.session.query(ExposureGraphNode)
            .filter(ExposureGraphNode.tenant_id == tenant.id)
            .all()
        )
        edges = (
            self.session.query(ExposureGraphEdge)
            .filter(ExposureGraphEdge.tenant_id == tenant.id)
            .all()
        )
        node_by_id: Dict[int, ExposureGraphNode] = {node.id: node for node in nodes}

        start_nodes = [
            node
            for node in nodes
            if node.node_type == "indicator" and node.label == needle
        ]
        if not start_nodes:
            return {
                "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
                "indicator_value": indicator_value,
                "paths": [],
            }

        adjacency: Dict[int, List[Tuple[int, ExposureGraphEdge]]] = defaultdict(list)
        for edge in edges:
            adjacency[edge.from_node_id].append((edge.to_node_id, edge))
            # IOC pivot paths are useful in both directions — the co-occurrence
            # edge is stored twice but ioc_to_* edges should also allow the
            # analyst to pivot from the indicator toward the asset/cve.
            # Allow reverse traversal for the undirected co-occurrence edge.
            if edge.edge_type == "ioc_cooccurs_with":
                continue

        target_ids: Set[int] = set()
        for node in nodes:
            if node.node_type == "asset" and (node.meta or {}).get("is_crown_jewel"):
                target_ids.add(node.id)
            elif node.node_type == "cve":
                target_ids.add(node.id)

        paths = self._search_paths(
            node_by_id,
            adjacency,
            [node.id for node in start_nodes],
            target_ids,
            limit=top_k,
        )
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "indicator_value": indicator_value,
            "paths": paths,
        }

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _indicator_value_key(ind: IndicatorArtifact) -> str:
        return f"{ind.indicator_kind}:{ind.value}".lower()

    @staticmethod
    def _iter_ints(raw) -> Iterable[int]:
        if not raw:
            return []
        if isinstance(raw, (int,)):
            return [raw]
        if isinstance(raw, (list, tuple, set)):
            out: List[int] = []
            for item in raw:
                try:
                    out.append(int(item))
                except (TypeError, ValueError):
                    continue
            return out
        try:
            return [int(raw)]
        except (TypeError, ValueError):
            return []

    @staticmethod
    def _iter_strings(raw) -> Iterable[str]:
        if not raw:
            return []
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, (list, tuple, set)):
            return [str(item) for item in raw if item]
        return [str(raw)]

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

    def case_graph(self, tenant: Tenant, *, case_id: int, depth: int = 2) -> Dict[str, object]:
        """Return a subgraph anchored on an :class:`AnalysisCase`.

        The case node is virtual: we synthesise a single ``case`` node and
        attach edges from each indicator and finding linked to the case.
        Then we expand outward by ``depth`` hops over the persisted IOC
        pivot edges so the analyst sees specimens, IOCs, CVEs, and assets
        related to the case in one view.
        """

        case = (
            self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id, AnalysisCase.id == case_id)
            .first()
        )
        if case is None:
            return {
                "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
                "case": None,
                "nodes": [],
                "edges": [],
                "depth": depth,
            }

        indicators = (
            self.session.query(IndicatorArtifact)
            .filter(
                IndicatorArtifact.tenant_id == tenant.id,
                IndicatorArtifact.analysis_case_id == case_id,
            )
            .all()
        )
        findings = (
            self.session.query(BehaviorFinding)
            .filter(
                BehaviorFinding.tenant_id == tenant.id,
                BehaviorFinding.analysis_case_id == case_id,
            )
            .all()
        )

        all_nodes = (
            self.session.query(ExposureGraphNode)
            .filter(ExposureGraphNode.tenant_id == tenant.id)
            .all()
        )
        all_edges = (
            self.session.query(ExposureGraphEdge)
            .filter(ExposureGraphEdge.tenant_id == tenant.id)
            .all()
        )
        node_by_id: Dict[int, ExposureGraphNode] = {node.id: node for node in all_nodes}
        node_by_key: Dict[str, ExposureGraphNode] = {node.node_key: node for node in all_nodes}

        seed_keys: Set[str] = set()
        for ind in indicators:
            seed_keys.add(f"indicator:{ind.id}")
        for finding in findings:
            seed_keys.add(f"finding:{finding.id}")

        seed_ids: Set[int] = {
            node_by_key[key].id for key in seed_keys if key in node_by_key
        }

        adjacency: Dict[int, List[Tuple[int, ExposureGraphEdge]]] = defaultdict(list)
        for edge in all_edges:
            adjacency[edge.from_node_id].append((edge.to_node_id, edge))
            adjacency[edge.to_node_id].append((edge.from_node_id, edge))

        reachable_node_ids: Set[int] = set(seed_ids)
        reachable_edge_ids: Set[int] = set()
        frontier: deque[Tuple[int, int]] = deque((nid, 0) for nid in seed_ids)
        while frontier:
            current, distance = frontier.popleft()
            if distance >= depth:
                continue
            for neighbor_id, edge in adjacency.get(current, []):
                reachable_edge_ids.add(edge.id)
                if neighbor_id not in reachable_node_ids:
                    reachable_node_ids.add(neighbor_id)
                    frontier.append((neighbor_id, distance + 1))

        nodes_payload = [
            self._serialize_node(node_by_id[nid])
            for nid in reachable_node_ids
            if nid in node_by_id
        ]
        edges_payload = [
            self._serialize_edge(edge)
            for edge in all_edges
            if edge.id in reachable_edge_ids
        ]

        # Synthetic case node + edges to seed nodes give the UI an explicit
        # anchor without polluting the persisted graph schema.
        case_label = getattr(case, "title", None) or getattr(case, "name", None) or f"Case {case.id}"
        case_node = {
            "id": -case.id,
            "node_type": "case",
            "node_key": f"case:{case.id}",
            "label": case_label,
            "metadata": {
                "case_id": case.id,
                "status": case.status,
                "priority": getattr(case, "priority", None),
            },
        }
        synthetic_edges = [
            {
                "id": -1000 - idx,
                "from_node_id": -case.id,
                "to_node_id": node_by_key[key].id,
                "edge_type": "case_anchor",
                "weight": 1.0,
                "metadata": {"case_id": case.id},
            }
            for idx, key in enumerate(sorted(seed_keys))
            if key in node_by_key
        ]
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "case": {
                "id": case.id,
                "name": case_label,
                "status": case.status,
                "indicator_count": len(indicators),
                "finding_count": len(findings),
            },
            "nodes": [case_node, *nodes_payload],
            "edges": [*synthetic_edges, *edges_payload],
            "depth": depth,
        }

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
