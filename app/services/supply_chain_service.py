"""Supply-chain focused product metadata and narrative surfaces."""

from __future__ import annotations

from datetime import datetime
from app.core.time import utc_now
from typing import Dict, List

from sqlalchemy.orm import Session

from app.models.v2 import (
    AttackTechnique,
    EPSSSnapshot,
    ExposureGraphEdge,
    ExposureGraphNode,
    KEVEntry,
    KnowledgeDocument,
)


class SupplyChainService:
    """Expose source breadth and supply-chain attack storytelling metadata."""

    def __init__(self, session: Session):
        self.session = session

    def get_overview(self, tenant_id: int | None = None) -> Dict[str, object]:
        graph_nodes = (
            self.session.query(ExposureGraphNode)
            .filter(ExposureGraphNode.tenant_id == tenant_id)
            .count()
            if tenant_id is not None
            else self.session.query(ExposureGraphNode).count()
        )
        graph_edges = (
            self.session.query(ExposureGraphEdge)
            .filter(ExposureGraphEdge.tenant_id == tenant_id)
            .count()
            if tenant_id is not None
            else self.session.query(ExposureGraphEdge).count()
        )

        return {
            "generated_at": utc_now().isoformat(),
            "mission": {
                "headline": "Understand and predict AI-era software supply-chain attacks before they become operational damage.",
                "summary": (
                    "Project Sheshnaag frames modern attacks as source-fused, graph-aware supply-chain campaigns: "
                    "vulnerability disclosure, package exposure, adversary technique mapping, blast-radius reasoning, "
                    "and remediation planning."
                ),
            },
            "source_catalog": self._source_catalog(),
            "attack_story": [
                {
                    "title": "Dependency signal appears",
                    "detail": "A vulnerable component or service enters the graph through SBOM, advisory, or CVE intelligence.",
                    "signal": "Correlate CVE, package, vendor, and product aliases into a single entity.",
                },
                {
                    "title": "Exploitability accelerates",
                    "detail": "EPSS, KEV, exploit sightings, and ATT&CK mappings turn static severity into dynamic likelihood.",
                    "signal": "Track which issues have real-world abuse potential rather than just high CVSS numbers.",
                },
                {
                    "title": "Exposure reaches production",
                    "detail": "Internet-facing services, crown-jewel assets, and trust relationships determine blast radius.",
                    "signal": "Persist attack-path edges so defenders can see the route from library flaw to business impact.",
                },
                {
                    "title": "Analyst decision loop closes",
                    "detail": "Simulation, approvals, and feedback shape practical remediation plans instead of one-shot scores.",
                    "signal": "Keep the prioritization explainable and auditable for engineering and AppSec teams.",
                },
            ],
            "ai_threats": [
                {
                    "title": "Model-assisted phishing to token theft",
                    "summary": "Attackers use generative tooling to scale social engineering against developers and CI maintainers.",
                    "detection": "Watch for credential abuse tied to privileged package publishing or repo automation identities.",
                    "defense": "Require stronger publisher identity, protected release workflows, and auditable approval gates.",
                },
                {
                    "title": "Typosquatting and dependency confusion at scale",
                    "summary": "AI lowers the cost of generating believable malicious packages and package metadata.",
                    "detection": "Correlate package provenance, repository trust, and import behavior with vulnerability intelligence.",
                    "defense": "Use SBOM ingestion, source allowlists, private registries, and package reputation signals.",
                },
                {
                    "title": "Adversarial exploit chaining",
                    "summary": "Attackers combine public-facing flaws with identity or lateral-movement opportunities across the graph.",
                    "detection": "Score not only the CVE but the reachable path through assets, services, and identities.",
                    "defense": "Patch the enabling path, not just the loudest node, and simulate reduction before rollout.",
                },
            ],
            "defense_layers": [
                {
                    "title": "Source fusion",
                    "detail": "Blend NVD, exploit intelligence, KEV, EPSS, ATT&CK, SBOM, and VEX into one decision surface.",
                },
                {
                    "title": "Graph-aware reasoning",
                    "detail": "Model how vulnerable components sit inside services, assets, identities, and internet exposure.",
                },
                {
                    "title": "Explainable prioritization",
                    "detail": "Show evidence, citations, confidence, and governance instead of opaque ML-only decisions.",
                },
                {
                    "title": "Operational defense",
                    "detail": "Turn analysis into simulation-ready remediation actions with downtime and approval context.",
                },
            ],
            "platform_capabilities": [
                "Threat-intel fusion across multiple public and tenant-scoped data sources",
                "Persisted attack-path graph modeling for supply-chain blast-radius analysis",
                "Explainable ML trust center with drift and feedback visibility",
                "SBOM/VEX-aware remediation workflows for engineering and AppSec teams",
                f"{graph_nodes} graph nodes and {graph_edges} graph edges available in the current demo environment",
            ],
        }

    def _source_catalog(self) -> List[Dict[str, object]]:
        kev_entries = self.session.query(KEVEntry).count()
        epss_snapshots = self.session.query(EPSSSnapshot).count()
        attack_techniques = self.session.query(AttackTechnique).count()
        knowledge_documents = self.session.query(KnowledgeDocument).count()

        return [
            {
                "id": "nvd",
                "name": "NVD",
                "category": "vulnerability-disclosure",
                "status": "active",
                "coverage": "Primary CVE corpus and scoring metadata",
                "detail": "Canonical vulnerability records and CVSS context used as the baseline ingest.",
                "official_url": "https://nvd.nist.gov/",
                "signal_count": None,
            },
            {
                "id": "exploitdb",
                "name": "Exploit-DB",
                "category": "exploit-intel",
                "status": "active",
                "coverage": "Exploit availability and exploitability context",
                "detail": "Adds evidence that a vulnerability has public exploit material or offensive research behind it.",
                "official_url": "https://www.exploit-db.com/",
                "signal_count": None,
            },
            {
                "id": "kev",
                "name": "CISA KEV",
                "category": "known-exploitation",
                "status": "active",
                "coverage": "Known exploited vulnerabilities",
                "detail": "Used to emphasize active exploitation over theoretical severity.",
                "official_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "signal_count": kev_entries,
            },
            {
                "id": "epss",
                "name": "FIRST EPSS",
                "category": "exploit-prediction",
                "status": "active",
                "coverage": "Probability of exploitation in the next 30 days",
                "detail": "Supports exploit-likelihood modeling and trust-center drift comparison.",
                "official_url": "https://www.first.org/epss/",
                "signal_count": epss_snapshots,
            },
            {
                "id": "attack",
                "name": "MITRE ATT&CK",
                "category": "adversary-behavior",
                "status": "active",
                "coverage": "Technique mappings for explanation and path context",
                "detail": "Anchors vulnerable states to adversary behavior and defensive reasoning.",
                "official_url": "https://attack.mitre.org/",
                "signal_count": attack_techniques,
            },
            {
                "id": "osv",
                "name": "OSV",
                "category": "open-source-vulnerability",
                "status": "integration-next",
                "coverage": "Package-centric open source vulnerability aliases and version ranges",
                "detail": "Ideal for broadening supply-chain coverage beyond CVE-first feeds into ecosystem-native records.",
                "official_url": "https://google.github.io/osv.dev/",
                "signal_count": None,
            },
            {
                "id": "ghsa",
                "name": "GitHub Advisory Database",
                "category": "package-advisory",
                "status": "integration-next",
                "coverage": "Ecosystem advisories, package versions, and community curation",
                "detail": "Useful for package-level supply-chain intelligence and advisory cross-linking.",
                "official_url": "https://github.com/advisories",
                "signal_count": None,
            },
            {
                "id": "vex",
                "name": "SBOM and VEX",
                "category": "tenant-context",
                "status": "active",
                "coverage": "Tenant-specific component, dependency, and exploitability posture",
                "detail": "Transforms generic intelligence into environment-aware supply-chain decisions.",
                "official_url": "https://cyclonedx.org/capabilities/vex/",
                "signal_count": knowledge_documents,
            },
        ]
