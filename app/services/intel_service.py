"""Threat intelligence enrichments for KEV, EPSS, and ATT&CK mappings."""

from __future__ import annotations

from datetime import datetime, timedelta
from app.core.time import utc_now
from typing import Dict, Iterable, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.cve import CVE
from app.models.v2 import (
    AttackTechnique,
    CVEAttackTechnique,
    EPSSSnapshot,
    KEVEntry,
    KnowledgeDocument,
)
from app.services.knowledge_service import KnowledgeRetrievalService


class ThreatIntelService:
    """Query and seed threat-intel signals used by v2 ranking and explanations."""

    def __init__(self, session: Session):
        self.session = session
        self.knowledge = KnowledgeRetrievalService(session)

    def get_latest_epss_map(self, cve_ids: Iterable[str]) -> Dict[str, EPSSSnapshot]:
        """Return latest EPSS snapshot keyed by CVE id."""
        wanted = {c.upper() for c in cve_ids if c}
        if not wanted:
            return {}

        rows = (
            self.session.query(EPSSSnapshot)
            .filter(EPSSSnapshot.cve_id.in_(wanted))
            .order_by(EPSSSnapshot.cve_id, desc(EPSSSnapshot.scored_at))
            .all()
        )

        latest: Dict[str, EPSSSnapshot] = {}
        for row in rows:
            key = row.cve_id.upper()
            if key not in latest:
                latest[key] = row
        return latest

    def get_kev_map(self, cve_ids: Iterable[str]) -> Dict[str, KEVEntry]:
        """Return KEV membership keyed by CVE id."""
        wanted = {c.upper() for c in cve_ids if c}
        if not wanted:
            return {}

        rows = self.session.query(KEVEntry).filter(KEVEntry.cve_id.in_(wanted)).all()
        return {row.cve_id.upper(): row for row in rows}

    def get_attack_techniques_for_cves(self, cve_db_ids: Iterable[int]) -> Dict[int, List[AttackTechnique]]:
        """Return ATT&CK technique lists keyed by DB CVE id."""
        wanted = {c for c in cve_db_ids if c is not None}
        if not wanted:
            return {}

        mappings = (
            self.session.query(CVEAttackTechnique)
            .filter(CVEAttackTechnique.cve_id.in_(wanted))
            .all()
        )

        result: Dict[int, List[AttackTechnique]] = {}
        for mapping in mappings:
            result.setdefault(mapping.cve_id, []).append(mapping.technique)
        return result

    def get_knowledge_documents(self, *, cve_id: Optional[int] = None, limit: int = 10) -> List[KnowledgeDocument]:
        """Fetch knowledge documents for citations."""
        self.knowledge.backfill_knowledge_layers()
        query = self.session.query(KnowledgeDocument)
        if cve_id is not None:
            query = query.filter(KnowledgeDocument.cve_id == cve_id)
        return query.order_by(desc(KnowledgeDocument.updated_at)).limit(limit).all()

    def seed_demo_intel(self) -> None:
        """Create a compact, source-backed baseline for the public demo."""
        cves = {
            c.cve_id: c
            for c in self.session.query(CVE).filter(
                CVE.cve_id.in_(
                    [
                        "CVE-2024-10001",
                        "CVE-2024-10002",
                        "CVE-2024-10003",
                    ]
                )
            ).all()
        }
        if not cves:
            return

        now = utc_now()

        self._upsert_kev(
            cve_id="CVE-2024-10001",
            vendor_project="Acme Edge",
            product="Public API Gateway",
            short_description="Actively exploited remote code execution in internet-facing gateway software.",
            added_date=now - timedelta(days=9),
            due_date=now + timedelta(days=5),
            known_ransomware_use="Known",
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        )
        self._upsert_kev(
            cve_id="CVE-2024-10003",
            vendor_project="Acme Identity",
            product="Admin Portal",
            short_description="Exploited auth bypass enabling privileged session creation.",
            added_date=now - timedelta(days=4),
            due_date=now + timedelta(days=3),
            known_ransomware_use="Unknown",
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        )

        self._upsert_epss("CVE-2024-10001", 0.97, 0.995, now - timedelta(hours=12))
        self._upsert_epss("CVE-2024-10002", 0.61, 0.84, now - timedelta(hours=12))
        self._upsert_epss("CVE-2024-10003", 0.88, 0.97, now - timedelta(hours=12))

        technique_exec = self._upsert_technique(
            external_id="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Exploit a vulnerability in an internet-facing application to gain initial access.",
            source_url="https://attack.mitre.org/techniques/T1190/",
        )
        technique_move = self._upsert_technique(
            external_id="T1078",
            name="Valid Accounts",
            tactic="Defense Evasion",
            description="Use stolen or abused credentials to move laterally or blend with normal activity.",
            source_url="https://attack.mitre.org/techniques/T1078/",
        )

        self._upsert_cve_technique(cves["CVE-2024-10001"].id, technique_exec.id, "Internet-facing RCE on the demo API gateway.")
        self._upsert_cve_technique(cves["CVE-2024-10003"].id, technique_move.id, "Privileged access path through the admin portal.")

        self._upsert_document(
            document_type="advisory",
            title="Public API Gateway advisory",
            content="The public API gateway vulnerability enables remote code execution on internet-exposed services and should be patched immediately.",
            source_label="Vendor Advisory",
            source_url="https://example.com/advisories/public-api-gateway",
            cve_id=cves["CVE-2024-10001"].id,
        )
        self._upsert_document(
            document_type="attack-note",
            title="ATT&CK mapping for public-facing exploit",
            content="This exposure pattern maps to ATT&CK T1190 and materially increases initial access likelihood.",
            source_label="MITRE ATT&CK",
            source_url="https://attack.mitre.org/techniques/T1190/",
            cve_id=cves["CVE-2024-10001"].id,
        )
        self._upsert_document(
            document_type="advisory",
            title="Admin portal auth-bypass advisory",
            content="The administrative portal vulnerability enables session creation without valid credentials and affects privileged workflows. Patch as part of the next approved change window.",
            source_label="Vendor Advisory",
            source_url="https://example.com/advisories/admin-portal-auth-bypass",
            cve_id=cves["CVE-2024-10003"].id,
        )
        self._upsert_document(
            document_type="attack-note",
            title="ATT&CK mapping for privileged account abuse",
            content="Credential abuse and session hijacking scenarios align with ATT&CK T1078 and increase the value of the identity-admin asset in attack path analysis.",
            source_label="MITRE ATT&CK",
            source_url="https://attack.mitre.org/techniques/T1078/",
            cve_id=cves["CVE-2024-10003"].id,
        )

    def _upsert_kev(self, **payload) -> KEVEntry:
        record = self.session.query(KEVEntry).filter(KEVEntry.cve_id == payload["cve_id"]).first()
        if record is None:
            record = KEVEntry(**payload)
            self.session.add(record)
            return record

        for key, value in payload.items():
            setattr(record, key, value)
        return record

    def _upsert_epss(self, cve_id: str, score: float, percentile: float, scored_at: datetime) -> EPSSSnapshot:
        record = (
            self.session.query(EPSSSnapshot)
            .filter(EPSSSnapshot.cve_id == cve_id, EPSSSnapshot.scored_at == scored_at)
            .first()
        )
        if record is None:
            record = EPSSSnapshot(
                cve_id=cve_id,
                score=score,
                percentile=percentile,
                scored_at=scored_at,
                source_url="https://www.first.org/epss/epss_tools",
                raw_data={"score": score, "percentile": percentile},
            )
            self.session.add(record)
            return record

        record.score = score
        record.percentile = percentile
        return record

    def _upsert_technique(self, **payload) -> AttackTechnique:
        record = self.session.query(AttackTechnique).filter(AttackTechnique.external_id == payload["external_id"]).first()
        if record is None:
            record = AttackTechnique(**payload)
            self.session.add(record)
            self.session.flush()
            return record

        for key, value in payload.items():
            setattr(record, key, value)
        self.session.flush()
        return record

    def _upsert_cve_technique(self, cve_id: int, technique_id: int, rationale: str) -> CVEAttackTechnique:
        record = (
            self.session.query(CVEAttackTechnique)
            .filter(CVEAttackTechnique.cve_id == cve_id, CVEAttackTechnique.technique_id == technique_id)
            .first()
        )
        if record is None:
            record = CVEAttackTechnique(cve_id=cve_id, technique_id=technique_id, rationale=rationale)
            self.session.add(record)
            return record
        record.rationale = rationale
        return record

    def _upsert_document(self, **payload) -> KnowledgeDocument:
        record = (
            self.session.query(KnowledgeDocument)
            .filter(
                KnowledgeDocument.document_type == payload["document_type"],
                KnowledgeDocument.title == payload["title"],
                KnowledgeDocument.cve_id == payload.get("cve_id"),
            )
            .first()
        )
        if record is None:
            record = KnowledgeDocument(**payload)
            self.session.add(record)
            return record

        for key, value in payload.items():
            setattr(record, key, value)
        return record
