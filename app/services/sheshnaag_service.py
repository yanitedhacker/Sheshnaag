"""Core application service layer for Project Sheshnaag."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from app.core.time import utc_now
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.tenancy import resolve_tenant
from app.lab.artifact_generator import DefensiveArtifactGenerator
from app.lab.attestation import HashAttestationSigner
from app.lab.collectors import default_collectors
from app.lab.docker_kali_provider import DEFAULT_KALI_IMAGE, DockerKaliProvider
from app.models.asset import Asset, AssetVulnerability
from app.models.cve import AffectedProduct, CVE
from app.models.risk_score import RiskScore
from app.models.sheshnaag import (
    AdvisoryRecord,
    AnalystIdentity,
    AttestationRecord,
    ContributionLedgerEntry,
    DetectionArtifact,
    DisclosureBundle,
    EvidenceArtifact,
    ExploitSignal,
    LabRecipe,
    LabRun,
    LabTemplate,
    MitigationArtifact,
    PackageRecord,
    ProductRecord,
    RecipeRevision,
    ResearchCandidate,
    ReviewDecision,
    RunEvent,
    SourceFeed,
    VersionRange,
    WorkstationFingerprint,
)
from app.models.v2 import EPSSSnapshot, KEVEntry, Tenant, VexStatement
from app.services.intel_service import ThreatIntelService


@dataclass
class RunArtifacts:
    """In-memory run outputs before persistence."""

    evidence: List[Dict[str, Any]]
    detections: List[Dict[str, Any]]
    mitigations: List[Dict[str, Any]]
    attestation: Dict[str, str]


class SheshnaagService:
    """Drive candidate triage, validation runs, and provenance flows."""

    def __init__(self, session: Session):
        self.session = session
        self.intel = ThreatIntelService(session)
        self.provider = DockerKaliProvider()
        self.collectors = default_collectors()
        self.artifact_generator = DefensiveArtifactGenerator()
        self.attestation_signer = HashAttestationSigner()

    def get_intel_overview(self, tenant: Tenant) -> Dict[str, Any]:
        """Return source and candidate freshness data."""
        self._ensure_source_feeds()
        self.sync_candidates(tenant)

        feeds = self.session.query(SourceFeed).order_by(SourceFeed.display_name.asc()).all()
        candidate_count = self.session.query(ResearchCandidate).filter(ResearchCandidate.tenant_id == tenant.id).count()
        active_runs = (
            self.session.query(LabRun)
            .filter(LabRun.tenant_id == tenant.id, LabRun.state.in_(["planned", "running"]))
            .count()
        )
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "generated_at": utc_now().isoformat(),
            "mission": {
                "headline": "Live CVE intelligence to isolated validation, defensive artifacts, and signed research evidence.",
                "summary": (
                    "Project Sheshnaag turns vulnerability intelligence into research candidates, constrained Linux validation plans, "
                    "reviewable evidence, defensive artifacts, and provenance-rich disclosure bundles."
                ),
            },
            "sources": [
                {
                    "feed_key": feed.feed_key,
                    "display_name": feed.display_name,
                    "category": feed.category,
                    "status": feed.status,
                    "source_url": feed.source_url,
                    "last_synced_at": feed.last_synced_at.isoformat() if feed.last_synced_at else None,
                    "freshness_seconds": feed.freshness_seconds,
                }
                for feed in feeds
            ],
            "summary": {
                "candidate_count": candidate_count,
                "active_runs": active_runs,
                "disclosure_bundles": self.session.query(DisclosureBundle).filter(DisclosureBundle.tenant_id == tenant.id).count(),
            },
        }

    def sync_candidates(self, tenant: Tenant) -> None:
        """Populate research candidates from current CVE/intel context."""
        self._ensure_source_feeds()
        cves = self.session.query(CVE).order_by(desc(CVE.published_date), desc(CVE.id)).limit(20).all()
        if not cves:
            return

        epss_map = self.intel.get_latest_epss_map([c.cve_id for c in cves])
        kev_map = self.intel.get_kev_map([c.cve_id for c in cves])
        latest_risk = self._latest_risk_by_cve_id([c.id for c in cves])

        for cve in cves:
            candidate = (
                self.session.query(ResearchCandidate)
                .filter(ResearchCandidate.tenant_id == tenant.id, ResearchCandidate.cve_id == cve.id)
                .first()
            )
            affected = self.session.query(AffectedProduct).filter(AffectedProduct.cve_id == cve.id).first()
            product = self._ensure_product_record(affected)
            package = self._ensure_package_record(affected)
            explainability = self._build_candidate_explainability(
                cve=cve,
                tenant=tenant,
                risk=latest_risk.get(cve.id),
                kev=kev_map.get(cve.cve_id.upper()),
                epss=epss_map.get(cve.cve_id.upper()),
                affected=affected,
            )
            score = explainability["score"]
            status = "queued" if score >= 35 else "deferred"

            if candidate is None:
                candidate = ResearchCandidate(
                    tenant_id=tenant.id,
                    cve_id=cve.id,
                    package_record_id=package.id if package else None,
                    product_record_id=product.id if product else None,
                    title=f"{cve.cve_id} defensive validation candidate",
                    summary=cve.description,
                    package_name=(affected.product if affected else None),
                    product_name=(affected.product if affected else None),
                    patch_available=bool(self.session.query(VexStatement).filter(VexStatement.cve_id == cve.cve_id.upper()).count()),
                )
                self.session.add(candidate)

            candidate.candidate_score = score
            candidate.status = status
            candidate.package_name = (affected.product if affected else candidate.package_name)
            candidate.product_name = (affected.product if affected else candidate.product_name)
            candidate.environment_fit = "local-docker-kali"
            candidate.linux_reproducibility_confidence = explainability["linux_reproducibility_confidence"]
            candidate.observability_score = explainability["observability_score"]
            candidate.patch_available = explainability["patch_available"]
            candidate.explainability = explainability

        self.session.flush()
        self._ensure_lab_template()
        self._ensure_analyst_identity(tenant)

    def list_candidates(self, tenant: Tenant, *, limit: int = 20, status: Optional[str] = None) -> Dict[str, Any]:
        """List scored candidates."""
        self.sync_candidates(tenant)
        query = self.session.query(ResearchCandidate).filter(ResearchCandidate.tenant_id == tenant.id)
        if status:
            query = query.filter(ResearchCandidate.status == status)
        rows = query.order_by(desc(ResearchCandidate.candidate_score)).limit(limit).all()
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "count": len(rows),
            "items": [self._candidate_payload(item) for item in rows],
        }

    def assign_candidate(self, tenant: Tenant, *, candidate_id: int, analyst_name: str) -> Dict[str, Any]:
        """Assign candidate to an analyst."""
        candidate = self._get_candidate(tenant, candidate_id)
        candidate.assigned_to = analyst_name
        candidate.assignment_state = "assigned"
        candidate.status = "in_review" if candidate.status == "queued" else candidate.status
        self.session.flush()
        return self._candidate_payload(candidate)

    def create_recipe(
        self,
        tenant: Tenant,
        *,
        candidate_id: int,
        name: str,
        objective: str,
        created_by: str,
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create recipe root plus first revision."""
        candidate = self._get_candidate(tenant, candidate_id)
        template = self._ensure_lab_template()
        recipe = LabRecipe(
            tenant_id=tenant.id,
            candidate_id=candidate.id,
            template_id=template.id,
            name=name,
            objective=objective,
            provider="docker_kali",
            status="draft",
            created_by=created_by,
            current_revision_number=1,
        )
        self.session.add(recipe)
        self.session.flush()
        revision = RecipeRevision(
            recipe_id=recipe.id,
            revision_number=1,
            approval_state="draft",
            risk_level=content.get("risk_level", "standard"),
            requires_acknowledgement=bool(content.get("requires_acknowledgement", False)),
            signed_digest=self.attestation_signer.sign(payload=content, signer=created_by)["sha256"],
            content=self._normalize_recipe_content(content, template.base_image),
        )
        self.session.add(revision)
        self._ledger(tenant.id, None, "recipe_created", "recipe", str(recipe.id), 4.0, {"candidate_id": candidate.id})
        self.session.flush()
        return self.get_recipe(tenant, recipe.id)

    def add_recipe_revision(
        self,
        tenant: Tenant,
        *,
        recipe_id: int,
        updated_by: str,
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a new immutable revision."""
        recipe = self._get_recipe(tenant, recipe_id)
        next_revision = (recipe.current_revision_number or 0) + 1
        revision = RecipeRevision(
            recipe_id=recipe.id,
            revision_number=next_revision,
            approval_state="draft",
            risk_level=content.get("risk_level", "standard"),
            requires_acknowledgement=bool(content.get("requires_acknowledgement", False)),
            signed_digest=self.attestation_signer.sign(payload=content, signer=updated_by)["sha256"],
            content=self._normalize_recipe_content(content, self._ensure_lab_template().base_image),
        )
        recipe.current_revision_number = next_revision
        recipe.status = "draft"
        self.session.add(revision)
        self.session.flush()
        return self.get_recipe(tenant, recipe.id)

    def approve_recipe_revision(self, tenant: Tenant, *, recipe_id: int, revision_number: int, reviewer: str) -> Dict[str, Any]:
        """Approve a recipe revision for launch."""
        recipe = self._get_recipe(tenant, recipe_id)
        revision = self._get_recipe_revision(recipe.id, revision_number)
        revision.approval_state = "approved"
        revision.approved_by = reviewer
        revision.approved_at = utc_now()
        recipe.status = "approved"
        self.session.add(
            ReviewDecision(
                tenant_id=tenant.id,
                reviewer_name=reviewer,
                target_type="recipe_revision",
                target_id=str(revision.id),
                decision="approved",
                rationale="Approved for constrained Kali validation.",
                payload={"recipe_id": recipe.id, "revision_number": revision_number},
            )
        )
        self._ledger(tenant.id, None, "recipe_approved", "recipe_revision", str(revision.id), 2.0, {"reviewer": reviewer})
        self.session.flush()
        return self.get_recipe(tenant, recipe.id)

    def list_recipes(self, tenant: Tenant) -> Dict[str, Any]:
        """List recipes for a tenant."""
        rows = self.session.query(LabRecipe).filter(LabRecipe.tenant_id == tenant.id).order_by(desc(LabRecipe.updated_at)).all()
        return {"items": [self._recipe_summary(item) for item in rows], "count": len(rows)}

    def get_recipe(self, tenant: Tenant, recipe_id: int) -> Dict[str, Any]:
        """Get recipe details with revisions."""
        recipe = self._get_recipe(tenant, recipe_id)
        revisions = (
            self.session.query(RecipeRevision)
            .filter(RecipeRevision.recipe_id == recipe.id)
            .order_by(desc(RecipeRevision.revision_number))
            .all()
        )
        return {
            **self._recipe_summary(recipe),
            "revisions": [
                {
                    "id": item.id,
                    "revision_number": item.revision_number,
                    "approval_state": item.approval_state,
                    "risk_level": item.risk_level,
                    "requires_acknowledgement": item.requires_acknowledgement,
                    "approved_by": item.approved_by,
                    "approved_at": item.approved_at.isoformat() if item.approved_at else None,
                    "content": item.content,
                }
                for item in revisions
            ],
        }

    def launch_run(
        self,
        tenant: Tenant,
        *,
        recipe_id: int,
        revision_number: Optional[int],
        analyst_name: str,
        workstation: Dict[str, Any],
        launch_mode: str = "simulated",
        acknowledge_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """Launch or simulate a validation run."""
        recipe = self._get_recipe(tenant, recipe_id)
        revision = self._get_recipe_revision(recipe.id, revision_number or recipe.current_revision_number)
        if revision.approval_state != "approved":
            raise ValueError("Recipe revision must be approved before launch.")
        if revision.requires_acknowledgement and not acknowledge_sensitive:
            raise ValueError("Sensitive recipe revisions require analyst acknowledgement before launch.")

        analyst = self._ensure_analyst_identity(tenant, analyst_name)
        workstation_record = self._ensure_workstation(tenant, workstation)
        candidate = self._get_candidate(tenant, recipe.candidate_id) if recipe.candidate_id else None

        run = LabRun(
            tenant_id=tenant.id,
            recipe_revision_id=revision.id,
            candidate_id=recipe.candidate_id,
            analyst_id=analyst.id,
            workstation_fingerprint_id=workstation_record.id,
            provider="docker_kali",
            launch_mode=launch_mode,
            state="planned",
            requires_acknowledgement=revision.requires_acknowledgement,
            acknowledged_by=analyst_name if acknowledge_sensitive else None,
            acknowledged_at=utc_now() if acknowledge_sensitive else None,
            workspace_path=f"/tmp/sheshnaag/run-{recipe.id}-{revision.revision_number}",
        )
        self.session.add(run)
        self.session.flush()

        run_context = {
            "run_id": run.id,
            "tenant_slug": tenant.slug,
            "analyst_name": analyst_name,
            "launch_mode": launch_mode,
            "candidate": self._candidate_payload(candidate) if candidate else {},
            "cve_id": candidate.cve.cve_id if candidate and candidate.cve else None,
        }
        provider_result = self.provider.launch(revision_content=revision.content, run_context=run_context)
        run.provider_run_ref = provider_result["provider_run_ref"]
        run.state = provider_result["state"]
        run.guest_image = provider_result["plan"]["image"]
        run.image_digest = provider_result["plan"]["image_digest"]
        run.network_mode = provider_result["plan"]["network_mode"]
        run.manifest = provider_result["plan"]
        run.run_transcript = provider_result["transcript"]
        run.started_at = utc_now()
        if provider_result["state"] in {"completed", "blocked", "planned"}:
            run.ended_at = utc_now()

        self.session.add(
            RunEvent(
                run_id=run.id,
                event_type="provider_launch",
                message=provider_result["transcript"],
                payload=provider_result["plan"],
            )
        )

        artifacts = self._collect_and_generate(run=run, candidate=candidate, analyst_name=analyst_name)
        self._persist_run_artifacts(run=run, artifacts=artifacts)
        self._ledger(tenant.id, analyst.id, "run_launched", "run", str(run.id), 5.0, {"state": run.state})
        self.session.flush()
        return self.get_run(tenant, run.id)

    def list_runs(self, tenant: Tenant) -> Dict[str, Any]:
        """List validation runs."""
        rows = self.session.query(LabRun).filter(LabRun.tenant_id == tenant.id).order_by(desc(LabRun.created_at)).all()
        return {"count": len(rows), "items": [self._run_summary(item) for item in rows]}

    def get_run(self, tenant: Tenant, run_id: int) -> Dict[str, Any]:
        """Get run details."""
        run = self._get_run(tenant, run_id)
        events = self.session.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.created_at.asc()).all()
        return {
            **self._run_summary(run),
            "timeline": [
                {
                    "event_type": event.event_type,
                    "level": event.level,
                    "message": event.message,
                    "payload": event.payload,
                    "created_at": event.created_at.isoformat() if event.created_at else None,
                }
                for event in events
            ],
        }

    def list_evidence(self, tenant: Tenant, *, run_id: Optional[int] = None) -> Dict[str, Any]:
        """List evidence artifacts."""
        query = self.session.query(EvidenceArtifact).join(LabRun, LabRun.id == EvidenceArtifact.run_id).filter(LabRun.tenant_id == tenant.id)
        if run_id is not None:
            query = query.filter(EvidenceArtifact.run_id == run_id)
        rows = query.order_by(desc(EvidenceArtifact.created_at)).all()
        return {
            "count": len(rows),
            "items": [
                {
                    "id": item.id,
                    "run_id": item.run_id,
                    "artifact_kind": item.artifact_kind,
                    "title": item.title,
                    "summary": item.summary,
                    "reviewed_state": item.reviewed_state,
                    "sha256": item.sha256,
                    "payload": item.payload,
                }
                for item in rows
            ],
        }

    def list_artifacts(self, tenant: Tenant, *, run_id: Optional[int] = None) -> Dict[str, Any]:
        """List generated defensive artifacts."""
        detection_query = self.session.query(DetectionArtifact).join(LabRun, LabRun.id == DetectionArtifact.run_id).filter(LabRun.tenant_id == tenant.id)
        mitigation_query = self.session.query(MitigationArtifact).join(LabRun, LabRun.id == MitigationArtifact.run_id).filter(LabRun.tenant_id == tenant.id)
        if run_id is not None:
            detection_query = detection_query.filter(DetectionArtifact.run_id == run_id)
            mitigation_query = mitigation_query.filter(MitigationArtifact.run_id == run_id)
        return {
            "detections": [
                {
                    "id": item.id,
                    "run_id": item.run_id,
                    "artifact_type": item.artifact_type,
                    "name": item.name,
                    "status": item.status,
                    "sha256": item.sha256,
                }
                for item in detection_query.order_by(desc(DetectionArtifact.created_at)).all()
            ],
            "mitigations": [
                {
                    "id": item.id,
                    "run_id": item.run_id,
                    "artifact_type": item.artifact_type,
                    "title": item.title,
                    "status": item.status,
                }
                for item in mitigation_query.order_by(desc(MitigationArtifact.created_at)).all()
            ],
        }

    def get_provenance(self, tenant: Tenant, *, run_id: Optional[int] = None) -> Dict[str, Any]:
        """Return run- and bundle-linked attestation data."""
        query = self.session.query(AttestationRecord).filter(AttestationRecord.tenant_id == tenant.id)
        if run_id is not None:
            query = query.filter(AttestationRecord.run_id == run_id)
        rows = query.order_by(desc(AttestationRecord.created_at)).all()
        return {
            "count": len(rows),
            "items": [
                {
                    "id": row.id,
                    "run_id": row.run_id,
                    "disclosure_bundle_id": row.disclosure_bundle_id,
                    "subject_type": row.subject_type,
                    "subject_id": row.subject_id,
                    "sha256": row.sha256,
                    "signature": row.signature,
                    "signer": row.signer,
                    "payload": row.payload,
                }
                for row in rows
            ],
        }

    def get_ledger(self, tenant: Tenant) -> Dict[str, Any]:
        """Return analyst contribution ledger."""
        rows = self.session.query(ContributionLedgerEntry).filter(ContributionLedgerEntry.tenant_id == tenant.id).order_by(desc(ContributionLedgerEntry.created_at)).all()
        return {
            "count": len(rows),
            "items": [
                {
                    "id": row.id,
                    "analyst_id": row.analyst_id,
                    "entry_type": row.entry_type,
                    "object_type": row.object_type,
                    "object_id": row.object_id,
                    "score": row.score,
                    "note": row.note,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ],
        }

    def create_disclosure_bundle(self, tenant: Tenant, *, run_id: int, bundle_type: str, title: str, signed_by: str) -> Dict[str, Any]:
        """Create a disclosure/export bundle from a run."""
        run = self._get_run(tenant, run_id)
        evidence = self.list_evidence(tenant, run_id=run.id)["items"]
        artifacts = self.list_artifacts(tenant, run_id=run.id)
        manifest = {
            "run": self._run_summary(run),
            "evidence_count": len(evidence),
            "detection_count": len(artifacts["detections"]),
            "mitigation_count": len(artifacts["mitigations"]),
            "exported_at": utc_now().isoformat(),
        }
        signed = self.attestation_signer.sign(payload=manifest, signer=signed_by)
        bundle = DisclosureBundle(
            tenant_id=tenant.id,
            run_id=run.id,
            bundle_type=bundle_type,
            title=title,
            status="signed",
            manifest=manifest,
            sha256=signed["sha256"],
            signed_by=signed_by,
        )
        self.session.add(bundle)
        self.session.flush()
        self.session.add(
            AttestationRecord(
                tenant_id=tenant.id,
                run_id=run.id,
                disclosure_bundle_id=bundle.id,
                subject_type="disclosure_bundle",
                subject_id=str(bundle.id),
                sha256=signed["sha256"],
                signature=signed["signature"],
                signer=signed["signer"],
                payload=manifest,
            )
        )
        self._ledger(tenant.id, run.analyst_id, "bundle_signed", "disclosure_bundle", str(bundle.id), 3.0, {"bundle_type": bundle_type})
        self.session.flush()
        return self.list_disclosure_bundles(tenant)

    def list_disclosure_bundles(self, tenant: Tenant) -> Dict[str, Any]:
        """List disclosure bundles."""
        rows = self.session.query(DisclosureBundle).filter(DisclosureBundle.tenant_id == tenant.id).order_by(desc(DisclosureBundle.created_at)).all()
        return {
            "count": len(rows),
            "items": [
                {
                    "id": row.id,
                    "run_id": row.run_id,
                    "bundle_type": row.bundle_type,
                    "title": row.title,
                    "status": row.status,
                    "sha256": row.sha256,
                    "signed_by": row.signed_by,
                    "manifest": row.manifest,
                }
                for row in rows
            ],
        }

    def _build_candidate_explainability(
        self,
        *,
        cve: CVE,
        tenant: Tenant,
        risk: Optional[RiskScore],
        kev: Optional[KEVEntry],
        epss: Optional[EPSSSnapshot],
        affected: Optional[AffectedProduct],
    ) -> Dict[str, Any]:
        asset_matches = self._asset_match_count(tenant, affected)
        patch_available = bool(self.session.query(VexStatement).filter(VexStatement.cve_id == cve.cve_id.upper()).count() or cve.exploit_available)
        risk_score = float(risk.overall_score / 100.0) if risk and risk.overall_score is not None else 0.35
        kev_score = 1.0 if kev else 0.0
        epss_score = float(epss.score) if epss else 0.0
        package_match = min(1.0, asset_matches / 3.0)
        observability = 0.85 if cve.attack_vector == "NETWORK" else 0.65
        reproducibility = 0.9 if affected else 0.55

        score = round(
            (
                0.28 * risk_score
                + 0.22 * epss_score
                + 0.16 * kev_score
                + 0.14 * package_match
                + 0.10 * observability
                + 0.10 * reproducibility
            )
            * 100.0,
            2,
        )
        return {
            "score": score,
            "factors": {
                "risk_score": round(risk_score, 3),
                "epss": round(epss_score, 3),
                "kev": bool(kev),
                "package_match_confidence": round(package_match, 3),
                "observability_score": round(observability, 3),
                "linux_reproducibility_confidence": round(reproducibility, 3),
            },
            "asset_match_count": asset_matches,
            "patch_available": patch_available,
            "observability_score": round(observability, 3),
            "linux_reproducibility_confidence": round(reproducibility, 3),
            "citations": [
                item
                for item in [
                    {"label": "CISA KEV", "url": kev.source_url} if kev and kev.source_url else None,
                    {"label": "FIRST EPSS", "url": epss.source_url} if epss and epss.source_url else None,
                ]
                if item is not None
            ],
        }

    def _collect_and_generate(self, *, run: LabRun, candidate: Optional[ResearchCandidate], analyst_name: str) -> RunArtifacts:
        run_context = {
            "run_id": run.id,
            "candidate": self._candidate_payload(candidate) if candidate else {},
            "cve_id": candidate.cve.cve_id if candidate and candidate.cve else None,
        }
        provider_result = {"provider_run_ref": run.provider_run_ref, "plan": run.manifest}
        evidence = []
        for collector in self.collectors:
            evidence.extend(collector.collect(run_context=run_context, provider_result=provider_result))
        generated = self.artifact_generator.generate(run_context=run_context, evidence=evidence)
        attestation = self.attestation_signer.sign(payload=run.manifest or {}, signer=analyst_name)
        return RunArtifacts(
            evidence=evidence,
            detections=generated["detection_artifacts"],
            mitigations=generated["mitigation_artifacts"],
            attestation=attestation,
        )

    def _persist_run_artifacts(self, *, run: LabRun, artifacts: RunArtifacts) -> None:
        evidence_records: List[EvidenceArtifact] = []
        for item in artifacts.evidence:
            record = EvidenceArtifact(
                run_id=run.id,
                artifact_kind=item["artifact_kind"],
                title=item["title"],
                summary=item["summary"],
                sha256=item["sha256"],
                payload=item["payload"],
                reviewed_state="captured",
            )
            self.session.add(record)
            evidence_records.append(record)
        self.session.flush()

        first_evidence_id = evidence_records[0].id if evidence_records else None
        for item in artifacts.detections:
            self.session.add(
                DetectionArtifact(
                    run_id=run.id,
                    evidence_artifact_id=item.get("evidence_artifact_id") or first_evidence_id,
                    artifact_type=item["artifact_type"],
                    name=item["name"],
                    rule_body=item["rule_body"],
                    status=item["status"],
                    sha256=item["sha256"],
                )
            )
        for item in artifacts.mitigations:
            self.session.add(
                MitigationArtifact(
                    run_id=run.id,
                    artifact_type=item["artifact_type"],
                    title=item["title"],
                    body=item["body"],
                    status=item["status"],
                )
            )
        self.session.add(
            AttestationRecord(
                tenant_id=run.tenant_id,
                run_id=run.id,
                subject_type="run_manifest",
                subject_id=str(run.id),
                sha256=artifacts.attestation["sha256"],
                signature=artifacts.attestation["signature"],
                signer=artifacts.attestation["signer"],
                payload=run.manifest or {},
            )
        )

    def _candidate_payload(self, candidate: Optional[ResearchCandidate]) -> Dict[str, Any]:
        if candidate is None:
            return {}
        return {
            "id": candidate.id,
            "cve_id": candidate.cve.cve_id if candidate.cve else None,
            "title": candidate.title,
            "summary": candidate.summary,
            "candidate_score": candidate.candidate_score,
            "status": candidate.status,
            "assignment_state": candidate.assignment_state,
            "assigned_to": candidate.assigned_to,
            "package_name": candidate.package_name,
            "product_name": candidate.product_name,
            "environment_fit": candidate.environment_fit,
            "patch_available": candidate.patch_available,
            "linux_reproducibility_confidence": candidate.linux_reproducibility_confidence,
            "observability_score": candidate.observability_score,
            "explainability": candidate.explainability,
        }

    def _recipe_summary(self, recipe: LabRecipe) -> Dict[str, Any]:
        return {
            "id": recipe.id,
            "candidate_id": recipe.candidate_id,
            "name": recipe.name,
            "objective": recipe.objective,
            "provider": recipe.provider,
            "status": recipe.status,
            "created_by": recipe.created_by,
            "current_revision_number": recipe.current_revision_number,
            "created_at": recipe.created_at.isoformat() if recipe.created_at else None,
            "updated_at": recipe.updated_at.isoformat() if recipe.updated_at else None,
        }

    def _run_summary(self, run: LabRun) -> Dict[str, Any]:
        return {
            "id": run.id,
            "recipe_revision_id": run.recipe_revision_id,
            "candidate_id": run.candidate_id,
            "provider": run.provider,
            "provider_run_ref": run.provider_run_ref,
            "state": run.state,
            "launch_mode": run.launch_mode,
            "guest_image": run.guest_image,
            "image_digest": run.image_digest,
            "network_mode": run.network_mode,
            "workspace_path": run.workspace_path,
            "requires_acknowledgement": run.requires_acknowledgement,
            "acknowledged_by": run.acknowledged_by,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
            "manifest": run.manifest,
            "run_transcript": run.run_transcript,
        }

    def _get_candidate(self, tenant: Tenant, candidate_id: int) -> ResearchCandidate:
        candidate = (
            self.session.query(ResearchCandidate)
            .filter(ResearchCandidate.tenant_id == tenant.id, ResearchCandidate.id == candidate_id)
            .first()
        )
        if candidate is None:
            raise ValueError("Candidate not found.")
        return candidate

    def _get_recipe(self, tenant: Tenant, recipe_id: int) -> LabRecipe:
        recipe = (
            self.session.query(LabRecipe)
            .filter(LabRecipe.tenant_id == tenant.id, LabRecipe.id == recipe_id)
            .first()
        )
        if recipe is None:
            raise ValueError("Recipe not found.")
        return recipe

    def _get_recipe_revision(self, recipe_id: int, revision_number: Optional[int]) -> RecipeRevision:
        revision = (
            self.session.query(RecipeRevision)
            .filter(RecipeRevision.recipe_id == recipe_id, RecipeRevision.revision_number == revision_number)
            .first()
        )
        if revision is None:
            raise ValueError("Recipe revision not found.")
        return revision

    def _get_run(self, tenant: Tenant, run_id: int) -> LabRun:
        run = self.session.query(LabRun).filter(LabRun.tenant_id == tenant.id, LabRun.id == run_id).first()
        if run is None:
            raise ValueError("Run not found.")
        return run

    def _normalize_recipe_content(self, content: Dict[str, Any], image: str) -> Dict[str, Any]:
        normalized = dict(content)
        normalized.setdefault("base_image", image)
        normalized.setdefault("command", ["sleep", "1"])
        normalized.setdefault("network_policy", {"allow_egress_hosts": []})
        normalized.setdefault(
            "collectors",
            ["process_tree", "package_inventory", "file_diff", "network_metadata", "service_logs", "tracee_events"],
        )
        normalized.setdefault("teardown_policy", {"mode": "destroy_container", "ephemeral_workspace": True})
        return normalized

    def _ensure_source_feeds(self) -> None:
        defaults = [
            ("nvd", "NVD", "intel", "active", "https://nvd.nist.gov/"),
            ("kev", "CISA KEV", "exploitability", "active", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ("epss", "FIRST EPSS", "exploitability", "active", "https://www.first.org/epss/"),
            ("osv", "OSV", "package", "planned", "https://osv.dev/"),
            ("ghsa", "GitHub Advisory Database", "package", "planned", "https://github.com/advisories"),
        ]
        for feed_key, display_name, category, status, url in defaults:
            feed = self.session.query(SourceFeed).filter(SourceFeed.feed_key == feed_key).first()
            if feed is None:
                self.session.add(
                    SourceFeed(
                        feed_key=feed_key,
                        display_name=display_name,
                        category=category,
                        status=status,
                        source_url=url,
                        freshness_seconds=21600,
                        last_synced_at=utc_now(),
                    )
                )
        self.session.flush()

    def _ensure_lab_template(self) -> LabTemplate:
        template = (
            self.session.query(LabTemplate)
            .filter(LabTemplate.provider == "docker_kali", LabTemplate.name == "Constrained Kali Validation")
            .first()
        )
        if template is None:
            template = LabTemplate(
                provider="docker_kali",
                name="Constrained Kali Validation",
                distro="kali",
                base_image=DEFAULT_KALI_IMAGE,
                image_digest=self.attestation_signer.sign(payload={"image": DEFAULT_KALI_IMAGE}, signer="system")["sha256"],
                is_hardened=True,
                network_mode="isolated",
                meta={
                    "read_only_rootfs": True,
                    "default_cap_drop": ["ALL"],
                    "egress_policy": "default-deny",
                },
            )
            self.session.add(template)
            self.session.flush()
        return template

    def _ensure_analyst_identity(self, tenant: Tenant, analyst_name: Optional[str] = None) -> AnalystIdentity:
        email = f"{(analyst_name or 'demo.analyst').lower().replace(' ', '.')}@sheshnaag.local"
        record = (
            self.session.query(AnalystIdentity)
            .filter(AnalystIdentity.tenant_id == tenant.id, AnalystIdentity.email == email)
            .first()
        )
        if record is None:
            record = AnalystIdentity(
                tenant_id=tenant.id,
                name=analyst_name or "Demo Analyst",
                email=email,
                handle=(analyst_name or "demo-analyst").lower().replace(" ", "-"),
                role="researcher",
                public_key_fingerprint="local-dev-fingerprint",
            )
            self.session.add(record)
            self.session.flush()
        return record

    def _ensure_workstation(self, tenant: Tenant, workstation: Dict[str, Any]) -> WorkstationFingerprint:
        fingerprint = workstation.get("fingerprint") or "local-workstation"
        record = (
            self.session.query(WorkstationFingerprint)
            .filter(WorkstationFingerprint.tenant_id == tenant.id, WorkstationFingerprint.fingerprint == fingerprint)
            .first()
        )
        if record is None:
            record = WorkstationFingerprint(
                tenant_id=tenant.id,
                hostname=workstation.get("hostname"),
                os_family=workstation.get("os_family", "macOS"),
                architecture=workstation.get("architecture", "arm64"),
                fingerprint=fingerprint,
                meta=workstation,
            )
            self.session.add(record)
            self.session.flush()
        return record

    def _ensure_product_record(self, affected: Optional[AffectedProduct]) -> Optional[ProductRecord]:
        if affected is None or not affected.product:
            return None
        record = (
            self.session.query(ProductRecord)
            .filter(ProductRecord.vendor == (affected.vendor or "unknown"), ProductRecord.name == affected.product)
            .first()
        )
        if record is None:
            record = ProductRecord(vendor=affected.vendor or "unknown", name=affected.product, description="Derived from affected product data.")
            self.session.add(record)
            self.session.flush()
        return record

    def _ensure_package_record(self, affected: Optional[AffectedProduct]) -> Optional[PackageRecord]:
        if affected is None or not affected.product:
            return None
        record = (
            self.session.query(PackageRecord)
            .filter(PackageRecord.ecosystem == "enterprise", PackageRecord.name == affected.product)
            .first()
        )
        if record is None:
            record = PackageRecord(
                ecosystem="enterprise",
                name=affected.product,
                purl=f"pkg:generic/{affected.vendor or 'unknown'}/{affected.product}",
                description="Derived from CVE affected product mapping.",
            )
            self.session.add(record)
            self.session.flush()
        return record

    def _asset_match_count(self, tenant: Tenant, affected: Optional[AffectedProduct]) -> int:
        if affected is None:
            return 0
        matches = 0
        assets = self.session.query(Asset).filter(Asset.tenant_id == tenant.id).all()
        for asset in assets:
            installed = asset.installed_software or []
            if any((item.get("product") or "").lower() == (affected.product or "").lower() for item in installed if isinstance(item, dict)):
                matches += 1
        return matches

    def _latest_risk_by_cve_id(self, cve_ids: Iterable[int]) -> Dict[int, RiskScore]:
        rows = (
            self.session.query(RiskScore)
            .filter(RiskScore.cve_id.in_(list(cve_ids)))
            .order_by(desc(RiskScore.created_at))
            .all()
        )
        latest: Dict[int, RiskScore] = {}
        for row in rows:
            latest.setdefault(row.cve_id, row)
        return latest

    def _ledger(
        self,
        tenant_id: int,
        analyst_id: Optional[int],
        entry_type: str,
        object_type: str,
        object_id: str,
        score: float,
        payload: Dict[str, Any],
    ) -> None:
        self.session.add(
            ContributionLedgerEntry(
                tenant_id=tenant_id,
                analyst_id=analyst_id,
                entry_type=entry_type,
                object_type=object_type,
                object_id=object_id,
                score=score,
                note=entry_type.replace("_", " "),
                payload=payload,
            )
        )
