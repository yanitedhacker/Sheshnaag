"""Core application service layer for Project Sheshnaag."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from app.core.time import utc_now
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.tenancy import resolve_tenant
from app.ingestion.connector import get_registered_connectors
from app.models.ops import FeedSyncRun, FeedSyncState
from app.lab.artifact_generator import DefensiveArtifactGenerator
from app.lab.attestation import HashAttestationSigner
from app.lab.collectors import default_collectors
from app.lab.docker_kali_provider import DEFAULT_KALI_IMAGE, DockerKaliProvider
from app.lab.interfaces import HealthStatus, ProviderResult, RunState, validate_transition
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
from app.models.v2 import AssetSoftware, EPSSSnapshot, KEVEntry, KnowledgeDocument, SoftwareComponent, Tenant, VexStatement
from app.services.intel_service import ThreatIntelService


CANDIDATE_SCORING_WEIGHTS: Dict[str, float] = {
    "risk_score": 0.20,
    "epss": 0.18,
    "kev": 0.14,
    "package_match_confidence": 0.12,
    "attack_surface": 0.10,
    "observability": 0.08,
    "linux_reproducibility": 0.08,
    "patch_availability": 0.06,
    "exploit_maturity": 0.04,
}
"""Named weights for candidate scoring.  All weights must sum to 1.0.
Each key corresponds to a `ScoringFactor.key`.  Changing a weight here
is the *only* place that affects score output, making auditing trivial."""

VALID_CANDIDATE_STATUSES = {
    "queued",
    "deferred",
    "in_review",
    "rejected",
    "duplicate",
    "archived",
}

CANDIDATE_STATUS_TRANSITIONS: Dict[str, set] = {
    "queued": {"in_review", "deferred", "rejected", "duplicate", "archived"},
    "deferred": {"queued", "in_review", "rejected", "archived"},
    "in_review": {"queued", "deferred", "rejected", "duplicate", "archived"},
    "rejected": {"queued"},
    "duplicate": set(),
    "archived": {"queued"},
}


@dataclass
class ScoringFactor:
    """One named factor contributing to a candidate score."""

    key: str
    raw_value: float
    weight: float
    weighted_value: float
    reason: str


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

        sync_states: Dict[str, FeedSyncState] = {
            s.source.lower(): s
            for s in self.session.query(FeedSyncState).all()
        }

        latest_run_subq = (
            self.session.query(
                FeedSyncRun.source,
                func.max(FeedSyncRun.id).label("max_id"),
            )
            .group_by(FeedSyncRun.source)
            .subquery()
        )
        latest_runs: Dict[str, FeedSyncRun] = {
            r.source.lower(): r
            for r in self.session.query(FeedSyncRun)
            .join(latest_run_subq, FeedSyncRun.id == latest_run_subq.c.max_id)
            .all()
        }

        now = utc_now()
        sources: List[Dict[str, Any]] = []
        for feed in feeds:
            threshold = feed.freshness_seconds or 21600
            is_stale = True
            stale_since: Optional[str] = None
            if feed.last_synced_at:
                synced = feed.last_synced_at.replace(tzinfo=None) if feed.last_synced_at.tzinfo else feed.last_synced_at
                age = (now.replace(tzinfo=None) - synced).total_seconds()
                is_stale = age > threshold
                if is_stale:
                    from datetime import timedelta
                    stale_since = (synced + timedelta(seconds=threshold)).isoformat()

            state = sync_states.get(feed.feed_key)
            last_run = latest_runs.get(feed.feed_key)

            sources.append({
                "feed_key": feed.feed_key,
                "display_name": feed.display_name,
                "category": feed.category,
                "status": feed.status,
                "source_url": feed.source_url,
                "last_synced_at": feed.last_synced_at.isoformat() if feed.last_synced_at else None,
                "freshness_seconds": feed.freshness_seconds,
                "is_stale": is_stale,
                "stale_since": stale_since,
                "last_error": state.last_error if state else None,
                "recent_item_count_delta": last_run.items_new if last_run else 0,
            })

        candidate_count = self.session.query(ResearchCandidate).filter(ResearchCandidate.tenant_id == tenant.id).count()
        active_states = [
            RunState.PLANNED.value, RunState.BOOTING.value, RunState.READY.value,
            RunState.RUNNING.value, RunState.STOPPING.value,
        ]
        active_runs = (
            self.session.query(LabRun)
            .filter(LabRun.tenant_id == tenant.id, LabRun.state.in_(active_states))
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
            "sources": sources,
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

    def list_candidates(
        self,
        tenant: Tenant,
        *,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None,
        package_name: Optional[str] = None,
        product_name: Optional[str] = None,
        distro_hint: Optional[str] = None,
        kev_only: Optional[bool] = None,
        epss_min: Optional[float] = None,
        epss_max: Optional[float] = None,
        patch_available: Optional[bool] = None,
        assigned_to: Optional[str] = None,
        assignment_state: Optional[str] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        sort_by: Optional[str] = None,
        sort_order: Optional[str] = "desc",
    ) -> Dict[str, Any]:
        """List scored candidates with filtering, sorting, and pagination."""
        self.sync_candidates(tenant)
        query = self.session.query(ResearchCandidate).filter(ResearchCandidate.tenant_id == tenant.id)

        if status:
            query = query.filter(ResearchCandidate.status == status)
        if package_name:
            query = query.filter(ResearchCandidate.package_name.ilike(f"%{package_name}%"))
        if product_name:
            query = query.filter(ResearchCandidate.product_name.ilike(f"%{product_name}%"))
        if distro_hint:
            query = query.filter(ResearchCandidate.distro_hint == distro_hint)
        if patch_available is not None:
            query = query.filter(ResearchCandidate.patch_available == patch_available)
        if assigned_to:
            query = query.filter(ResearchCandidate.assigned_to == assigned_to)
        if assignment_state:
            query = query.filter(ResearchCandidate.assignment_state == assignment_state)
        if min_score is not None:
            query = query.filter(ResearchCandidate.candidate_score >= min_score)
        if max_score is not None:
            query = query.filter(ResearchCandidate.candidate_score <= max_score)

        if kev_only:
            kev_cve_ids = {row.cve_id.upper() for row in self.session.query(KEVEntry).all()}
            if kev_cve_ids:
                kev_db_ids = [
                    c.id for c in self.session.query(CVE).filter(CVE.cve_id.in_(kev_cve_ids)).all()
                ]
                query = query.filter(ResearchCandidate.cve_id.in_(kev_db_ids))
            else:
                query = query.filter(ResearchCandidate.id < 0)

        if epss_min is not None or epss_max is not None:
            epss_map = self._epss_filter_cve_ids(epss_min, epss_max)
            if epss_map is not None:
                query = query.filter(ResearchCandidate.cve_id.in_(epss_map))

        total = query.count()

        sort_column = {
            "score": ResearchCandidate.candidate_score,
            "status": ResearchCandidate.status,
            "created_at": ResearchCandidate.created_at,
            "updated_at": ResearchCandidate.updated_at,
            "assigned_to": ResearchCandidate.assigned_to,
            "package_name": ResearchCandidate.package_name,
        }.get(sort_by or "score", ResearchCandidate.candidate_score)

        if sort_order == "asc":
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())

        rows = query.offset(offset).limit(limit).all()
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "total": total,
            "count": len(rows),
            "offset": offset,
            "limit": limit,
            "items": [self._candidate_payload(item) for item in rows],
        }

    def get_workload_summary(self, tenant: Tenant) -> Dict[str, Any]:
        """Return per-analyst queue counts and unassigned totals."""
        base = self.session.query(ResearchCandidate).filter(
            ResearchCandidate.tenant_id == tenant.id,
            ResearchCandidate.status.in_(["queued", "in_review"]),
        )
        unassigned = base.filter(ResearchCandidate.assignment_state == "unassigned").count()
        total_active = base.count()

        analyst_rows = (
            self.session.query(
                ResearchCandidate.assigned_to,
                func.count(ResearchCandidate.id),
            )
            .filter(
                ResearchCandidate.tenant_id == tenant.id,
                ResearchCandidate.assignment_state == "assigned",
                ResearchCandidate.status.in_(["queued", "in_review"]),
            )
            .group_by(ResearchCandidate.assigned_to)
            .all()
        )
        by_analyst = [
            {"analyst": name, "count": count} for name, count in analyst_rows if name
        ]

        status_rows = (
            self.session.query(
                ResearchCandidate.status,
                func.count(ResearchCandidate.id),
            )
            .filter(ResearchCandidate.tenant_id == tenant.id)
            .group_by(ResearchCandidate.status)
            .all()
        )
        by_status = {status: count for status, count in status_rows}

        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "total_active": total_active,
            "unassigned": unassigned,
            "by_analyst": by_analyst,
            "by_status": by_status,
        }

    def assign_candidate(self, tenant: Tenant, *, candidate_id: int, analyst_name: str, assigned_by: Optional[str] = None) -> Dict[str, Any]:
        """Assign candidate to an analyst."""
        candidate = self._get_candidate(tenant, candidate_id)
        candidate.assigned_to = analyst_name
        candidate.assigned_by = assigned_by or analyst_name
        candidate.assigned_at = utc_now()
        candidate.assignment_state = "assigned"
        candidate.status = "in_review" if candidate.status == "queued" else candidate.status
        self.session.flush()
        return self._candidate_payload(candidate)

    def transition_candidate_status(
        self,
        tenant: Tenant,
        *,
        candidate_id: int,
        new_status: str,
        reason: Optional[str] = None,
        changed_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Transition candidate to a new status with validation."""
        if new_status not in VALID_CANDIDATE_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Valid: {sorted(VALID_CANDIDATE_STATUSES)}")

        candidate = self._get_candidate(tenant, candidate_id)
        allowed = CANDIDATE_STATUS_TRANSITIONS.get(candidate.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition from '{candidate.status}' to '{new_status}'. "
                f"Allowed transitions: {sorted(allowed) if allowed else 'none'}"
            )

        candidate.status = new_status
        candidate.status_reason = reason
        candidate.status_changed_at = utc_now()
        candidate.status_changed_by = changed_by
        self.session.flush()
        return self._candidate_payload(candidate)

    def merge_candidate_duplicate(
        self,
        tenant: Tenant,
        *,
        candidate_id: int,
        merge_into_id: int,
        merged_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark candidate as a duplicate of another and transfer context."""
        if candidate_id == merge_into_id:
            raise ValueError("A candidate cannot be merged into itself.")
        candidate = self._get_candidate(tenant, candidate_id)
        target = self._get_candidate(tenant, merge_into_id)

        allowed = CANDIDATE_STATUS_TRANSITIONS.get(candidate.status, set())
        if "duplicate" not in allowed:
            raise ValueError(f"Cannot mark candidate in '{candidate.status}' as duplicate.")

        candidate.status = "duplicate"
        candidate.status_reason = f"Merged into candidate {merge_into_id}"
        candidate.status_changed_at = utc_now()
        candidate.status_changed_by = merged_by
        candidate.merged_into_id = merge_into_id
        self.session.flush()
        return {
            "merged": self._candidate_payload(candidate),
            "target": self._candidate_payload(target),
        }

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
        self._apply_provider_result(run, provider_result)
        run.started_at = utc_now()
        terminal_states = {RunState.COMPLETED.value, RunState.BLOCKED.value, RunState.PLANNED.value, RunState.ERRORED.value}
        if run.state in terminal_states:
            run.ended_at = utc_now()

        self.session.add(
            RunEvent(
                run_id=run.id,
                event_type="provider_launch",
                message=provider_result.transcript,
                payload=provider_result.to_dict(),
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

    def stop_run(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Stop a running validation run."""
        run = self._get_run(tenant, run_id)
        self._assert_transition(run, RunState.STOPPING)
        result = self.provider.stop(provider_run_ref=run.provider_run_ref)
        self._apply_provider_result(run, result)
        self._add_run_event(run, "run_stopped", result)
        self.session.flush()
        return self.get_run(tenant, run.id)

    def teardown_run(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Teardown a stopped or completed run, releasing execution resources."""
        run = self._get_run(tenant, run_id)
        self._assert_transition(run, RunState.TEARING_DOWN)
        retention = (run.manifest or {}).get("workspace_retention", "destroy_immediately")
        retain = retention in ("retain_exports_only", "retain_workspace_until_review")
        result = self.provider.teardown(provider_run_ref=run.provider_run_ref, retain_workspace=retain)
        self._apply_provider_result(run, result)
        run.ended_at = run.ended_at or utc_now()
        self._add_run_event(run, "run_teardown", result)
        self.session.flush()
        return self.get_run(tenant, run.id)

    def destroy_run(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Destroy all resources for a run including workspace data."""
        run = self._get_run(tenant, run_id)
        current = RunState(run.state) if run.state in [s.value for s in RunState] else RunState.ERRORED
        if current not in (RunState.DESTROYED,):
            result = self.provider.destroy(provider_run_ref=run.provider_run_ref)
            self._apply_provider_result(run, result)
            run.ended_at = run.ended_at or utc_now()
            self._add_run_event(run, "run_destroyed", result)
        self.session.flush()
        return self.get_run(tenant, run.id)

    def run_health(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Check the health of a running validation run."""
        run = self._get_run(tenant, run_id)
        result = self.provider.health(provider_run_ref=run.provider_run_ref)
        prev_state = run.state
        if result.state.value != prev_state:
            self._apply_provider_result(run, result)
            self._add_run_event(run, "health_check", result, level="warning" if result.health == HealthStatus.UNHEALTHY else "info")
            if result.health in (HealthStatus.UNHEALTHY, HealthStatus.ERRORED):
                self._add_run_event(
                    run, "unhealthy_detected", result, level="error",
                    message=f"Guest entered {result.health.value} state.",
                )
        self.session.flush()
        events = self.session.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.created_at.asc()).all()
        return {
            **self._run_summary(run),
            "health": result.health.value,
            "timeline": [
                {
                    "event_type": e.event_type,
                    "level": e.level,
                    "message": e.message,
                    "payload": e.payload,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in events
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
        applicability = self._compute_environment_applicability(cve=cve, tenant=tenant, affected=affected)
        asset_matches = applicability["asset_match_count"] + applicability["sbom_match_count"]
        vex_fixed = applicability.get("vex_status") in ("fixed", "not_affected")
        vex_count = self.session.query(VexStatement).filter(VexStatement.cve_id == cve.cve_id.upper()).count()
        patch_available = bool(vex_fixed or vex_count or cve.exploit_available)

        factors = self._compute_scoring_factors(
            cve=cve,
            risk=risk,
            kev=kev,
            epss=epss,
            affected=affected,
            asset_matches=asset_matches,
            patch_available=patch_available,
        )
        weighted_total = sum(f.weighted_value for f in factors)
        score = round(weighted_total * 100.0, 2)

        factors_dict = {f.key: round(f.raw_value, 3) for f in factors}
        factors_dict["kev"] = bool(kev)

        observability = next(f.raw_value for f in factors if f.key == "observability")
        reproducibility = next(f.raw_value for f in factors if f.key == "linux_reproducibility")

        citations = self._build_citations(cve=cve, tenant=tenant, kev=kev, epss=epss, affected=affected)

        return {
            "score": score,
            "factors": factors_dict,
            "weights": dict(CANDIDATE_SCORING_WEIGHTS),
            "factor_details": [
                {"key": f.key, "raw": round(f.raw_value, 3), "weight": f.weight, "weighted": round(f.weighted_value, 4), "reason": f.reason}
                for f in factors
            ],
            "asset_match_count": asset_matches,
            "patch_available": patch_available,
            "observability_score": round(observability, 3),
            "linux_reproducibility_confidence": round(reproducibility, 3),
            "environment_applicability": applicability,
            "citations": citations,
        }

    def _compute_scoring_factors(
        self,
        *,
        cve: CVE,
        risk: Optional[RiskScore],
        kev: Optional[KEVEntry],
        epss: Optional[EPSSSnapshot],
        affected: Optional[AffectedProduct],
        asset_matches: int,
        patch_available: bool,
    ) -> List[ScoringFactor]:
        """Build the ordered list of scoring factors with named weights."""
        w = CANDIDATE_SCORING_WEIGHTS

        risk_val = float(risk.overall_score / 100.0) if risk and risk.overall_score is not None else 0.35
        epss_val = float(epss.score) if epss else 0.0
        kev_val = 1.0 if kev else 0.0
        pkg_val = min(1.0, asset_matches / 3.0)

        # Attack surface: network-reachable CVEs score higher
        attack_surface = 0.9 if cve.attack_vector == "NETWORK" else (0.7 if cve.attack_vector == "ADJACENT" else 0.4)
        observability = 0.85 if cve.attack_vector == "NETWORK" else 0.65
        reproducibility = 0.9 if affected else 0.55
        # Patch availability penalises already-patched CVEs (lower research urgency)
        patch_factor = 0.3 if patch_available else 0.8

        # Exploit maturity: KEV + high EPSS implies mature exploitation
        exploit_maturity = min(1.0, kev_val * 0.5 + epss_val * 0.5 + (0.2 if cve.exploit_available else 0.0))

        raw = {
            "risk_score": (risk_val, "Overall risk composite from prior scoring"),
            "epss": (epss_val, f"EPSS probability {epss_val:.3f}" if epss else "No EPSS data available"),
            "kev": (kev_val, "In CISA KEV catalog" if kev else "Not in KEV catalog"),
            "package_match_confidence": (pkg_val, f"{asset_matches} tenant asset(s) match affected package"),
            "attack_surface": (attack_surface, f"Attack vector: {cve.attack_vector or 'UNKNOWN'}"),
            "observability": (observability, "Network vector aids monitoring" if observability > 0.7 else "Local vector limits telemetry"),
            "linux_reproducibility": (reproducibility, "Affected product data present" if affected else "No affected product mapping"),
            "patch_availability": (patch_factor, "Patch available — lower research urgency" if patch_available else "No patch — higher research urgency"),
            "exploit_maturity": (exploit_maturity, "Composite of KEV, EPSS, and known exploit signals"),
        }

        return [
            ScoringFactor(key=key, raw_value=val, weight=w[key], weighted_value=val * w[key], reason=reason)
            for key, (val, reason) in raw.items()
        ]

    def _build_citations(
        self,
        *,
        cve: CVE,
        tenant: Tenant,
        kev: Optional[KEVEntry],
        epss: Optional[EPSSSnapshot],
        affected: Optional[AffectedProduct],
    ) -> List[Dict[str, Any]]:
        """Build a normalized list of explainability citations from all available sources."""
        citations: List[Dict[str, Any]] = []

        if kev and kev.source_url:
            citations.append({"type": "kev", "label": "CISA KEV", "url": kev.source_url, "detail": kev.short_description if hasattr(kev, "short_description") else None})
        if epss and epss.source_url:
            citations.append({"type": "epss", "label": "FIRST EPSS", "url": epss.source_url, "detail": f"Score {epss.score:.3f}, percentile {epss.percentile:.3f}" if epss.percentile else None})

        # Advisory citations from AdvisoryRecord
        advisories = (
            self.session.query(AdvisoryRecord)
            .filter(AdvisoryRecord.cve_id == cve.id)
            .limit(5)
            .all()
        )
        for adv in advisories:
            citations.append({"type": "advisory", "label": adv.title, "url": adv.source_url, "detail": adv.summary})

        # Knowledge document citations
        knowledge_docs = (
            self.session.query(KnowledgeDocument)
            .filter(KnowledgeDocument.cve_id == cve.id)
            .limit(5)
            .all()
        )
        for doc in knowledge_docs:
            citations.append({
                "type": f"knowledge_{doc.document_type}",
                "label": doc.title,
                "url": doc.source_url,
                "detail": (doc.content[:200] + "...") if doc.content and len(doc.content) > 200 else doc.content,
            })

        # VEX citations
        vex_stmts = (
            self.session.query(VexStatement)
            .filter(VexStatement.cve_id == cve.cve_id.upper(), VexStatement.tenant_id == tenant.id)
            .limit(5)
            .all()
        )
        for stmt in vex_stmts:
            citations.append({
                "type": "vex",
                "label": f"VEX: {stmt.status}",
                "url": stmt.source_url,
                "detail": stmt.justification,
            })

        # Package / affected product citation
        if affected:
            citations.append({
                "type": "affected_product",
                "label": f"Affected: {affected.vendor or 'unknown'}/{affected.product}",
                "url": None,
                "detail": f"Version range from NVD affected product data",
            })

        # Asset match rationale
        asset_count = self._asset_match_count(tenant, affected)
        if asset_count > 0:
            citations.append({
                "type": "asset_match",
                "label": f"{asset_count} tenant asset(s) match",
                "url": None,
                "detail": f"Matched via installed_software on {asset_count} asset record(s)",
            })

        return citations

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
            "status_reason": candidate.status_reason,
            "status_changed_at": candidate.status_changed_at.isoformat() if candidate.status_changed_at else None,
            "status_changed_by": candidate.status_changed_by,
            "merged_into_id": candidate.merged_into_id,
            "assignment_state": candidate.assignment_state,
            "assigned_to": candidate.assigned_to,
            "assigned_by": candidate.assigned_by,
            "assigned_at": candidate.assigned_at.isoformat() if candidate.assigned_at else None,
            "package_name": candidate.package_name,
            "product_name": candidate.product_name,
            "distro_hint": candidate.distro_hint,
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

    def _apply_provider_result(self, run: LabRun, result: ProviderResult) -> None:
        """Apply a ProviderResult to a LabRun record."""
        run.provider_run_ref = result.provider_run_ref
        run.state = result.state.value if isinstance(result.state, RunState) else result.state
        run.guest_image = result.plan.get("image")
        run.image_digest = result.plan.get("image_digest")
        run.network_mode = result.plan.get("network_mode")
        run.manifest = result.plan
        run.run_transcript = result.transcript

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

    def validate_recipe_content(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Validate recipe content against schema rules."""
        from app.lab.recipe_schema import RecipeSchemaValidator
        result = RecipeSchemaValidator().validate(content)
        return {"valid": result.valid, "errors": result.errors, "warnings": result.warnings}

    def lint_recipe_content(self, content: Dict[str, Any], expected_distro: Optional[str] = None) -> Dict[str, Any]:
        """Lint recipe content for risky configurations."""
        from app.lab.recipe_schema import RecipeLinter
        result = RecipeLinter(expected_distro=expected_distro).lint(content)
        return {"errors": result.errors, "warnings": result.warnings, "has_blocking_errors": result.has_blocking_errors}

    def diff_recipe_revisions(self, tenant: Tenant, *, recipe_id: int, old_revision: int, new_revision: int) -> Dict[str, Any]:
        """Diff two recipe revisions."""
        from app.lab.recipe_schema import RecipeDiffEngine
        recipe = self._get_recipe(tenant, recipe_id)
        old_rev = self._get_recipe_revision(recipe.id, old_revision)
        new_rev = self._get_recipe_revision(recipe.id, new_revision)
        result = RecipeDiffEngine().diff(old_rev.content or {}, new_rev.content or {})
        return result.to_dict()

    def list_templates(self, tenant: Tenant) -> Dict[str, Any]:
        """List available lab templates."""
        self._ensure_template_catalog()
        rows = self.session.query(LabTemplate).order_by(LabTemplate.distro.asc(), LabTemplate.name.asc()).all()
        return {
            "items": [
                {
                    "id": t.id,
                    "provider": t.provider,
                    "name": t.name,
                    "distro": t.distro,
                    "base_image": t.base_image,
                    "is_hardened": t.is_hardened,
                    "network_mode": t.network_mode,
                    "meta": t.meta,
                }
                for t in rows
            ],
            "count": len(rows),
        }

    def _normalize_recipe_content(self, content: Dict[str, Any], image: str) -> Dict[str, Any]:
        normalized = dict(content)
        normalized.setdefault("base_image", image)
        normalized.setdefault("command", ["sleep", "1"])
        normalized.setdefault("network_policy", {"allow_egress_hosts": []})
        normalized.setdefault(
            "collectors",
            ["process_tree", "package_inventory", "file_diff", "network_metadata", "service_logs", "tracee_events"],
        )
        normalized.setdefault("teardown_policy", {"mode": "destroy_immediately", "ephemeral_workspace": True})
        normalized.setdefault("risk_level", "standard")
        normalized.setdefault("workspace_retention", "destroy_immediately")
        return normalized

    def _ensure_source_feeds(self) -> None:
        defaults = [
            ("nvd", "NVD", "intel", "active", "https://nvd.nist.gov/"),
            ("kev", "CISA KEV", "exploitability", "active", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ("epss", "FIRST EPSS", "exploitability", "active", "https://www.first.org/epss/"),
            ("osv", "OSV", "package", "planned", "https://osv.dev/"),
            ("ghsa", "GitHub Advisory Database", "package", "planned", "https://github.com/advisories"),
        ]
        seen_keys: set = set()

        for connector_cls in get_registered_connectors().values():
            key = connector_cls.name
            seen_keys.add(key)
            feed = self.session.query(SourceFeed).filter(SourceFeed.feed_key == key).first()
            if feed is None:
                self.session.add(
                    SourceFeed(
                        feed_key=key,
                        display_name=connector_cls.display_name,
                        category=getattr(connector_cls, "category", "intel"),
                        status="active",
                        source_url=getattr(connector_cls, "source_url", ""),
                        freshness_seconds=getattr(connector_cls, "default_freshness_seconds", 21600),
                        last_synced_at=utc_now(),
                    )
                )

        for feed_key, display_name, category, status, url in defaults:
            if feed_key in seen_keys:
                continue
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

    def _ensure_template_catalog(self) -> None:
        """Seed the full template catalog including Ubuntu, Debian, and Rocky."""
        catalog = [
            {
                "provider": "docker_kali",
                "name": "Constrained Kali Validation",
                "distro": "kali",
                "base_image": DEFAULT_KALI_IMAGE,
                "is_hardened": True,
                "network_mode": "isolated",
                "meta": {
                    "read_only_rootfs": True,
                    "default_cap_drop": ["ALL"],
                    "egress_policy": "default-deny",
                    "description": "Default Kali-on-Docker for offensive validation.",
                },
            },
            {
                "provider": "docker_kali",
                "name": "Ubuntu Server LTS Validation",
                "distro": "ubuntu",
                "base_image": "ubuntu:24.04",
                "is_hardened": True,
                "network_mode": "isolated",
                "meta": {
                    "read_only_rootfs": True,
                    "default_cap_drop": ["ALL"],
                    "egress_policy": "default-deny",
                    "description": "Ubuntu LTS for server-side vulnerability reproduction.",
                    "compatibility_hints": ["apt-based", "systemd", "glibc"],
                },
            },
            {
                "provider": "docker_kali",
                "name": "Debian Stable Validation",
                "distro": "debian",
                "base_image": "debian:bookworm-slim",
                "is_hardened": True,
                "network_mode": "isolated",
                "meta": {
                    "read_only_rootfs": True,
                    "default_cap_drop": ["ALL"],
                    "egress_policy": "default-deny",
                    "description": "Debian stable for minimal-footprint validation.",
                    "compatibility_hints": ["apt-based", "systemd", "glibc"],
                },
            },
            {
                "provider": "docker_kali",
                "name": "Rocky Linux Validation",
                "distro": "rocky",
                "base_image": "rockylinux:9-minimal",
                "is_hardened": True,
                "network_mode": "isolated",
                "meta": {
                    "read_only_rootfs": True,
                    "default_cap_drop": ["ALL"],
                    "egress_policy": "default-deny",
                    "description": "Rocky Linux for RHEL-family vulnerability reproduction.",
                    "compatibility_hints": ["dnf-based", "systemd", "glibc", "selinux"],
                },
            },
        ]
        for entry in catalog:
            existing = (
                self.session.query(LabTemplate)
                .filter(LabTemplate.provider == entry["provider"], LabTemplate.name == entry["name"])
                .first()
            )
            if existing is None:
                self.session.add(
                    LabTemplate(
                        provider=entry["provider"],
                        name=entry["name"],
                        distro=entry["distro"],
                        base_image=entry["base_image"],
                        image_digest=self.attestation_signer.sign(
                            payload={"image": entry["base_image"]}, signer="system"
                        )["sha256"],
                        is_hardened=entry["is_hardened"],
                        network_mode=entry["network_mode"],
                        meta=entry["meta"],
                    )
                )
        self.session.flush()

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

    def _compute_environment_applicability(
        self,
        *,
        cve: CVE,
        tenant: Tenant,
        affected: Optional[AffectedProduct],
    ) -> Dict[str, Any]:
        """Compute rich applicability using SBOM components, VEX, and asset mappings."""
        result: Dict[str, Any] = {
            "match_sources": [],
            "confidence": 0.0,
            "vex_status": None,
            "vex_justification": None,
            "direct_product_match": False,
            "sbom_component_match": False,
            "asset_match_count": 0,
            "sbom_match_count": 0,
        }

        # 1. Legacy asset installed_software match
        asset_matches = self._asset_match_count(tenant, affected)
        result["asset_match_count"] = asset_matches
        if asset_matches > 0:
            result["match_sources"].append({"source": "asset_installed_software", "count": asset_matches, "confidence": 0.6})

        # 2. SBOM component match via SoftwareComponent table
        sbom_matches = 0
        if affected and affected.product:
            product_lower = affected.product.lower()
            components = (
                self.session.query(SoftwareComponent)
                .filter(SoftwareComponent.tenant_id == tenant.id)
                .all()
            )
            for comp in components:
                if comp.name and comp.name.lower() == product_lower:
                    sbom_matches += 1
                    result["direct_product_match"] = True
                elif comp.purl and product_lower in (comp.purl or "").lower():
                    sbom_matches += 1
                    result["sbom_component_match"] = True

        result["sbom_match_count"] = sbom_matches
        if sbom_matches > 0:
            result["match_sources"].append({"source": "sbom_component", "count": sbom_matches, "confidence": 0.85})

        # 3. VEX status check
        vex_statements = (
            self.session.query(VexStatement)
            .filter(VexStatement.tenant_id == tenant.id, VexStatement.cve_id == cve.cve_id.upper())
            .all()
        )
        if vex_statements:
            best = vex_statements[0]
            result["vex_status"] = best.status
            result["vex_justification"] = best.justification
            vex_conf = {"not_affected": -0.5, "fixed": -0.3, "affected": 0.9, "under_investigation": 0.5}
            result["match_sources"].append({
                "source": "vex_statement",
                "status": best.status,
                "confidence": vex_conf.get(best.status, 0.5),
            })

        # Aggregate confidence: highest source wins, with additive bonus for multiple sources
        if result["match_sources"]:
            confidences = [s["confidence"] for s in result["match_sources"]]
            result["confidence"] = min(1.0, max(confidences) + 0.1 * (len(confidences) - 1))
        else:
            result["confidence"] = 0.1

        return result

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

    def _epss_filter_cve_ids(self, epss_min: Optional[float], epss_max: Optional[float]) -> Optional[List[int]]:
        """Return CVE DB IDs whose latest EPSS falls within [epss_min, epss_max]."""
        all_epss = self.session.query(EPSSSnapshot).all()
        latest: Dict[str, EPSSSnapshot] = {}
        for row in all_epss:
            key = row.cve_id.upper()
            existing = latest.get(key)
            if existing is None or (row.scored_at and existing.scored_at and row.scored_at > existing.scored_at):
                latest[key] = row

        matching_cve_ids = set()
        for cve_id, snap in latest.items():
            if epss_min is not None and snap.score < epss_min:
                continue
            if epss_max is not None and snap.score > epss_max:
                continue
            matching_cve_ids.add(cve_id)

        if not matching_cve_ids:
            return []
        db_ids = [c.id for c in self.session.query(CVE).filter(CVE.cve_id.in_(matching_cve_ids)).all()]
        return db_ids

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
