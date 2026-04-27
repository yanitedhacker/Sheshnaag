"""Core application service layer for Project Sheshnaag."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from app.core.time import utc_now
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.tenancy import resolve_tenant
from app.ingestion.connector import get_registered_connectors
from app.models.ops import FeedSyncRun, FeedSyncState
from app.lab.artifact_generator import DefensiveArtifactGenerator
from app.core.config import settings
from app.lab.attestation import Ed25519AttestationSigner, HashAttestationSigner
from app.lab.collector_contract import (
    DEFAULT_RECIPE_COLLECTORS,
    build_provider_result_dict,
    recipe_collector_names,
)
from app.lab.collectors import instantiate_collectors
from app.lab.collectors.common import collector_error_evidence
from app.lab.docker_kali_provider import DEFAULT_KALI_IMAGE, DEFAULT_OSQUERY_IMAGE, DEFAULT_TRACEE_IMAGE
from app.lab.image_catalog import list_image_catalog, resolve_catalog_entry
from app.lab.interfaces import HealthStatus, ProviderResult, RunState, normalize_launch_mode, validate_transition
from app.lab.provider_registry import SUPPORTED_PROVIDER_NAMES, build_default_provider_registry
from app.models.asset import Asset, AssetVulnerability
from app.models.cve import AffectedProduct, CVE
from app.models.risk_score import RiskScore
from app.models.sheshnaag import (
    AdvisoryRecord,
    AdvisoryPackageLink,
    AnalystIdentity,
    AttestationRecord,
    CandidateScoreRecalculationRun,
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
    RawKnowledgeSource,
    RecipeRevision,
    ResearchCandidate,
    ReviewDecision,
    RunEvent,
    SourceFeed,
    TenantSigningKey,
    VersionRange,
    WorkstationFingerprint,
)
from app.models.v2 import AssetSoftware, EPSSSnapshot, KEVEntry, KnowledgeDocument, SoftwareComponent, Tenant, VexStatement
from app.services.advisory_normalization import summarize_advisory_records
from app.services.candidate_scoring import (
    CANDIDATE_SCORING_WEIGHTS,
    CandidateScoringContext,
    compute_candidate_explainability,
)
from app.services.intel_service import ThreatIntelService
from app.services.knowledge_service import KnowledgeRetrievalService

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
        self.knowledge = KnowledgeRetrievalService(session)
        self.provider_registry = build_default_provider_registry()
        self.providers = {name: self.provider_registry.create(name) for name in self.provider_registry.supported()}
        self.provider = self.providers["docker_kali"]
        self.artifact_generator = DefensiveArtifactGenerator()
        self.default_attestation_signer = HashAttestationSigner()
        self.export_root = Path(os.getenv("SHESHNAAG_EXPORT_ROOT", "/tmp/sheshnaag_exports"))
        self._backfill_live_launch_modes()

    def _backfill_live_launch_modes(self) -> None:
        self.session.query(LabRun).filter(LabRun.launch_mode == "live").update(
            {LabRun.launch_mode: "execute"},
            synchronize_session=False,
        )

    def _tenant_signing_key_path(self, tenant: Tenant, *, key_name: str = "default") -> str:
        safe_slug = (tenant.slug or f"tenant-{tenant.id}").replace("/", "-")
        return str(Path(settings.signing_key_dir) / f"{safe_slug}-{key_name}.ed25519")

    def _ensure_tenant_signing_key(self, tenant: Tenant, *, key_name: str = "default") -> TenantSigningKey:
        record = (
            self.session.query(TenantSigningKey)
            .filter(TenantSigningKey.tenant_id == tenant.id, TenantSigningKey.key_name == key_name)
            .first()
        )
        key_path = self._tenant_signing_key_path(tenant, key_name=key_name)
        material = Ed25519AttestationSigner.ensure_key_material(key_path)
        if record is None:
            record = TenantSigningKey(
                tenant_id=tenant.id,
                key_name=key_name,
                algorithm="ed25519",
                public_key=material["public_key"],
                fingerprint=material["fingerprint"],
                storage_backend="local-file",
                key_path=material["key_path"],
            )
            self.session.add(record)
            self.session.flush()
            return record

        record.algorithm = "ed25519"
        record.public_key = material["public_key"]
        record.fingerprint = material["fingerprint"]
        record.storage_backend = "local-file"
        record.key_path = material["key_path"]
        return record

    def _attestation_signer_for_tenant(self, tenant: Tenant) -> Ed25519AttestationSigner:
        key = self._ensure_tenant_signing_key(tenant)
        return Ed25519AttestationSigner(
            private_key_path=key.key_path or self._tenant_signing_key_path(tenant),
            public_key=key.public_key,
            fingerprint=key.fingerprint,
        )

    def _assert_transition(self, run: LabRun, target: RunState) -> None:
        current = RunState(run.state) if run.state in {s.value for s in RunState} else RunState.ERRORED
        if not validate_transition(current, target):
            raise ValueError(
                f"Invalid run state transition from '{current.value}' to '{target.value}'."
            )

    def _provider_for_name(self, provider_name: Optional[str]) -> Any:
        normalized = (provider_name or "docker_kali").strip().lower()
        provider = self.providers.get(normalized)
        if provider is None:
            raise ValueError(f"Unsupported provider '{provider_name}'. Expected one of {sorted(self.providers)}.")
        return provider

    def _provider_for_revision(self, recipe: LabRecipe, revision: RecipeRevision) -> Any:
        content = dict(revision.content or {})
        provider_name = str(content.get("provider") or recipe.provider or "docker_kali")
        return self._provider_for_name(provider_name)

    def _enforce_execution_policy(
        self,
        *,
        recipe: LabRecipe,
        revision: RecipeRevision,
        launch_mode: str,
    ) -> str:
        content = dict(revision.content or {})
        provider_name = str(content.get("provider") or recipe.provider or "docker_kali")
        if provider_name not in SUPPORTED_PROVIDER_NAMES:
            raise ValueError(f"Unsupported provider '{provider_name}'.")
        execution_policy = content.get("execution_policy") or {}
        secure_mode_required = bool(execution_policy.get("secure_mode_required"))
        if secure_mode_required and provider_name != "lima":
            raise ValueError("This recipe requires secure mode and must use the Lima provider.")
        allowed_modes = execution_policy.get("allowed_modes") or ["dry_run", "simulated", "execute"]
        if launch_mode not in allowed_modes:
            raise ValueError(f"Launch mode '{launch_mode}' is not allowed for this recipe.")
        return provider_name

    def _add_run_event(
        self,
        run: LabRun,
        event_type: str,
        result: ProviderResult,
        level: str = "info",
        message: Optional[str] = None,
    ) -> None:
        self.session.add(
            RunEvent(
                run_id=run.id,
                event_type=event_type,
                level=level,
                message=message or result.transcript,
                payload=result.to_dict(),
            )
        )

    def _publish_live_run_event(
        self,
        run: LabRun,
        event_type: str,
        *,
        severity: str = "info",
        source: str = "api",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        from app.core.event_bus import EventBus, run_event_stream

        EventBus().publish(
            run_event_stream(run.id),
            {
                "run_id": run.id,
                "type": event_type,
                "timestamp": utc_now().isoformat(),
                "severity": severity,
                "source": source,
                "payload": payload or {},
            },
        )

    def _enqueue_sandbox_work(self, *, run: LabRun, tenant: Tenant, actor: str) -> str:
        from app.core.event_bus import EventBus, SANDBOX_WORK_STREAM

        return EventBus().publish(
            SANDBOX_WORK_STREAM,
            {
                "run_id": run.id,
                "tenant_id": tenant.id,
                "actor": actor,
                "correlation_id": uuid.uuid4().hex,
            },
        )

    def _analyst_display_name(self, run: LabRun) -> str:
        if run.analyst_id:
            row = (
                self.session.query(AnalystIdentity)
                .filter(AnalystIdentity.id == run.analyst_id)
                .first()
            )
            if row:
                return row.name
        return "analyst"

    def _run_context_for_provider(
        self,
        tenant: Tenant,
        run: LabRun,
        *,
        analyst_name: str,
        candidate: Optional[ResearchCandidate],
    ) -> Dict[str, Any]:
        return {
            "run_id": run.id,
            "tenant_slug": tenant.slug,
            "analyst_name": analyst_name,
            "provider": run.provider,
            "launch_mode": run.launch_mode,
            "analysis_mode": (run.manifest or {}).get("analysis_mode", "cve_validation"),
            "specimen_ids": (run.manifest or {}).get("specimen_ids") or [],
            "candidate": self._candidate_payload(candidate) if candidate else {},
            "cve_id": candidate.cve.cve_id if candidate and candidate.cve else None,
        }

    def _resolve_v3_run_context(
        self,
        tenant: Tenant,
        *,
        provider_name: str,
        launch_mode: str,
        analysis_mode: Optional[str],
        sandbox_profile_id: Optional[int],
        specimen_ids: Optional[List[int]],
        egress_mode: Optional[str],
        ai_assist_enabled: bool,
        ai_provider_hint: Optional[str],
    ) -> Dict[str, Any]:
        from app.services.malware_lab_service import MalwareLabService

        resolved = MalwareLabService(self.session).resolve_run_contract(
            tenant,
            provider_name=provider_name,
            analysis_mode=analysis_mode,
            sandbox_profile_id=sandbox_profile_id,
            specimen_ids=specimen_ids,
            egress_mode=egress_mode,
            ai_assist_enabled=ai_assist_enabled,
            ai_provider_hint=ai_provider_hint,
        )
        risky_modes = {"malware_detonation", "url_analysis", "email_analysis"}
        if resolved["analysis_mode"] in risky_modes and resolved["resolved_provider_name"] != "lima" and launch_mode in {"simulated", "execute"}:
            raise ValueError("Risky malware analysis modes require the Lima provider.")
        return resolved

    def _persist_v3_run_context(self, run: LabRun, *, v3_context: Dict[str, Any]) -> None:
        manifest = dict(run.manifest or {})
        manifest["analysis_mode"] = v3_context["analysis_mode"]
        manifest["sandbox_profile_id"] = v3_context["sandbox_profile_id"]
        manifest["sandbox_profile"] = v3_context["sandbox_profile"]
        manifest["specimen_ids"] = v3_context["specimen_ids"]
        manifest["specimen_revisions"] = v3_context.get("specimen_revisions") or []
        manifest["egress_mode"] = v3_context["egress_mode"]
        manifest["ai_assist"] = {
            "enabled": v3_context["ai_assist_enabled"],
            "provider_hint": v3_context["ai_provider_hint"],
        }
        manifest["collector_plan"] = v3_context.get("collector_plan") or []
        manifest["policy_snapshot"] = v3_context.get("policy_snapshot") or {}
        manifest["linked_case_ids"] = v3_context.get("linked_case_ids") or []
        manifest["execution_plan"] = v3_context.get("execution_plan") or {}
        manifest["v3_context"] = {
            "analysis_mode": v3_context["analysis_mode"],
            "sandbox_profile_id": v3_context["sandbox_profile_id"],
            "specimen_ids": v3_context["specimen_ids"],
            "specimen_revisions": v3_context.get("specimen_revisions") or [],
            "egress_mode": v3_context["egress_mode"],
            "ai_assist_enabled": v3_context["ai_assist_enabled"],
            "ai_provider_hint": v3_context["ai_provider_hint"],
            "collector_plan": v3_context.get("collector_plan") or [],
            "policy_snapshot": v3_context.get("policy_snapshot") or {},
            "resolved_provider_name": v3_context.get("resolved_provider_name"),
            "linked_case_ids": v3_context.get("linked_case_ids") or [],
            "execution_plan": v3_context.get("execution_plan") or {},
        }
        run.manifest = manifest
        if v3_context["egress_mode"] != "default_deny":
            run.network_mode = v3_context["egress_mode"]
        if v3_context.get("resolved_provider_name"):
            run.provider = v3_context["resolved_provider_name"]

    def _revision_content_for_provider(self, content: Dict[str, Any], provider_name: str) -> Dict[str, Any]:
        """Adapt trusted recipe defaults when policy resolves to a different provider."""
        resolved = dict(content or {})
        original_provider = str(resolved.get("provider") or "docker_kali")
        if provider_name == original_provider:
            return resolved
        resolved["provider"] = provider_name
        if provider_name == "lima":
            resolved.pop("base_image", None)
            resolved.pop("image_profile", None)
            execution_policy = dict(resolved.get("execution_policy") or {})
            execution_policy["preferred_provider"] = "lima"
            execution_policy["secure_mode_required"] = True
            resolved["execution_policy"] = execution_policy
        return resolved

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

    def sync_candidates(self, tenant: Tenant, *, force: bool = False) -> None:
        """Populate research candidates from current CVE/intel context."""
        self._ensure_source_feeds()
        self.knowledge.backfill_knowledge_layers()
        if not force and not self._candidate_cache_is_stale(tenant):
            self._ensure_lab_template()
            self._ensure_analyst_identity(tenant)
            return

        cves = self._candidate_sync_cves()
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

    def _candidate_cache_is_stale(self, tenant: Tenant) -> bool:
        latest_candidate = (
            self.session.query(ResearchCandidate)
            .filter(ResearchCandidate.tenant_id == tenant.id)
            .order_by(desc(ResearchCandidate.updated_at), desc(ResearchCandidate.id))
            .first()
        )
        if latest_candidate is None:
            return True

        newest_source_sync = self.session.query(func.max(SourceFeed.last_synced_at)).scalar()
        latest_candidate_ts = latest_candidate.updated_at or latest_candidate.created_at
        if newest_source_sync and latest_candidate_ts and newest_source_sync > latest_candidate_ts:
            return True
        if not latest_candidate_ts:
            return True
        age_seconds = (utc_now().replace(tzinfo=None) - latest_candidate_ts.replace(tzinfo=None)).total_seconds()
        return age_seconds > settings.candidate_sync_stale_seconds

    def _candidate_sync_cves(self) -> List[CVE]:
        lookback_start = utc_now() - timedelta(days=settings.candidate_sync_lookback_days)
        limit = settings.candidate_sync_limit
        selected: Dict[int, CVE] = {}

        recent_rows = (
            self.session.query(CVE)
            .filter(CVE.published_date.isnot(None), CVE.published_date >= lookback_start)
            .order_by(desc(CVE.published_date), desc(CVE.id))
            .limit(limit)
            .all()
        )
        for row in recent_rows:
            selected[row.id] = row

        kev_ids = [row.cve_id for row in self.session.query(KEVEntry.cve_id).all()]
        if kev_ids:
            for row in self.session.query(CVE).filter(CVE.cve_id.in_(kev_ids)).all():
                selected[row.id] = row

        for row in self.session.query(CVE).filter(CVE.exploit_available.is_(True)).limit(limit).all():
            selected[row.id] = row

        advisory_rows = (
            self.session.query(AdvisoryRecord)
            .filter(AdvisoryRecord.cve_id.isnot(None))
            .order_by(desc(AdvisoryRecord.published_at), desc(AdvisoryRecord.id))
            .all()
        )
        advisory_cve_ids = {int(row.cve_id) for row in advisory_rows if row.cve_id}
        if advisory_cve_ids:
            for row in self.session.query(CVE).filter(CVE.id.in_(advisory_cve_ids)).all():
                selected[row.id] = row

        ranked = sorted(
            selected.values(),
            key=lambda row: (
                1 if row.cve_id in set(kev_ids) else 0,
                1 if row.exploit_available else 0,
                row.published_date or datetime.min,
                row.id,
            ),
            reverse=True,
        )
        return ranked[:limit]

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
        exploit_available: Optional[bool] = None,
        min_observability: Optional[float] = None,
        max_observability: Optional[float] = None,
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

        if exploit_available is not None:
            query = query.join(CVE, ResearchCandidate.cve_id == CVE.id).filter(
                CVE.exploit_available == exploit_available
            )
        if min_observability is not None:
            query = query.filter(ResearchCandidate.observability_score >= min_observability)
        if max_observability is not None:
            query = query.filter(ResearchCandidate.observability_score <= max_observability)

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

    def recalculate_candidate_scores(
        self,
        tenant: Tenant,
        *,
        requested_by: str,
        dry_run: bool = True,
        reason: Optional[str] = None,
        candidate_ids: Optional[List[int]] = None,
        package_name: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Recompute candidate scores/explainability and persist a recalculation summary."""
        self.sync_candidates(tenant)
        query = self.session.query(ResearchCandidate).filter(ResearchCandidate.tenant_id == tenant.id)
        if candidate_ids:
            query = query.filter(ResearchCandidate.id.in_(candidate_ids))
        if package_name:
            query = query.filter(ResearchCandidate.package_name.ilike(f"%{package_name}%"))
        query = query.order_by(ResearchCandidate.id.asc())
        if limit:
            query = query.limit(limit)
        rows = query.all()

        epss_map = self.intel.get_latest_epss_map([row.cve.cve_id for row in rows if row.cve and row.cve.cve_id])
        kev_map = self.intel.get_kev_map([row.cve.cve_id for row in rows if row.cve and row.cve.cve_id])
        latest_risk = self._latest_risk_by_cve_id([row.cve_id for row in rows if row.cve_id])

        changed_count = 0
        total_delta = 0.0
        items: List[Dict[str, Any]] = []
        for candidate in rows:
            cve = candidate.cve
            if cve is None:
                continue
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
            new_score = explainability["score"]
            score_delta = round(float(new_score) - float(candidate.candidate_score or 0.0), 2)
            old_status = candidate.status
            new_status = "queued" if new_score >= 35 else "deferred"
            changed = (
                round(float(candidate.candidate_score or 0.0), 2) != round(float(new_score), 2)
                or candidate.explainability != explainability
                or candidate.status != new_status
            )
            if changed:
                changed_count += 1
                total_delta += score_delta
            items.append(
                {
                    "candidate_id": candidate.id,
                    "cve_id": cve.cve_id,
                    "previous_score": round(float(candidate.candidate_score or 0.0), 2),
                    "new_score": round(float(new_score), 2),
                    "score_delta": score_delta,
                    "previous_status": old_status,
                    "new_status": new_status,
                    "changed": changed,
                }
            )
            if dry_run:
                continue
            candidate.candidate_score = new_score
            candidate.status = new_status
            candidate.explainability = explainability
            candidate.package_record_id = package.id if package else candidate.package_record_id
            candidate.product_record_id = product.id if product else candidate.product_record_id
            candidate.package_name = affected.product if affected else candidate.package_name
            candidate.product_name = affected.product if affected else candidate.product_name
            candidate.patch_available = explainability["patch_available"]
            candidate.linux_reproducibility_confidence = explainability["linux_reproducibility_confidence"]
            candidate.observability_score = explainability["observability_score"]

        summary = {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "dry_run": dry_run,
            "requested_by": requested_by,
            "reason": reason,
            "total_candidates": len(items),
            "changed_count": changed_count,
            "unchanged_count": max(0, len(items) - changed_count),
            "average_score_delta": round((total_delta / changed_count), 2) if changed_count else 0.0,
            "items": items[:200],
        }
        record = CandidateScoreRecalculationRun(
            tenant_id=tenant.id,
            requested_by=requested_by,
            status="completed",
            dry_run=dry_run,
            reason=reason,
            filters={
                "candidate_ids": candidate_ids or [],
                "package_name": package_name,
                "limit": limit,
            },
            summary=summary,
        )
        self.session.add(record)
        self.session.flush()
        self._ledger(
            tenant.id,
            None,
            "candidate_scores_recalculated",
            "candidate_score_recalculation_run",
            str(record.id),
            1.5,
            {
                "dry_run": dry_run,
                "changed_count": changed_count,
                "requested_by": requested_by,
            },
        )
        summary["recalculation_run_id"] = record.id
        if not dry_run:
            self.session.flush()
        return summary

    def list_candidate_recalculation_runs(self, tenant: Tenant, *, limit: int = 20) -> Dict[str, Any]:
        rows = (
            self.session.query(CandidateScoreRecalculationRun)
            .filter(CandidateScoreRecalculationRun.tenant_id == tenant.id)
            .order_by(desc(CandidateScoreRecalculationRun.created_at), desc(CandidateScoreRecalculationRun.id))
            .limit(limit)
            .all()
        )
        return {
            "count": len(rows),
            "items": [
                {
                    "id": row.id,
                    "requested_by": row.requested_by,
                    "status": row.status,
                    "dry_run": row.dry_run,
                    "reason": row.reason,
                    "filters": row.filters,
                    "summary": row.summary,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                }
                for row in rows
            ],
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
        normalized_content = self._prepare_recipe_content(content, None)
        template = self._ensure_lab_template(
            provider_name=str(normalized_content.get("provider") or "docker_kali"),
            image_profile=str(normalized_content.get("image_profile") or "baseline"),
        )
        recipe = LabRecipe(
            tenant_id=tenant.id,
            candidate_id=candidate.id,
            template_id=template.id,
            name=name,
            objective=objective,
            provider=str(normalized_content.get("provider") or "docker_kali"),
            status="draft",
            created_by=created_by,
            current_revision_number=1,
        )
        self.session.add(recipe)
        self.session.flush()
        signer = self._attestation_signer_for_tenant(tenant)
        revision = RecipeRevision(
            recipe_id=recipe.id,
            revision_number=1,
            approval_state="draft",
            risk_level=normalized_content.get("risk_level", "standard"),
            requires_acknowledgement=bool(normalized_content.get("requires_acknowledgement", False)),
            signed_digest=signer.sign(payload=normalized_content, signer=created_by)["sha256"],
            content=normalized_content,
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
        normalized_content = self._prepare_recipe_content(content, None)
        signer = self._attestation_signer_for_tenant(tenant)
        revision = RecipeRevision(
            recipe_id=recipe.id,
            revision_number=next_revision,
            approval_state="draft",
            risk_level=normalized_content.get("risk_level", "standard"),
            requires_acknowledgement=bool(normalized_content.get("requires_acknowledgement", False)),
            signed_digest=signer.sign(payload=normalized_content, signer=updated_by)["sha256"],
            content=normalized_content,
        )
        recipe.provider = str(normalized_content.get("provider") or recipe.provider or "docker_kali")
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
                rationale=(
                    "Approved for secure-mode Lima validation."
                    if recipe.provider == "lima"
                    else "Approved for trusted-image constrained validation."
                ),
                payload={
                    "recipe_id": recipe.id,
                    "revision_number": revision_number,
                    "provider": recipe.provider,
                },
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
        analysis_mode: str = "cve_validation",
        sandbox_profile_id: Optional[int] = None,
        specimen_ids: Optional[List[int]] = None,
        egress_mode: Optional[str] = None,
        ai_assist_enabled: bool = False,
        ai_provider_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Launch or simulate a validation run."""
        launch_mode = normalize_launch_mode(launch_mode)
        recipe = self._get_recipe(tenant, recipe_id)
        revision = self._get_recipe_revision(recipe.id, revision_number or recipe.current_revision_number)
        if revision.approval_state != "approved":
            raise ValueError("Recipe revision must be approved before launch.")
        if revision.requires_acknowledgement and not acknowledge_sensitive:
            raise ValueError("Sensitive recipe revisions require analyst acknowledgement before launch.")
        provider_name = self._enforce_execution_policy(recipe=recipe, revision=revision, launch_mode=launch_mode)
        v3_context = self._resolve_v3_run_context(
            tenant,
            provider_name=provider_name,
            launch_mode=launch_mode,
            analysis_mode=analysis_mode,
            sandbox_profile_id=sandbox_profile_id,
            specimen_ids=specimen_ids,
            egress_mode=egress_mode,
            ai_assist_enabled=ai_assist_enabled,
            ai_provider_hint=ai_provider_hint,
        )
        provider_name = v3_context.get("resolved_provider_name") or provider_name
        provider = self._provider_for_name(provider_name)

        analyst = self._ensure_analyst_identity(tenant, analyst_name)
        workstation_record = self._ensure_workstation(tenant, workstation)
        candidate = self._get_candidate(tenant, recipe.candidate_id) if recipe.candidate_id else None

        run = LabRun(
            tenant_id=tenant.id,
            recipe_revision_id=revision.id,
            candidate_id=recipe.candidate_id,
            analyst_id=analyst.id,
            workstation_fingerprint_id=workstation_record.id,
            provider=provider_name,
            launch_mode=launch_mode,
            state="planned",
            requires_acknowledgement=revision.requires_acknowledgement,
            acknowledged_by=analyst_name if acknowledge_sensitive else None,
            acknowledged_at=utc_now() if acknowledge_sensitive else None,
            workspace_path=f"/tmp/sheshnaag/{provider_name}/run-{recipe.id}-{revision.revision_number}",
        )
        self.session.add(run)
        self.session.flush()

        run_context = self._run_context_for_provider(
            tenant, run, analyst_name=analyst_name, candidate=candidate
        )
        provider_revision_content = self._revision_content_for_provider(revision.content or {}, provider_name)
        if launch_mode == "execute":
            built_plan = provider.build_plan(revision_content=provider_revision_content, run_context=run_context)
            queued_result = ProviderResult(
                state=RunState.PLANNED,
                provider_run_ref="",
                plan=built_plan,
                transcript="Run queued for sandbox worker execution.",
            )
            self._apply_provider_result(run, queued_result)
            run.provider_run_ref = None
            run.state = "queued"
            self._annotate_run_manifest(
                run=run,
                revision=revision,
                analyst_name=analyst_name,
                acknowledgement_recorded=acknowledge_sensitive,
            )
            self._persist_v3_run_context(run, v3_context=v3_context)
            from app.services.malware_lab_service import MalwareLabService

            try:
                preflight = MalwareLabService(self.session).enforce_run_execution_preflight(
                    tenant,
                    run=run,
                    actor=analyst_name,
                )
                run.manifest = {**dict(run.manifest or {}), "detonation_preflight": preflight}
            except ValueError as exc:
                run.state = RunState.BLOCKED.value
                run.ended_at = utc_now()
                run.manifest = {
                    **dict(run.manifest or {}),
                    "detonation_preflight": {
                        "status": "blocked",
                        "blockers": [item for item in str(exc).split(";") if item],
                    },
                }
                self._add_run_event(run, "run_blocked", queued_result, level="error", message=str(exc))
                self.session.flush()
                raise
            self._persist_run_acknowledgement(
                tenant=tenant,
                run=run,
                revision=revision,
                analyst_name=analyst_name,
                acknowledged=acknowledge_sensitive,
            )
            queue_entry_id = self._enqueue_sandbox_work(run=run, tenant=tenant, actor=analyst_name)
            queued_payload = {"queue_entry_id": queue_entry_id, "message": "Run queued for sandbox worker execution."}
            self._add_run_event(run, "run_queued", queued_result, message=queued_payload["message"])
            self._publish_live_run_event(run, "run_queued", payload=queued_payload)
            self._ledger(tenant.id, analyst.id, "run_queued", "run", str(run.id), 2.0, {"state": run.state})
            self.session.flush()
            return self.get_run(tenant, run.id)

        provider_result = provider.launch(revision_content=provider_revision_content, run_context=run_context)
        self._apply_provider_result(run, provider_result)
        self._annotate_run_manifest(
            run=run,
            revision=revision,
            analyst_name=analyst_name,
            acknowledgement_recorded=acknowledge_sensitive,
        )
        self._persist_v3_run_context(run, v3_context=v3_context)
        self._persist_run_acknowledgement(
            tenant=tenant,
            run=run,
            revision=revision,
            analyst_name=analyst_name,
            acknowledged=acknowledge_sensitive,
        )
        if launch_mode != "execute":
            self._transfer_artifact_inputs(run=run, recipe_content=dict(revision.content or {}))
        run.started_at = utc_now()
        terminal_states = {RunState.COMPLETED.value, RunState.BLOCKED.value, RunState.PLANNED.value, RunState.ERRORED.value}
        if run.state in terminal_states:
            run.ended_at = utc_now()

        self._add_run_event(run, "provider_launch", provider_result)

        if self._should_collect_after_provider_launch(run):
            artifacts = self._collect_and_generate(run=run, candidate=candidate, analyst_name=analyst_name)
            self._persist_run_artifacts(run=run, artifacts=artifacts)
            from app.services.malware_lab_service import MalwareLabService

            MalwareLabService(self.session).materialize_run_outputs(tenant, run=run)
        self._ledger(tenant.id, analyst.id, "run_launched", "run", str(run.id), 5.0, {"state": run.state})
        self.session.flush()
        return self.get_run(tenant, run.id)

    def plan_run(
        self,
        tenant: Tenant,
        *,
        recipe_id: int,
        revision_number: Optional[int],
        analyst_name: str,
        workstation: Dict[str, Any],
        launch_mode: str = "dry_run",
        acknowledge_sensitive: bool = False,
        analysis_mode: str = "cve_validation",
        sandbox_profile_id: Optional[int] = None,
        specimen_ids: Optional[List[int]] = None,
        egress_mode: Optional[str] = None,
        ai_assist_enabled: bool = False,
        ai_provider_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist a planned run using provider.build_plan (staged lifecycle, WS4-T3)."""
        launch_mode = normalize_launch_mode(launch_mode)
        recipe = self._get_recipe(tenant, recipe_id)
        revision = self._get_recipe_revision(recipe.id, revision_number or recipe.current_revision_number)
        if revision.approval_state != "approved":
            raise ValueError("Recipe revision must be approved before plan.")
        if revision.requires_acknowledgement and not acknowledge_sensitive:
            raise ValueError("Sensitive recipe revisions require analyst acknowledgement before plan.")
        provider_name = self._enforce_execution_policy(recipe=recipe, revision=revision, launch_mode=launch_mode)
        v3_context = self._resolve_v3_run_context(
            tenant,
            provider_name=provider_name,
            launch_mode=launch_mode,
            analysis_mode=analysis_mode,
            sandbox_profile_id=sandbox_profile_id,
            specimen_ids=specimen_ids,
            egress_mode=egress_mode,
            ai_assist_enabled=ai_assist_enabled,
            ai_provider_hint=ai_provider_hint,
        )
        provider_name = v3_context.get("resolved_provider_name") or provider_name

        analyst = self._ensure_analyst_identity(tenant, analyst_name)
        workstation_record = self._ensure_workstation(tenant, workstation)
        candidate = self._get_candidate(tenant, recipe.candidate_id) if recipe.candidate_id else None

        run = LabRun(
            tenant_id=tenant.id,
            recipe_revision_id=revision.id,
            candidate_id=recipe.candidate_id,
            analyst_id=analyst.id,
            workstation_fingerprint_id=workstation_record.id,
            provider=provider_name,
            launch_mode=launch_mode,
            state=RunState.PLANNED.value,
            requires_acknowledgement=revision.requires_acknowledgement,
            acknowledged_by=analyst_name if acknowledge_sensitive else None,
            acknowledged_at=utc_now() if acknowledge_sensitive else None,
            workspace_path=f"/tmp/sheshnaag/{provider_name}/run-{recipe.id}-{revision.revision_number}",
        )
        self.session.add(run)
        self.session.flush()

        run_context = self._run_context_for_provider(
            tenant, run, analyst_name=analyst_name, candidate=candidate
        )
        provider_revision_content = self._revision_content_for_provider(revision.content or {}, provider_name)
        built_plan = self._provider_for_name(provider_name).build_plan(revision_content=provider_revision_content, run_context=run_context)
        placeholder = ProviderResult(
            state=RunState.PLANNED,
            provider_run_ref="",
            plan=built_plan,
            transcript="Run planned; allocate resources before boot.",
        )
        self._apply_provider_result(run, placeholder)
        run.provider_run_ref = None
        self._annotate_run_manifest(
            run=run,
            revision=revision,
            analyst_name=analyst_name,
            acknowledgement_recorded=acknowledge_sensitive,
        )
        self._persist_v3_run_context(run, v3_context=v3_context)
        self._persist_run_acknowledgement(
            tenant=tenant,
            run=run,
            revision=revision,
            analyst_name=analyst_name,
            acknowledged=acknowledge_sensitive,
        )

        self._add_run_event(run, "run_planned", placeholder)
        self._ledger(tenant.id, analyst.id, "run_planned", "run", str(run.id), 1.0, {"state": run.state})
        self.session.flush()
        return self.get_run(tenant, run.id)

    def allocate_run_resources(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Allocate provider workspace/resources for a planned run."""
        run = self._get_run(tenant, run_id)
        if run.state != RunState.PLANNED.value:
            raise ValueError(f"Run must be in planned state to allocate resources; current={run.state}.")
        if run.provider_run_ref:
            raise ValueError("Run resources already allocated.")
        if not run.manifest:
            raise ValueError("Run is missing a provider plan manifest.")

        candidate = self._get_candidate(tenant, run.candidate_id) if run.candidate_id else None
        run_context = self._run_context_for_provider(
            tenant, run, analyst_name=self._analyst_display_name(run), candidate=candidate
        )
        provider = self._provider_for_name(run.provider)
        result = provider.create(plan=run.manifest, run_context=run_context)
        self._apply_provider_result(run, result)
        revision = (
            self.session.query(RecipeRevision)
            .filter(RecipeRevision.id == run.recipe_revision_id)
            .first()
        )
        if revision is not None:
            self._annotate_run_manifest(
                run=run,
                revision=revision,
                analyst_name=self._analyst_display_name(run),
                acknowledgement_recorded=bool(run.acknowledged_by),
            )
            self._transfer_artifact_inputs(run=run, recipe_content=dict(revision.content or {}))
        self._add_run_event(run, "run_allocated", result)
        self._ledger(tenant.id, run.analyst_id, "run_allocated", "run", str(run.id), 2.0, {"state": run.state})
        self.session.flush()
        return self.get_run(tenant, run.id)

    def boot_run(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Boot the guest for a run after allocate_run_resources."""
        run = self._get_run(tenant, run_id)
        if not run.provider_run_ref:
            raise ValueError("Run has no provider reference; allocate resources first.")
        current = RunState(run.state) if run.state in {s.value for s in RunState} else RunState.ERRORED
        if current != RunState.PLANNED:
            raise ValueError(f"Boot requires planned state after allocation; current={run.state}.")

        provider = self._provider_for_name(run.provider)
        result = provider.boot(provider_run_ref=run.provider_run_ref)
        self._apply_provider_result(run, result)
        self._add_run_event(run, "run_booted", result)
        run.started_at = run.started_at or utc_now()
        terminal_states = {RunState.COMPLETED.value, RunState.BLOCKED.value, RunState.PLANNED.value, RunState.ERRORED.value}
        if run.state in terminal_states:
            run.ended_at = run.ended_at or utc_now()

        candidate = self._get_candidate(tenant, run.candidate_id) if run.candidate_id else None
        analyst_name = self._analyst_display_name(run)
        if self._should_collect_after_provider_launch(run) and not self.session.query(EvidenceArtifact).filter(EvidenceArtifact.run_id == run.id).count():
            artifacts = self._collect_and_generate(run=run, candidate=candidate, analyst_name=analyst_name)
            self._persist_run_artifacts(run=run, artifacts=artifacts)

        if run.analyst_id:
            self._ledger(tenant.id, run.analyst_id, "run_booted", "run", str(run.id), 4.0, {"state": run.state})
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
            "evidence_timeline": self._evidence_timeline_payload(run.id),
            "runtime_findings_summary": self._runtime_findings_summary(run.id),
            "evidence_summary": self._evidence_summary(run.id),
        }

    def list_review_queue(
        self,
        tenant: Tenant,
        *,
        entity_type: Optional[str] = None,
        status: Optional[str] = None,
        run_id: Optional[int] = None,
        reviewer: Optional[str] = None,
        needs_attention: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Aggregate reviewable runs, evidence, artifacts, and bundles into one operator queue."""
        items: List[Dict[str, Any]] = []
        if entity_type in (None, "run"):
            for run in self.session.query(LabRun).filter(LabRun.tenant_id == tenant.id).all():
                manifest = run.manifest or {}
                blocking_reasons: List[str] = []
                readiness = manifest.get("provider_readiness") or {}
                if readiness.get("status") in {"degraded", "unavailable"}:
                    blocking_reasons.append(f"provider_readiness:{readiness.get('status')}")
                if (manifest.get("artifact_transfer") or {}).get("status") == "completed_with_errors":
                    blocking_reasons.append("artifact_transfer_warnings")
                for capability in manifest.get("collector_capabilities") or []:
                    if capability.get("selected") and capability.get("status") in {"degraded", "unavailable"}:
                        blocking_reasons.append(f"collector:{capability.get('collector_name')}:{capability.get('status')}")
                secure_audit = manifest.get("secure_mode_audit") or {}
                execute_result = secure_audit.get("execute_result") or {}
                if manifest.get("provider") == "lima" and run.launch_mode == "execute" and not execute_result:
                    blocking_reasons.append("secure_execute_audit_missing")
                latest_review = self._latest_review_entry("run", run.id)
                items.append(
                    self._review_queue_item(
                        entity_type="run",
                        entity_id=run.id,
                        run_id=run.id,
                        title=f"Run #{run.id}",
                        status=run.state,
                        review_state="needs_attention" if blocking_reasons else "ready",
                        sensitivity={
                            "requires_acknowledgement": bool(run.requires_acknowledgement),
                            "secure_mode": bool(manifest.get("secure_mode")),
                        },
                        blocking_reasons=blocking_reasons,
                        last_review=latest_review,
                        updated_at=run.updated_at or run.created_at,
                        route=f"/runs",
                        extra={
                            "provider": run.provider,
                            "launch_mode": run.launch_mode,
                            "bundle_export_gating": None,
                        },
                    )
                )
        if entity_type in (None, "evidence"):
            evidence_query = self.session.query(EvidenceArtifact).join(LabRun, LabRun.id == EvidenceArtifact.run_id).filter(LabRun.tenant_id == tenant.id)
            if run_id is not None:
                evidence_query = evidence_query.filter(EvidenceArtifact.run_id == run_id)
            for row in evidence_query.all():
                payload = row.payload or {}
                blocking_reasons = []
                if row.reviewed_state in {"captured", "under_review"}:
                    blocking_reasons.append("unreviewed_evidence")
                if row.artifact_kind in {"pcap", "service_logs"}:
                    blocking_reasons.append("sensitive_evidence")
                latest_review = self._latest_review_entry("evidence_artifact", row.id)
                items.append(
                    self._review_queue_item(
                        entity_type="evidence",
                        entity_id=row.id,
                        run_id=row.run_id,
                        title=row.title,
                        status=row.artifact_kind,
                        review_state=row.reviewed_state,
                        sensitivity={
                            "artifact_kind": row.artifact_kind,
                            "sensitive": row.artifact_kind in {"pcap", "service_logs"},
                            "review_sensitivity": payload.get("review_sensitivity") or {},
                        },
                        blocking_reasons=blocking_reasons,
                        last_review=latest_review,
                        updated_at=row.updated_at or row.created_at,
                        route="/evidence",
                        extra={
                            "bundle_export_gating": bool((payload.get("review_sensitivity") or {}).get("external_export_requires_confirmation")),
                        },
                    )
                )
        if entity_type in (None, "artifact"):
            artifacts = [
                *self.session.query(DetectionArtifact).join(LabRun, LabRun.id == DetectionArtifact.run_id).filter(LabRun.tenant_id == tenant.id).all(),
                *self.session.query(MitigationArtifact).join(LabRun, LabRun.id == MitigationArtifact.run_id).filter(LabRun.tenant_id == tenant.id).all(),
            ]
            for row in artifacts:
                row_run_id = row.run_id
                if run_id is not None and row_run_id != run_id:
                    continue
                family = "detection_artifact" if isinstance(row, DetectionArtifact) else "mitigation_artifact"
                latest_review = self._latest_review_entry(family, row.id)
                blocking_reasons = []
                if row.status in {"draft", "under_review", "changes_requested"}:
                    blocking_reasons.append(f"artifact_status:{row.status}")
                items.append(
                    self._review_queue_item(
                        entity_type="artifact",
                        entity_id=row.id,
                        run_id=row_run_id,
                        title=getattr(row, "name", None) or getattr(row, "title", None) or f"Artifact {row.id}",
                        status=row.status,
                        review_state=row.status,
                        sensitivity={"artifact_type": row.artifact_type},
                        blocking_reasons=blocking_reasons,
                        last_review=latest_review,
                        updated_at=row.updated_at or row.created_at,
                        route="/artifacts",
                        extra={
                            "artifact_family": "detection" if isinstance(row, DetectionArtifact) else "mitigation",
                            "bundle_export_gating": None,
                        },
                    )
                )
        if entity_type in (None, "bundle"):
            bundle_query = self.session.query(DisclosureBundle).filter(DisclosureBundle.tenant_id == tenant.id)
            if run_id is not None:
                bundle_query = bundle_query.filter(DisclosureBundle.run_id == run_id)
            for bundle in bundle_query.all():
                manifest = bundle.manifest or {}
                gating = (manifest.get("safety_checklist") or {}).get("requires_external_confirmation") or False
                blocking_reasons = []
                if gating and bundle.status not in {"approved", "exported"}:
                    blocking_reasons.append("external_export_confirmation_required")
                if manifest.get("warnings"):
                    blocking_reasons.append("bundle_warnings_present")
                latest_review = self._latest_review_entry("disclosure_bundle", bundle.id)
                items.append(
                    self._review_queue_item(
                        entity_type="bundle",
                        entity_id=bundle.id,
                        run_id=bundle.run_id,
                        title=bundle.title,
                        status=bundle.status,
                        review_state=bundle.status,
                        sensitivity={"bundle_type": bundle.bundle_type, "contains_sensitive_evidence": gating},
                        blocking_reasons=blocking_reasons,
                        last_review=latest_review,
                        updated_at=bundle.created_at,
                        route="/disclosures",
                        extra={"bundle_export_gating": gating},
                    )
                )

        from app.services.malware_lab_service import MalwareLabService

        items.extend(
            [
                item
                for item in MalwareLabService(self.session).review_queue_items(tenant)
                if entity_type is None or entity_type == item["entity_type"]
            ]
        )

        if run_id is not None:
            items = [item for item in items if item["run_id"] == run_id]
        if status:
            items = [item for item in items if item["status"] == status or item["review_state"] == status]
        if reviewer:
            items = [item for item in items if item.get("last_reviewer") == reviewer]
        if needs_attention is not None:
            items = [item for item in items if bool(item["needs_attention_now"]) is needs_attention]
        items.sort(key=lambda item: (item["needs_attention_now"], item["updated_at"] or ""), reverse=True)
        return {"count": len(items), "items": items}

    def stop_run(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Stop a running validation run."""
        run = self._get_run(tenant, run_id)
        self._assert_transition(run, RunState.STOPPING)
        provider = self._provider_for_name(run.provider)
        result = provider.stop(provider_run_ref=run.provider_run_ref)
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
        provider = self._provider_for_name(run.provider)
        result = provider.teardown(provider_run_ref=run.provider_run_ref, retain_workspace=retain)
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
            provider = self._provider_for_name(run.provider)
            result = provider.destroy(provider_run_ref=run.provider_run_ref)
            self._apply_provider_result(run, result)
            run.ended_at = run.ended_at or utc_now()
            self._add_run_event(run, "run_destroyed", result)
        self.session.flush()
        return self.get_run(tenant, run.id)

    def run_health(self, tenant: Tenant, *, run_id: int) -> Dict[str, Any]:
        """Check the health of a running validation run."""
        run = self._get_run(tenant, run_id)
        provider = self._provider_for_name(run.provider)
        result = provider.health(provider_run_ref=run.provider_run_ref)
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
            "evidence_summary": self._evidence_summary(run.id),
        }

    def _runtime_findings_summary(self, run_id: int) -> Dict[str, Any]:
        """Aggregate ``findings`` from telemetry collector payloads (WS7-T5 operator view)."""
        rows = self.session.query(EvidenceArtifact).filter(EvidenceArtifact.run_id == run_id).all()
        items: List[Dict[str, Any]] = []
        per_tool_counts: Dict[str, int] = {}
        per_severity_counts: Dict[str, int] = {}
        collector_overhead: List[Dict[str, Any]] = []
        telemetry_slices: List[Dict[str, Any]] = []
        for row in rows:
            pl = row.payload or {}
            if not isinstance(pl, dict):
                continue
            summary = pl.get("telemetry_summary")
            if isinstance(summary, dict):
                for tool, count in (summary.get("source_tools") or {}).items():
                    per_tool_counts[str(tool)] = per_tool_counts.get(str(tool), 0) + int(count)
                for sev, count in (summary.get("severity_counts") or {}).items():
                    per_severity_counts[str(sev)] = per_severity_counts.get(str(sev), 0) + int(count)
            if isinstance(pl.get("collector_overhead"), dict):
                collector_overhead.append(
                    {
                        "collector_name": row.collector_name or row.artifact_kind,
                        **pl["collector_overhead"],
                    }
                )
            if any(key in pl for key in ("process_slice", "file_slice", "network_slice")):
                telemetry_slices.append(
                    {
                        "evidence_artifact_id": row.id,
                        "collector_name": row.collector_name or row.artifact_kind,
                        "process_slice": pl.get("process_slice") or [],
                        "file_slice": pl.get("file_slice") or [],
                        "network_slice": pl.get("network_slice") or [],
                        "policy_hits": pl.get("policy_hits") or [],
                    }
                )
            findings = pl.get("findings")
            if not isinstance(findings, list):
                continue
            for f in findings:
                if isinstance(f, dict):
                    items.append(
                        {
                            **f,
                            "evidence_artifact_id": row.id,
                            "artifact_kind": row.artifact_kind,
                        }
                    )
        top_findings = sorted(
            items,
            key=lambda finding: {"critical": 4, "high": 3, "medium": 2, "warning": 2, "notice": 1, "low": 1, "info": 0}.get(
                str(finding.get("severity") or "info").lower(),
                0,
            ),
            reverse=True,
        )
        return {
            "count": len(items),
            "items": items[:500],
            "per_tool_counts": per_tool_counts,
            "per_severity_counts": per_severity_counts,
            "top_findings": top_findings[:20],
            "collector_overhead": collector_overhead,
            "telemetry_slices": telemetry_slices[:50],
        }

    def _evidence_summary(self, run_id: int) -> Dict[str, Any]:
        rows = self.session.query(EvidenceArtifact).filter(EvidenceArtifact.run_id == run_id).all()
        by_kind: Dict[str, int] = {}
        by_collector: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            by_kind[row.artifact_kind] = by_kind.get(row.artifact_kind, 0) + 1
            collector_key = row.collector_name or row.artifact_kind
            payload = row.payload or {}
            health = payload.get("collector_health") if isinstance(payload, dict) else {}
            entry = by_collector.setdefault(
                collector_key,
                {
                    "collector_name": collector_key,
                    "status": "unknown",
                    "count": 0,
                    "latest_title": row.title,
                },
            )
            entry["count"] += 1
            entry["latest_title"] = row.title
            if isinstance(health, dict) and health.get("status"):
                status = str(health["status"]).strip().lower()
                entry["status"] = "live" if status == "ok" else status
        return {
            "count": len(rows),
            "by_kind": by_kind,
            "collectors": list(by_collector.values()),
        }

    def _evidence_timeline_payload(self, run_id: int) -> Dict[str, Any]:
        rows = (
            self.session.query(EvidenceArtifact)
            .filter(EvidenceArtifact.run_id == run_id)
            .order_by(EvidenceArtifact.created_at.asc())
            .all()
        )
        def _ev_ts(row: EvidenceArtifact) -> float:
            t = row.capture_started_at or row.created_at
            return t.timestamp() if t else 0.0

        rows.sort(key=lambda r: (_ev_ts(r), r.id))
        items: List[Dict[str, Any]] = []
        for row in rows:
            ts = row.capture_started_at or row.created_at
            items.append(
                {
                    "evidence_id": row.id,
                    "artifact_kind": row.artifact_kind,
                    "stage": "collection",
                    "timestamp": ts.isoformat() if ts else None,
                    "collector_name": row.collector_name,
                    "collector_version": row.collector_version,
                    "truncated": row.truncated,
                    "title": row.title,
                }
            )
        return {"items": items, "ordered_by": "capture_started_at_then_created_at"}

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
                    "storage_path": item.storage_path,
                    "content_type": item.content_type,
                    "byte_size": item.byte_size,
                    "capture_started_at": item.capture_started_at.isoformat() if item.capture_started_at else None,
                    "capture_ended_at": item.capture_ended_at.isoformat() if item.capture_ended_at else None,
                    "collector_name": item.collector_name,
                    "collector_version": item.collector_version,
                    "truncated": item.truncated,
                    "lineage_links": (item.payload or {}).get("lineage_links") or [],
                    "safe_render_metadata": (item.payload or {}).get("safe_render_metadata") or {},
                    "collector_status": (item.payload or {}).get("collector_status") or "completed",
                    "degradation_reasons": (item.payload or {}).get("degradation_reasons") or [],
                    "confidence": (item.payload or {}).get("confidence"),
                    "coverage": (item.payload or {}).get("coverage"),
                    "payload": item.payload,
                }
                for item in rows
            ],
        }

    def list_artifacts(self, tenant: Tenant, *, run_id: Optional[int] = None) -> Dict[str, Any]:
        """List generated defensive artifacts."""
        from app.services.malware_lab_service import MalwareLabService

        detection_query = self.session.query(DetectionArtifact).join(LabRun, LabRun.id == DetectionArtifact.run_id).filter(LabRun.tenant_id == tenant.id)
        mitigation_query = self.session.query(MitigationArtifact).join(LabRun, LabRun.id == MitigationArtifact.run_id).filter(LabRun.tenant_id == tenant.id)
        if run_id is not None:
            detection_query = detection_query.filter(DetectionArtifact.run_id == run_id)
            mitigation_query = mitigation_query.filter(MitigationArtifact.run_id == run_id)
        detections = detection_query.order_by(desc(DetectionArtifact.created_at)).all()
        mitigations = mitigation_query.order_by(desc(MitigationArtifact.created_at)).all()
        malware = MalwareLabService(self.session)
        indicators = malware.list_indicators(tenant)["items"]
        prevention = malware.list_prevention_artifacts(tenant)["items"]
        defang = malware.list_defang_actions(tenant)["items"]
        return {
            "detections": [self._detection_artifact_payload(item) for item in detections],
            "mitigations": [self._mitigation_artifact_payload(item) for item in mitigations],
            "indicators": indicators,
            "prevention": prevention,
            "defang": defang,
            "summary": {
                "detection_count": len(detections),
                "mitigation_count": len(mitigations),
                "indicator_count": len(indicators),
                "prevention_count": len(prevention),
                "defang_count": len(defang),
                "approved_count": sum(1 for item in [*detections, *mitigations] if item.status == "approved"),
                "under_review_count": sum(1 for item in [*detections, *mitigations] if item.status == "under_review"),
            },
        }

    def review_artifact(
        self,
        tenant: Tenant,
        *,
        artifact_family: str,
        artifact_id: int,
        decision: str,
        reviewer: str,
        rationale: Optional[str] = None,
        correction_note: Optional[str] = None,
        supersedes_artifact_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Advance an artifact through the review state machine."""
        artifact = self._get_artifact_entity(tenant, artifact_family, artifact_id)
        valid_states = {"draft", "under_review", "changes_requested", "approved", "rejected", "superseded", "deprecated"}
        if decision not in valid_states:
            raise ValueError(f"Invalid artifact review state '{decision}'.")
        artifact.status = decision
        self.session.add(
            ReviewDecision(
                tenant_id=tenant.id,
                reviewer_name=reviewer,
                target_type=f"{artifact_family}_artifact",
                target_id=str(artifact.id),
                decision=decision,
                rationale=rationale,
                payload={
                    "run_id": artifact.run_id,
                    "artifact_family": artifact_family,
                    "correction_note": correction_note,
                    "supersedes_artifact_id": supersedes_artifact_id,
                },
            )
        )
        analyst_id = self._run_analyst_id(artifact.run_id)
        self._ledger(
            tenant.id,
            analyst_id,
            f"{artifact_family}_artifact_{decision}",
            f"{artifact_family}_artifact",
            str(artifact.id),
            1.5 if decision == "approved" else 0.5,
            {"reviewer": reviewer, "run_id": artifact.run_id},
        )
        self.session.flush()
        return (
            self._detection_artifact_payload(artifact)
            if artifact_family == "detection"
            else self._mitigation_artifact_payload(artifact)
        )

    def add_artifact_feedback(
        self,
        tenant: Tenant,
        *,
        artifact_family: str,
        artifact_id: int,
        reviewer: str,
        feedback_type: str,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist explicit artifact feedback for future review and tuning."""
        artifact = self._get_artifact_entity(tenant, artifact_family, artifact_id)
        self.session.add(
            ReviewDecision(
                tenant_id=tenant.id,
                reviewer_name=reviewer,
                target_type=f"{artifact_family}_artifact",
                target_id=str(artifact.id),
                decision="feedback",
                rationale=note,
                payload={
                    "feedback_type": feedback_type,
                    "run_id": artifact.run_id,
                    "artifact_family": artifact_family,
                },
            )
        )
        self.session.flush()
        return (
            self._detection_artifact_payload(artifact)
            if artifact_family == "detection"
            else self._mitigation_artifact_payload(artifact)
        )

    def get_provenance(self, tenant: Tenant, *, run_id: Optional[int] = None) -> Dict[str, Any]:
        """Return run- and bundle-linked attestation data."""
        query = self.session.query(AttestationRecord).filter(AttestationRecord.tenant_id == tenant.id)
        if run_id is not None:
            query = query.filter(AttestationRecord.run_id == run_id)
        rows = query.order_by(desc(AttestationRecord.created_at)).all()
        response = {
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
                    "signing": (row.payload or {}).get("signing") if isinstance(row.payload, dict) else {},
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ],
        }
        if run_id is not None:
            run = self._get_run(tenant, run_id)
            evidence_rows = (
                self.session.query(EvidenceArtifact)
                .filter(EvidenceArtifact.run_id == run_id)
                .order_by(EvidenceArtifact.created_at.asc())
                .all()
            )
            detection_rows = self.session.query(DetectionArtifact).filter(DetectionArtifact.run_id == run_id).all()
            mitigation_rows = self.session.query(MitigationArtifact).filter(MitigationArtifact.run_id == run_id).all()
            bundle_rows = self.session.query(DisclosureBundle).filter(DisclosureBundle.run_id == run_id).all()
            review_rows = (
                self.session.query(ReviewDecision)
                .filter(ReviewDecision.tenant_id == tenant.id)
                .order_by(ReviewDecision.created_at.desc())
                .all()
            )
            revision = self.session.query(RecipeRevision).filter(RecipeRevision.id == run.recipe_revision_id).first()
            analyst = self.session.query(AnalystIdentity).filter(AnalystIdentity.id == run.analyst_id).first()
            workstation = self.session.query(WorkstationFingerprint).filter(
                WorkstationFingerprint.id == run.workstation_fingerprint_id
            ).first()
            response.update(
                {
                    "run": self.get_run(tenant, run_id),
                    "manifest_summary": {
                        "recipe_revision_id": run.recipe_revision_id,
                        "recipe_revision_digest": revision.signed_digest if revision else None,
                        "analyst": analyst.name if analyst else None,
                        "workstation_fingerprint": workstation.fingerprint if workstation else None,
                        "acknowledgement": (run.manifest or {}).get("acknowledgement"),
                        "artifact_transfer": (run.manifest or {}).get("artifact_transfer"),
                        "provider_contract": (run.manifest or {}).get("provider_contract"),
                        "trusted_image": (run.manifest or {}).get("image_catalog"),
                        "signing_backends": sorted(
                            {
                                (item.payload or {}).get("signing", {}).get("backend")
                                for item in rows
                                if isinstance(item.payload, dict)
                            }
                            - {None}
                        ),
                        "signing_fingerprints": sorted(
                            {
                                (item.payload or {}).get("signing", {}).get("fingerprint")
                                for item in rows
                                if isinstance(item.payload, dict)
                            }
                            - {None}
                        ),
                    },
                    "evidence_linkage": [
                        {
                            "id": row.id,
                            "artifact_kind": row.artifact_kind,
                            "sha256": row.sha256,
                            "collector_name": row.collector_name,
                            "storage_path": row.storage_path,
                            "capture_started_at": row.capture_started_at.isoformat() if row.capture_started_at else None,
                        }
                        for row in evidence_rows
                    ],
                    "artifact_linkage": {
                        "detections": [self._detection_artifact_payload(row) for row in detection_rows],
                        "mitigations": [self._mitigation_artifact_payload(row) for row in mitigation_rows],
                    },
                    "review_history": [
                        {
                            "id": row.id,
                            "target_type": row.target_type,
                            "target_id": row.target_id,
                            "decision": row.decision,
                            "reviewer_name": row.reviewer_name,
                            "rationale": row.rationale,
                            "payload": row.payload,
                            "created_at": row.created_at.isoformat() if row.created_at else None,
                        }
                        for row in review_rows
                        if (row.payload or {}).get("run_id") == run_id
                    ],
                    "export_history": [self._disclosure_bundle_payload(row) for row in bundle_rows],
                }
            )
        return response

    def get_ledger(self, tenant: Tenant) -> Dict[str, Any]:
        """Return analyst contribution ledger."""
        rows = self.session.query(ContributionLedgerEntry).filter(ContributionLedgerEntry.tenant_id == tenant.id).order_by(desc(ContributionLedgerEntry.created_at)).all()
        analyst_ids = {row.analyst_id for row in rows if row.analyst_id}
        analysts = {
            row.id: row.name
            for row in self.session.query(AnalystIdentity).filter(AnalystIdentity.id.in_(analyst_ids)).all()
        } if analyst_ids else {}
        by_analyst: Dict[str, float] = {}
        for row in rows:
            name = analysts.get(row.analyst_id, "system")
            by_analyst[name] = by_analyst.get(name, 0.0) + float(row.score or 0.0)
        return {
            "count": len(rows),
            "items": [
                {
                    "id": row.id,
                    "analyst_id": row.analyst_id,
                    "analyst_name": analysts.get(row.analyst_id),
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
            "summary": {
                "total_score": round(sum(float(row.score or 0.0) for row in rows), 2),
                "by_analyst": [{"name": name, "score": round(score, 2)} for name, score in sorted(by_analyst.items())],
            },
        }

    def create_disclosure_bundle(
        self,
        tenant: Tenant,
        *,
        run_id: int,
        bundle_type: str,
        title: str,
        signed_by: str,
        evidence_ids: Optional[List[int]] = None,
        redaction_notes: Optional[List[Dict[str, Any]]] = None,
        attachment_policy: Optional[Dict[str, Any]] = None,
        review_checklist: Optional[Dict[str, Any]] = None,
        reviewer_name: Optional[str] = None,
        reviewer_role: Optional[str] = None,
        confirm_external_export: bool = False,
    ) -> Dict[str, Any]:
        """Create a disclosure/export bundle from a run."""
        run = self._get_run(tenant, run_id)
        evidence_rows = (
            self.session.query(EvidenceArtifact)
            .filter(EvidenceArtifact.run_id == run.id)
            .order_by(EvidenceArtifact.created_at.asc())
            .all()
        )
        if evidence_ids:
            evidence_rows = [row for row in evidence_rows if row.id in set(evidence_ids)]
        detection_rows = self.session.query(DetectionArtifact).filter(DetectionArtifact.run_id == run.id).all()
        mitigation_rows = self.session.query(MitigationArtifact).filter(MitigationArtifact.run_id == run.id).all()
        approved_artifacts = [row for row in [*detection_rows, *mitigation_rows] if row.status == "approved"]
        selected_artifacts = approved_artifacts or [*detection_rows, *mitigation_rows]

        warnings: List[str] = []
        if any(row.artifact_kind == "pcap" for row in evidence_rows):
            warnings.append("Bundle includes PCAP-derived evidence; review raw packet data before external sharing.")
        if any(row.artifact_kind == "service_logs" for row in evidence_rows):
            warnings.append("Bundle includes service log excerpts; verify secrets and tenant identifiers are redacted.")
        if warnings and not confirm_external_export:
            raise ValueError("Bundle requires explicit external export confirmation for sensitive evidence.")

        manifest = self._build_bundle_manifest(
            run=run,
            bundle_type=bundle_type,
            title=title,
            signed_by=signed_by,
            evidence_rows=evidence_rows,
            artifacts=selected_artifacts,
            redaction_notes=redaction_notes or [],
            attachment_policy=attachment_policy or {},
            warnings=warnings,
            review_checklist=review_checklist or {},
        )
        archive = self._write_bundle_archive(
            manifest=manifest,
            evidence_rows=evidence_rows,
            detection_rows=[row for row in selected_artifacts if isinstance(row, DetectionArtifact)],
            mitigation_rows=[row for row in selected_artifacts if isinstance(row, MitigationArtifact)],
        )
        manifest["archive"] = archive
        signer = self._attestation_signer_for_tenant(tenant)
        signed = signer.sign(payload=manifest, signer=signed_by)
        manifest["signing"] = {
            "backend": signed.get("backend"),
            "algorithm": signed.get("algorithm"),
            "fingerprint": signed.get("fingerprint"),
            "public_key": signed.get("public_key"),
            "verification_status": "verified",
        }
        bundle = DisclosureBundle(
            tenant_id=tenant.id,
            run_id=run.id,
            bundle_type=bundle_type,
            title=title,
            status="exported",
            manifest=manifest,
            sha256=archive["sha256"],
            signed_by=signed_by,
        )
        self.session.add(bundle)
        self.session.flush()
        review_actor = reviewer_name or signed_by
        self.session.add(
            ReviewDecision(
                tenant_id=tenant.id,
                reviewer_name=review_actor,
                target_type="disclosure_bundle",
                target_id=str(bundle.id),
                decision="approved" if confirm_external_export else "under_review",
                rationale="Bundle exported with explicit external confirmation." if confirm_external_export else "Bundle assembled and awaiting operator confirmation.",
                payload={
                    "run_id": run.id,
                    "bundle_id": bundle.id,
                    "bundle_type": bundle_type,
                    "reviewer_role": reviewer_role or "analyst",
                    "checklist": review_checklist or {},
                    "redaction_note_count": len(redaction_notes or []),
                    "attachment_policy": attachment_policy or {},
                    "export_gating": {
                        "confirm_external_export": confirm_external_export,
                        "warnings": warnings,
                    },
                },
            )
        )
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
                payload={
                    **manifest,
                    "signing": {
                        "backend": signed.get("backend"),
                        "algorithm": signed.get("algorithm"),
                        "fingerprint": signed.get("fingerprint"),
                        "public_key": signed.get("public_key"),
                        "verification_status": "verified",
                    },
                },
            )
        )
        self._ledger(
            tenant.id,
            run.analyst_id,
            "bundle_exported",
            "disclosure_bundle",
            str(bundle.id),
            3.0,
            {"bundle_type": bundle_type, "archive_sha256": archive["sha256"]},
        )
        self.session.flush()
        return self._disclosure_bundle_payload(bundle)

    def review_disclosure_bundle(
        self,
        tenant: Tenant,
        *,
        bundle_id: int,
        reviewer_name: str,
        reviewer_role: str,
        decision: str,
        rationale: Optional[str] = None,
        checklist: Optional[Dict[str, Any]] = None,
        export_gating: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        valid_states = {"draft", "under_review", "changes_requested", "approved", "rejected", "superseded", "exported"}
        if decision not in valid_states:
            raise ValueError(f"Invalid disclosure bundle decision '{decision}'.")
        bundle = (
            self.session.query(DisclosureBundle)
            .filter(DisclosureBundle.tenant_id == tenant.id, DisclosureBundle.id == bundle_id)
            .first()
        )
        if bundle is None:
            raise ValueError("Disclosure bundle not found.")
        bundle.status = decision
        self.session.add(
            ReviewDecision(
                tenant_id=tenant.id,
                reviewer_name=reviewer_name,
                target_type="disclosure_bundle",
                target_id=str(bundle.id),
                decision=decision,
                rationale=rationale,
                payload={
                    "bundle_id": bundle.id,
                    "run_id": bundle.run_id,
                    "reviewer_role": reviewer_role,
                    "checklist": checklist or {},
                    "export_gating": export_gating or {},
                },
            )
        )
        self._ledger(
            tenant.id,
            self._run_analyst_id(bundle.run_id) if bundle.run_id else None,
            f"bundle_{decision}",
            "disclosure_bundle",
            str(bundle.id),
            1.25 if decision in {"approved", "exported"} else 0.75,
            {"reviewer": reviewer_name, "reviewer_role": reviewer_role},
        )
        self.session.flush()
        return self._disclosure_bundle_payload(bundle)

    def list_disclosure_bundles(self, tenant: Tenant) -> Dict[str, Any]:
        """List disclosure bundles."""
        rows = self.session.query(DisclosureBundle).filter(DisclosureBundle.tenant_id == tenant.id).order_by(desc(DisclosureBundle.created_at)).all()
        return {
            "count": len(rows),
            "items": [self._disclosure_bundle_payload(row) for row in rows],
        }

    def get_disclosure_bundle_archive(self, tenant: Tenant, *, bundle_id: int) -> Dict[str, str]:
        """Return archive location details for a previously exported bundle.

        Path-containment hardening: the manifest stores the on-disk archive
        path, but a tampered manifest (or stale row written by an earlier
        version with weaker validation) could point at an arbitrary file. We
        therefore require the resolved real path to live under
        ``self.export_root`` and to be a regular file. Any deviation surfaces
        as a 404-equivalent ValueError rather than streaming the file.
        """
        bundle = (
            self.session.query(DisclosureBundle)
            .filter(DisclosureBundle.tenant_id == tenant.id, DisclosureBundle.id == bundle_id)
            .first()
        )
        if bundle is None:
            raise ValueError("Disclosure bundle not found.")
        archive = (bundle.manifest or {}).get("archive") or {}
        path = archive.get("path")
        if not path:
            raise ValueError("Disclosure bundle archive is missing.")

        try:
            root_real = Path(self.export_root).resolve(strict=False)
            archive_real = Path(path).resolve(strict=False)
            archive_real.relative_to(root_real)
        except (OSError, ValueError) as exc:
            raise ValueError("Disclosure bundle archive path is not permitted.") from exc

        if not archive_real.is_file():
            raise ValueError("Disclosure bundle archive is missing.")

        return {
            "path": str(archive_real),
            "filename": archive.get("filename") or archive_real.name,
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
        advisory_rows = self.session.query(AdvisoryRecord).filter(AdvisoryRecord.cve_id == cve.id).all()
        advisory_summary = summarize_advisory_records(advisory_rows)
        patch_available = bool(applicability.get("patch_available") or cve.exploit_available)
        asset_matches = int(applicability["asset_match_count"]) + int(applicability["sbom_match_count"])
        risk_val = float(risk.overall_score / 100.0) if risk and risk.overall_score is not None else 0.35
        epss_val = float(epss.score) if epss else 0.0
        kev_val = bool(kev)
        attack_surface = 0.9 if cve.attack_vector == "NETWORK" else (0.7 if cve.attack_vector == "ADJACENT" else 0.4)
        observability = 0.9 if asset_matches > 0 and cve.attack_vector == "NETWORK" else (0.72 if asset_matches > 0 else 0.55)
        reproducibility = max(0.35, float(applicability.get("confidence") or 0.1))
        patch_factor = 0.35 if patch_available else 0.85
        exploit_maturity = min(1.0, (0.45 if kev_val else 0.0) + (epss_val * 0.45) + (0.1 if cve.exploit_available else 0.0))
        vendor_context_quality = min(
            1.0,
            (
                min(0.6, float(advisory_summary.get("count") or 0) * 0.2)
                + (0.2 if advisory_summary.get("advisories_by_type", {}).get("patch_note") else 0.0)
                + (0.2 if advisory_summary.get("advisories_by_type", {}).get("vendor") else 0.0)
            ),
        )
        citations = self._build_citations(cve=cve, tenant=tenant, kev=kev, epss=epss, affected=affected)
        return compute_candidate_explainability(
            CandidateScoringContext(
                risk_val=risk_val,
                epss_val=epss_val,
                kev=kev_val,
                package_match_confidence=min(1.0, asset_matches / 3.0),
                affected_version_confidence=float(applicability.get("version_match_confidence") or 0.25),
                sbom_vex_applicability=float(applicability.get("sbom_vex_applicability") or 0.2),
                attack_surface=attack_surface,
                observability=observability,
                linux_reproducibility=reproducibility,
                patch_availability_factor=patch_factor,
                exploit_maturity=exploit_maturity,
                advisory_normalization_confidence=float(advisory_summary.get("normalization_confidence") or 0.5),
                source_agreement=float(advisory_summary.get("source_agreement") or 0.6),
                vendor_context_quality=vendor_context_quality,
                source_freshness=self._source_freshness_score(["nvd", "kev", "epss", "osv", "ghsa", "vendor_advisory", "patch_notes"]),
                evidence_readiness=self._evidence_readiness_score(),
                applicability={
                    **applicability,
                    "patch_available": patch_available,
                },
                advisory_summary=advisory_summary,
                citations=citations,
            )
        )

    def _source_freshness_score(self, feed_keys: List[str]) -> float:
        now = utc_now().replace(tzinfo=None)
        relevant = self.session.query(SourceFeed).filter(SourceFeed.feed_key.in_(feed_keys)).all()
        if not relevant:
            return 0.5
        fresh = 0
        for feed in relevant:
            threshold = int(feed.freshness_seconds or 21600)
            if feed.last_synced_at is None:
                continue
            synced = feed.last_synced_at.replace(tzinfo=None) if feed.last_synced_at.tzinfo else feed.last_synced_at
            if (now - synced).total_seconds() <= threshold:
                fresh += 1
        return round(fresh / max(1, len(relevant)), 3)

    def _evidence_readiness_score(self) -> float:
        plan = self.provider.build_plan(
            revision_content={"base_image": DEFAULT_KALI_IMAGE, "collectors": list(DEFAULT_RECIPE_COLLECTORS)},
            run_context={"tenant_slug": "workspace", "analyst_name": "system", "run_id": 0},
        )
        status = ((plan.get("provider_readiness") or {}).get("status") or "degraded").lower()
        return {"ready": 1.0, "degraded": 0.65, "unavailable": 0.2}.get(status, 0.5)

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
            .limit(8)
            .all()
        )
        for adv in advisories:
            citations.append(
                {
                    "type": f"advisory_{adv.advisory_type or 'generic'}",
                    "label": adv.title,
                    "url": adv.source_url,
                    "detail": adv.summary,
                    "canonical_id": adv.canonical_id,
                    "severity": adv.severity,
                    "normalization_confidence": adv.normalization_confidence,
                }
            )

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

        raw_sources = (
            self.session.query(RawKnowledgeSource)
            .filter(RawKnowledgeSource.cve_id == cve.id)
            .order_by(desc(RawKnowledgeSource.collected_at), desc(RawKnowledgeSource.id))
            .limit(5)
            .all()
        )
        for source in raw_sources:
            citations.append(
                {
                    "type": f"raw_{source.source_kind}",
                    "label": source.source_label or source.source_kind,
                    "url": source.source_url,
                    "detail": f"Raw source sha256 {source.sha256[:12]}...",
                }
            )

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

        package_links = (
            self.session.query(AdvisoryPackageLink, PackageRecord)
            .join(PackageRecord, PackageRecord.id == AdvisoryPackageLink.package_record_id)
            .join(AdvisoryRecord, AdvisoryRecord.id == AdvisoryPackageLink.advisory_record_id)
            .filter(AdvisoryRecord.cve_id == cve.id)
            .limit(5)
            .all()
        )
        for link, pkg in package_links:
            citations.append(
                {
                    "type": "package_normalization",
                    "label": f"{pkg.ecosystem}:{pkg.name}",
                    "url": None,
                    "detail": f"Canonical package mapping via {link.meta.get('source') if isinstance(link.meta, dict) else 'advisory normalization'}",
                    "purl": link.purl or pkg.purl,
                }
            )

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

    def _artifact_inputs(self, recipe_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw = recipe_content.get("artifact_inputs", recipe_content.get("input_artifacts")) or []
        if not isinstance(raw, list):
            return []
        items: List[Dict[str, Any]] = []
        for artifact in raw:
            if not isinstance(artifact, dict):
                continue
            source_path = artifact.get("source_path")
            if not isinstance(source_path, str) or not source_path:
                continue
            name = artifact.get("name")
            if not isinstance(name, str) or not name.strip():
                name = os.path.basename(source_path)
            item = dict(artifact)
            item["source_path"] = source_path
            item["name"] = name
            items.append(item)
        return items

    def _acknowledgement_details(
        self,
        *,
        revision: RecipeRevision,
        analyst_name: str,
        include_actor: bool,
    ) -> Optional[Dict[str, Any]]:
        if not revision.requires_acknowledgement:
            return None

        from app.lab.recipe_schema import SignOffPolicy

        content = dict(revision.content or {})
        requirement = SignOffPolicy().evaluate(
            risk_level=str(content.get("risk_level", revision.risk_level or "standard")),
            capabilities=content.get("cap_add") if isinstance(content.get("cap_add"), list) else [],
        )
        acknowledgement_text = requirement.acknowledgement_text
        text_sha256 = hashlib.sha256(acknowledgement_text.encode("utf-8")).hexdigest()
        details: Dict[str, Any] = {
            "risk_level": revision.risk_level,
            "required": True,
            "required_approvals": requirement.required_approvals,
            "restricted_capabilities": requirement.restricted_caps_present,
            "eligible_roles": requirement.eligible_roles,
            "text": acknowledgement_text,
            "text_sha256": text_sha256,
        }
        if include_actor:
            details.update(
                {
                    "acknowledged_by": analyst_name,
                    "acknowledged_at": utc_now().isoformat(),
                }
            )
        return details

    def _annotate_run_manifest(
        self,
        *,
        run: LabRun,
        revision: RecipeRevision,
        analyst_name: str,
        acknowledgement_recorded: bool,
    ) -> None:
        manifest = dict(run.manifest or {})
        artifact_inputs = self._artifact_inputs(dict(revision.content or {}))
        if artifact_inputs:
            manifest["artifact_inputs"] = [
                {
                    "name": item.get("name"),
                    "source_path": item.get("source_path"),
                    "sha256": item.get("sha256") or item.get("expected_sha256"),
                    "destination": item.get("destination"),
                }
                for item in artifact_inputs
            ]
            manifest.setdefault(
                "artifact_transfer",
                {
                    "status": "pending",
                    "requested_count": len(artifact_inputs),
                    "transfers": [],
                },
            )
        acknowledgement = self._acknowledgement_details(
            revision=revision,
            analyst_name=analyst_name,
            include_actor=acknowledgement_recorded,
        )
        manifest.setdefault("provider_contract", {})
        manifest["provider_contract"].update(
            {
                "provider": run.provider,
                "launch_mode": run.launch_mode,
                "recipe_revision_id": run.recipe_revision_id,
                "trusted_image": manifest.get("image_catalog") or {},
                "execution_policy": (revision.content or {}).get("execution_policy") or {},
                "workspace_sync": manifest.get("workspace_sync") or {},
                "snapshot_policy": manifest.get("snapshot_policy") or {},
            }
        )
        if acknowledgement:
            manifest["acknowledgement"] = acknowledgement
        run.manifest = manifest

    def _persist_run_acknowledgement(
        self,
        *,
        tenant: Tenant,
        run: LabRun,
        revision: RecipeRevision,
        analyst_name: str,
        acknowledged: bool,
    ) -> None:
        if not acknowledged:
            return
        details = self._acknowledgement_details(
            revision=revision,
            analyst_name=analyst_name,
            include_actor=True,
        )
        if not details:
            return
        existing = (
            self.session.query(ReviewDecision)
            .filter(
                ReviewDecision.tenant_id == tenant.id,
                ReviewDecision.target_type == "run_acknowledgement",
                ReviewDecision.target_id == str(run.id),
            )
            .first()
        )
        if existing is not None:
            return
        self.session.add(
            ReviewDecision(
                tenant_id=tenant.id,
                reviewer_name=analyst_name,
                target_type="run_acknowledgement",
                target_id=str(run.id),
                decision="acknowledged",
                rationale=details["text"],
                payload={
                    "run_id": run.id,
                    "recipe_revision_id": run.recipe_revision_id,
                    "risk_level": details["risk_level"],
                    "acknowledgement_text_sha256": details["text_sha256"],
                    "acknowledged_at": details.get("acknowledged_at"),
                },
            )
        )

    def _transfer_artifact_inputs(
        self,
        *,
        run: LabRun,
        recipe_content: Dict[str, Any],
    ) -> None:
        artifact_inputs = self._artifact_inputs(recipe_content)
        if not artifact_inputs:
            return

        manifest = dict(run.manifest or {})
        transfer_state = manifest.get("artifact_transfer") if isinstance(manifest.get("artifact_transfer"), dict) else {}
        if transfer_state.get("status") == "completed":
            return

        workspace_path = (manifest.get("host_workspace") or run.workspace_path or "").strip()
        if not workspace_path:
            transfer_state = {
                **transfer_state,
                "status": "pending_workspace",
                "requested_count": len(artifact_inputs),
                "transfers": [],
            }
            manifest["artifact_transfer"] = transfer_state
            run.manifest = manifest
            return

        provider = self._provider_for_name(run.provider)
        transfer_result = provider.transfer_artifacts(
            provider_run_ref=run.provider_run_ref or f"run-{run.id}",
            artifacts=artifact_inputs,
            workspace_path=workspace_path,
        )
        transfers = transfer_result.get("transfers", [])
        has_errors = any(item.get("status") != "transferred" for item in transfers if isinstance(item, dict))
        transfer_state = {
            "status": "completed" if not has_errors else "completed_with_errors",
            "requested_count": len(artifact_inputs),
            "workspace_path": workspace_path,
            "transfers": transfers,
        }
        manifest["artifact_transfer"] = transfer_state
        run.manifest = manifest
        self._add_run_event(
            run,
            "artifact_transfer",
            ProviderResult(
                state=RunState(run.state) if run.state in {item.value for item in RunState} else RunState.ERRORED,
                provider_run_ref=run.provider_run_ref or f"run-{run.id}",
                plan=manifest,
                transcript=(
                    "Artifact inputs copied into the guest workspace."
                    if not has_errors
                    else "Artifact input transfer completed with warnings."
                ),
            ),
            level="warning" if has_errors else "info",
        )

    def _collect_and_generate(self, *, run: LabRun, candidate: Optional[ResearchCandidate], analyst_name: str) -> RunArtifacts:
        revision = (
            self.session.query(RecipeRevision).filter(RecipeRevision.id == run.recipe_revision_id).first()
        )
        recipe_content = dict(revision.content or {}) if revision else {}
        names = recipe_collector_names(recipe_content)
        collectors = instantiate_collectors(names)

        run_context: Dict[str, Any] = {
            "run_id": run.id,
            "candidate": self._candidate_payload(candidate) if candidate else {},
            "cve_id": candidate.cve.cve_id if candidate and candidate.cve else None,
            "launch_mode": run.launch_mode,
            "recipe_content": recipe_content,
        }
        provider_result = build_provider_result_dict(
            provider_run_ref=run.provider_run_ref,
            plan=run.manifest or {},
            state=run.state,
            container_id=(run.manifest or {}).get("container_id"),
        )
        evidence: List[Dict[str, Any]] = []
        for collector in collectors:
            try:
                collector.pre_run(run_context=run_context, provider_result=provider_result)
            except Exception as exc:  # noqa: BLE001 — isolate collector hook failures
                evidence.append(
                    collector_error_evidence(
                        collector_name=getattr(collector, "collector_name", "unknown"),
                        title="Collector pre_run failed",
                        message=str(exc),
                        run_context=run_context,
                        provider_result=provider_result,
                        collector_version=getattr(collector, "collector_version", "0.0.0"),
                    )
                )
        for collector in collectors:
            t_collect0 = time.monotonic()
            try:
                batch = collector.collect(run_context=run_context, provider_result=provider_result)
            except Exception as exc:  # noqa: BLE001
                wall_ms = int((time.monotonic() - t_collect0) * 1000)
                err_item = collector_error_evidence(
                    collector_name=getattr(collector, "collector_name", "unknown"),
                    title="Collector failed",
                    message=str(exc),
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=getattr(collector, "collector_version", "0.0.0"),
                )
                pl = err_item.get("payload")
                if isinstance(pl, dict):
                    pl["service_layer"] = {"collect_wall_ms": wall_ms}
                evidence.append(err_item)
            else:
                wall_ms = int((time.monotonic() - t_collect0) * 1000)
                for ev in batch:
                    pl = ev.get("payload")
                    if isinstance(pl, dict):
                        pl["service_layer"] = {"collect_wall_ms": wall_ms}
                evidence.extend(batch)
        for collector in collectors:
            try:
                collector.post_run(run_context=run_context, provider_result=provider_result)
            except Exception as exc:  # noqa: BLE001
                evidence.append(
                    collector_error_evidence(
                        collector_name=getattr(collector, "collector_name", "unknown"),
                        title="Collector post_run failed",
                        message=str(exc),
                        run_context=run_context,
                        provider_result=provider_result,
                        collector_version=getattr(collector, "collector_version", "0.0.0"),
                    )
                )
        generated = self.artifact_generator.generate(run_context=run_context, evidence=evidence)
        tenant = self.session.query(Tenant).filter(Tenant.id == run.tenant_id).first()
        signer = self._attestation_signer_for_tenant(tenant) if tenant else self.default_attestation_signer
        attestation = signer.sign(payload=run.manifest or {}, signer=analyst_name)
        return RunArtifacts(
            evidence=evidence,
            detections=generated["detection_artifacts"],
            mitigations=generated["mitigation_artifacts"],
            attestation=attestation,
        )

    def _parse_iso_datetime(self, value: Optional[str]) -> Optional[datetime]:
        if not value or not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _persist_run_artifacts(self, *, run: LabRun, artifacts: RunArtifacts) -> None:
        evidence_records: List[EvidenceArtifact] = []
        for item in artifacts.evidence:
            record = EvidenceArtifact(
                run_id=run.id,
                artifact_kind=item["artifact_kind"],
                title=item["title"],
                summary=item["summary"],
                sha256=item["sha256"],
                storage_path=item.get("storage_path"),
                content_type=item.get("content_type"),
                byte_size=item.get("byte_size"),
                capture_started_at=self._parse_iso_datetime(item.get("capture_started_at")),
                capture_ended_at=self._parse_iso_datetime(item.get("capture_ended_at")),
                collector_name=item.get("collector_name") or item.get("artifact_kind"),
                collector_version=item.get("collector_version"),
                truncated=bool(item.get("truncated")),
                payload=item["payload"],
                reviewed_state="captured",
            )
            self.session.add(record)
            evidence_records.append(record)
        self.session.flush()

        first_evidence_id = evidence_records[0].id if evidence_records else None
        detection_records: List[DetectionArtifact] = []
        for item in artifacts.detections:
            record = DetectionArtifact(
                run_id=run.id,
                evidence_artifact_id=item.get("evidence_artifact_id") or first_evidence_id,
                artifact_type=item["artifact_type"],
                name=item["name"],
                rule_body=item["rule_body"],
                status=item["status"],
                sha256=item["sha256"],
            )
            self.session.add(record)
            detection_records.append(record)
        mitigation_records: List[MitigationArtifact] = []
        for item in artifacts.mitigations:
            record = MitigationArtifact(
                run_id=run.id,
                artifact_type=item["artifact_type"],
                title=item["title"],
                body=item["body"],
                status=item["status"],
            )
            self.session.add(record)
            mitigation_records.append(record)
        self.session.flush()
        attestation_payload = self._build_run_attestation_payload(
            run=run,
            signer=artifacts.attestation["signer"],
            evidence_records=evidence_records,
            detection_records=detection_records,
            mitigation_records=mitigation_records,
        )
        tenant = self.session.query(Tenant).filter(Tenant.id == run.tenant_id).first()
        signer = self._attestation_signer_for_tenant(tenant) if tenant else self.default_attestation_signer
        signed = signer.sign(payload=attestation_payload, signer=artifacts.attestation["signer"])
        self.session.add(
            AttestationRecord(
                tenant_id=run.tenant_id,
                run_id=run.id,
                subject_type="run_manifest",
                subject_id=str(run.id),
                sha256=signed["sha256"],
                signature=signed["signature"],
                signer=signed["signer"],
                payload={
                    **attestation_payload,
                    "signing": {
                        "backend": signed.get("backend"),
                        "algorithm": signed.get("algorithm"),
                        "fingerprint": signed.get("fingerprint"),
                        "public_key": signed.get("public_key"),
                        "verification_status": "verified",
                    },
                },
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
        manifest = run.manifest or {}
        return {
            "id": run.id,
            "recipe_revision_id": run.recipe_revision_id,
            "candidate_id": run.candidate_id,
            "analysis_mode": manifest.get("analysis_mode", "cve_validation"),
            "sandbox_profile_id": manifest.get("sandbox_profile_id"),
            "specimen_ids": manifest.get("specimen_ids") or [],
            "specimen_revisions": manifest.get("specimen_revisions") or [],
            "egress_mode": manifest.get("egress_mode", "default_deny"),
            "ai_assist": manifest.get("ai_assist") or {},
            "collector_plan": manifest.get("collector_plan") or [],
            "linked_case_ids": manifest.get("linked_case_ids") or [],
            "execution_plan": manifest.get("execution_plan") or {},
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
            "acknowledged_at": run.acknowledged_at.isoformat() if run.acknowledged_at else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
            "manifest": manifest,
            "run_transcript": run.run_transcript,
            "provider_readiness": manifest.get("provider_readiness") or {},
            "collector_capabilities": manifest.get("collector_capabilities") or [],
            "image_catalog": manifest.get("image_catalog") or {},
            "execution_policy": manifest.get("execution_policy") or {},
            "provider_contract": manifest.get("provider_contract") or {},
        }

    def _apply_provider_result(self, run: LabRun, result: ProviderResult) -> None:
        """Apply a ProviderResult to a LabRun record."""
        run.provider_run_ref = result.provider_run_ref
        run.state = result.state.value if isinstance(result.state, RunState) else result.state
        plan = dict(run.manifest or {})
        if result.plan:
            plan = {**plan, **dict(result.plan)}
        if result.container_id:
            plan["container_id"] = result.container_id
        run.guest_image = plan.get("image")
        run.image_digest = plan.get("image_digest")
        run.network_mode = plan.get("network_mode")
        run.workspace_path = plan.get("host_workspace") or run.workspace_path
        run.manifest = plan
        run.run_transcript = result.transcript

    def _should_collect_after_provider_launch(self, run: LabRun) -> bool:
        if run.launch_mode in {"dry_run", "simulated"}:
            return True
        manifest = run.manifest or {}
        if run.launch_mode != "execute" or not run.provider_run_ref:
            return False
        if manifest.get("container_id"):
            return True
        if run.provider == "lima" and (manifest.get("instance_name") or (manifest.get("snapshot_refs") or {}).get("booted")):
            return True
        return False

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

    def _prepare_recipe_content(self, content: Dict[str, Any], image: Optional[str]) -> Dict[str, Any]:
        normalized = self._normalize_recipe_content(content, image)
        validation = self.validate_recipe_content(normalized)
        if not validation["valid"]:
            raise ValueError("; ".join(validation["errors"]))
        return normalized

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
                    "image_digest": t.image_digest,
                    "is_hardened": t.is_hardened,
                    "network_mode": t.network_mode,
                    "meta": t.meta,
                }
                for t in rows
            ],
            "count": len(rows),
        }

    def _normalize_recipe_content(self, content: Dict[str, Any], image: Optional[str]) -> Dict[str, Any]:
        normalized = dict(content)
        if "artifact_inputs" not in normalized and "input_artifacts" in normalized:
            normalized["artifact_inputs"] = normalized["input_artifacts"]
        normalized.setdefault("provider", "docker_kali")
        normalized.setdefault("command", ["sleep", "1"])
        normalized.setdefault("network_policy", {"allow_egress_hosts": []})
        normalized.setdefault("collectors", list(DEFAULT_RECIPE_COLLECTORS))
        normalized.setdefault("teardown_policy", {"mode": "destroy_immediately", "ephemeral_workspace": True})
        normalized.setdefault("risk_level", "standard")
        normalized.setdefault("workspace_retention", "destroy_immediately")
        execution_policy = dict(normalized.get("execution_policy") or {})
        if normalized["provider"] == "lima":
            execution_policy.setdefault("secure_mode_required", True)
        else:
            execution_policy.setdefault("secure_mode_required", False)
        execution_policy.setdefault("preferred_provider", normalized["provider"])
        execution_policy.setdefault("allowed_modes", ["dry_run", "simulated", "execute"])
        normalized["execution_policy"] = execution_policy
        catalog_entry = resolve_catalog_entry(
            provider=str(normalized["provider"]),
            image_profile=normalized.get("image_profile"),
            requested_image=normalized.get("base_image") or image,
            collectors=normalized.get("collectors") or [],
        )
        normalized["base_image"] = catalog_entry.image
        normalized["image_profile"] = catalog_entry.profile
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

    def _ensure_lab_template(self, *, provider_name: str = "docker_kali", image_profile: str = "baseline") -> LabTemplate:
        self._ensure_template_catalog()
        entry = resolve_catalog_entry(provider=provider_name, image_profile=image_profile)
        template = (
            self.session.query(LabTemplate)
            .filter(LabTemplate.provider == provider_name, LabTemplate.base_image == entry.image)
            .first()
        )
        if template is None:
            template = LabTemplate(
                provider=provider_name,
                name=f"{provider_name}:{entry.profile}",
                distro="ubuntu" if provider_name == "lima" else "kali",
                base_image=entry.image,
                image_digest=entry.digest,
                is_hardened=True,
                network_mode="isolated",
                meta=entry.to_manifest(),
            )
            self.session.add(template)
            self.session.flush()
        return template

    def _ensure_template_catalog(self) -> None:
        """Seed trusted image-backed templates plus compatibility templates."""
        for entry in list_image_catalog():
            existing = (
                self.session.query(LabTemplate)
                .filter(LabTemplate.provider == entry.provider, LabTemplate.base_image == entry.image)
                .first()
            )
            if existing is None:
                distro = "ubuntu" if entry.provider == "lima" else "kali"
                self.session.add(
                    LabTemplate(
                        provider=entry.provider,
                        name=f"{entry.provider}:{entry.profile}",
                        distro=distro,
                        base_image=entry.image,
                        image_digest=entry.digest,
                        is_hardened=True,
                        network_mode="isolated",
                        meta=entry.to_manifest(),
                    )
                )
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
                    "description": "Default Kali-on-Docker image for constrained defensive validation.",
                },
            },
            {
                "provider": "docker_kali",
                "name": "Constrained Kali Validation + osquery",
                "distro": "kali",
                "base_image": DEFAULT_OSQUERY_IMAGE,
                "is_hardened": True,
                "network_mode": "isolated",
                "meta": {
                    "read_only_rootfs": True,
                    "default_cap_drop": ["ALL"],
                    "egress_policy": "default-deny",
                    "description": "Dedicated Kali-derived lab image for execute-mode osquery snapshot collection.",
                    "tooling_profile": "osquery",
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
                        image_digest=self.default_attestation_signer.sign(
                            payload={"image": entry["base_image"]}, signer="system"
                        )["sha256"],
                        is_hardened=entry["is_hardened"],
                        network_mode=entry["network_mode"],
                        meta=entry["meta"],
                    )
                )
        self.session.flush()

    def _artifact_review_entries(self, target_type: str, target_id: int) -> List[ReviewDecision]:
        return (
            self.session.query(ReviewDecision)
            .filter(ReviewDecision.target_type == target_type, ReviewDecision.target_id == str(target_id))
            .order_by(ReviewDecision.created_at.desc())
            .all()
        )

    def _latest_review_entry(self, target_type: str, target_id: int) -> Optional[ReviewDecision]:
        return (
            self.session.query(ReviewDecision)
            .filter(ReviewDecision.target_type == target_type, ReviewDecision.target_id == str(target_id))
            .order_by(ReviewDecision.created_at.desc())
            .first()
        )

    def _review_queue_item(
        self,
        *,
        entity_type: str,
        entity_id: int,
        run_id: Optional[int],
        title: str,
        status: str,
        review_state: str,
        sensitivity: Dict[str, Any],
        blocking_reasons: List[str],
        last_review: Optional[ReviewDecision],
        updated_at: Optional[datetime],
        route: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "run_id": run_id,
            "title": title,
            "status": status,
            "review_state": review_state,
            "sensitivity": sensitivity,
            "blocking_reasons": blocking_reasons,
            "needs_attention_now": bool(blocking_reasons) or review_state in {"captured", "draft", "under_review", "changes_requested", "blocked", "needs_attention"},
            "last_reviewer": last_review.reviewer_name if last_review else None,
            "last_decision": last_review.decision if last_review else None,
            "last_decision_at": last_review.created_at.isoformat() if last_review and last_review.created_at else None,
            "updated_at": updated_at.isoformat() if updated_at else None,
            "route": route,
        }
        if extra:
            payload.update(extra)
        return payload

    def _detection_artifact_payload(self, item: DetectionArtifact) -> Dict[str, Any]:
        reviews = self._artifact_review_entries("detection_artifact", item.id)
        latest_review = reviews[0] if reviews else None
        return {
            "id": item.id,
            "run_id": item.run_id,
            "artifact_type": item.artifact_type,
            "name": item.name,
            "status": item.status,
            "sha256": item.sha256,
            "evidence_artifact_id": item.evidence_artifact_id,
            "rule_body": item.rule_body,
            "lineage": {
                "supersedes_artifact_id": (latest_review.payload or {}).get("supersedes_artifact_id") if latest_review else None,
                "correction_note": (latest_review.payload or {}).get("correction_note") if latest_review else None,
                "latest_decision": latest_review.decision if latest_review else item.status,
                "latest_reviewed_at": latest_review.created_at.isoformat() if latest_review and latest_review.created_at else None,
            },
            "review_history": [
                {
                    "decision": row.decision,
                    "reviewer_name": row.reviewer_name,
                    "rationale": row.rationale,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in reviews
            ],
            "feedback": [
                {
                    "reviewer_name": row.reviewer_name,
                    "feedback_type": (row.payload or {}).get("feedback_type"),
                    "note": row.rationale,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in reviews
                if row.decision == "feedback"
            ],
        }

    def _mitigation_artifact_payload(self, item: MitigationArtifact) -> Dict[str, Any]:
        reviews = self._artifact_review_entries("mitigation_artifact", item.id)
        latest_review = reviews[0] if reviews else None
        return {
            "id": item.id,
            "run_id": item.run_id,
            "artifact_type": item.artifact_type,
            "title": item.title,
            "status": item.status,
            "body": item.body,
            "lineage": {
                "supersedes_artifact_id": (latest_review.payload or {}).get("supersedes_artifact_id") if latest_review else None,
                "correction_note": (latest_review.payload or {}).get("correction_note") if latest_review else None,
                "latest_decision": latest_review.decision if latest_review else item.status,
                "latest_reviewed_at": latest_review.created_at.isoformat() if latest_review and latest_review.created_at else None,
            },
            "review_history": [
                {
                    "decision": row.decision,
                    "reviewer_name": row.reviewer_name,
                    "rationale": row.rationale,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in reviews
            ],
            "feedback": [
                {
                    "reviewer_name": row.reviewer_name,
                    "feedback_type": (row.payload or {}).get("feedback_type"),
                    "note": row.rationale,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in reviews
                if row.decision == "feedback"
            ],
        }

    def _get_artifact_entity(self, tenant: Tenant, artifact_family: str, artifact_id: int) -> Any:
        if artifact_family == "detection":
            row = (
                self.session.query(DetectionArtifact)
                .join(LabRun, LabRun.id == DetectionArtifact.run_id)
                .filter(LabRun.tenant_id == tenant.id, DetectionArtifact.id == artifact_id)
                .first()
            )
        elif artifact_family == "mitigation":
            row = (
                self.session.query(MitigationArtifact)
                .join(LabRun, LabRun.id == MitigationArtifact.run_id)
                .filter(LabRun.tenant_id == tenant.id, MitigationArtifact.id == artifact_id)
                .first()
            )
        else:
            raise ValueError("Artifact family must be 'detection' or 'mitigation'.")
        if row is None:
            raise ValueError("Artifact not found.")
        return row

    def _run_analyst_id(self, run_id: int) -> Optional[int]:
        row = self.session.query(LabRun).filter(LabRun.id == run_id).first()
        return row.analyst_id if row else None

    def _build_run_attestation_payload(
        self,
        *,
        run: LabRun,
        signer: str,
        evidence_records: List[EvidenceArtifact],
        detection_records: List[DetectionArtifact],
        mitigation_records: List[MitigationArtifact],
    ) -> Dict[str, Any]:
        revision = self.session.query(RecipeRevision).filter(RecipeRevision.id == run.recipe_revision_id).first()
        analyst = self.session.query(AnalystIdentity).filter(AnalystIdentity.id == run.analyst_id).first()
        workstation = self.session.query(WorkstationFingerprint).filter(
            WorkstationFingerprint.id == run.workstation_fingerprint_id
        ).first()
        payload = {
            "subject": {"type": "run_manifest", "id": str(run.id)},
            "run_id": run.id,
            "manifest": run.manifest or {},
            "recipe_revision_id": run.recipe_revision_id,
            "recipe_revision_digest": revision.signed_digest if revision else None,
            "analyst": analyst.name if analyst else signer,
            "workstation": workstation.fingerprint if workstation else None,
            "acknowledgement": (run.manifest or {}).get("acknowledgement"),
            "artifact_transfer": (run.manifest or {}).get("artifact_transfer"),
            "evidence_hashes": [
                {
                    "id": row.id,
                    "artifact_kind": row.artifact_kind,
                    "sha256": row.sha256,
                }
                for row in evidence_records
            ],
            "artifact_hashes": {
                "detections": [
                    {"id": row.id, "artifact_type": row.artifact_type, "sha256": row.sha256}
                    for row in detection_records
                ],
                "mitigations": [
                    {
                        "id": row.id,
                        "artifact_type": row.artifact_type,
                        "sha256": hashlib.sha256((row.body or "").encode("utf-8")).hexdigest(),
                    }
                    for row in mitigation_records
                ],
            },
        }
        tenant = self.session.query(Tenant).filter(Tenant.id == run.tenant_id).first()
        attestation_signer = self._attestation_signer_for_tenant(tenant) if tenant else self.default_attestation_signer
        signed = attestation_signer.sign(payload=payload, signer=signer)
        payload["signing"] = {
            "backend": signed.get("backend"),
            "algorithm": signed.get("algorithm"),
            "fingerprint": signed.get("fingerprint"),
            "public_key": signed.get("public_key"),
            "verification_status": "verified",
        }
        return payload

    def _build_reproduction_steps(self, *, run: LabRun, evidence_rows: List[EvidenceArtifact]) -> List[str]:
        command = (run.manifest or {}).get("command") or ["sleep", "1"]
        if isinstance(command, list):
            command_text = " ".join(str(part) for part in command)
        else:
            command_text = str(command)
        evidence_summary = f"Review {len(evidence_rows)} captured evidence artifacts for process, file, and network deltas."
        return [
            f"Provision the planned guest image `{run.guest_image or (run.manifest or {}).get('image', 'unknown')}` with the recorded network mode `{run.network_mode}`.",
            f"Execute the validation command `{command_text}` under the approved recipe revision `{run.recipe_revision_id}`.",
            evidence_summary,
            "Compare observed behavior against the expected defensive findings and mitigation checklist before export.",
        ]

    def _render_bundle_report(
        self,
        *,
        bundle_type: str,
        title: str,
        run: LabRun,
        evidence_rows: List[EvidenceArtifact],
        artifacts: List[Any],
        warnings: List[str],
        reproduction_steps: List[str],
    ) -> str:
        bundle_labels = {
            "vendor_disclosure": "Vendor disclosure",
            "bug_bounty": "Bug bounty submission",
            "research_submission": "Research submission",
            "internal_remediation": "Internal remediation package",
        }
        destination_language = {
            "vendor_disclosure": "Use vendor-facing language that emphasizes impact, reproducibility, and fix guidance.",
            "bug_bounty": "Use concise submission language that emphasizes exploitability, impact, and validation artifacts.",
            "research_submission": "Use research-oriented language that emphasizes rigor, methodology, and reproducibility.",
            "internal_remediation": "Use remediation-focused language that emphasizes affected scope, urgency, and rollout guidance.",
        }
        artifact_lines = []
        for row in artifacts:
            if isinstance(row, DetectionArtifact):
                artifact_lines.append(f"- Detection `{row.artifact_type}`: {row.name} [{row.status}]")
            else:
                artifact_lines.append(f"- Mitigation `{row.artifact_type}`: {row.title} [{row.status}]")
        warning_lines = [f"- {item}" for item in warnings] or ["- No export warnings were raised."]
        evidence_lines = [f"- `{row.artifact_kind}`: {row.title}" for row in evidence_rows]
        return "\n".join(
            [
                f"# {title}",
                "",
                f"Bundle type: `{bundle_labels.get(bundle_type, bundle_type)}`",
                f"Run ID: `{run.id}`",
                f"Launch mode: `{run.launch_mode}`",
                "",
                "## Summary",
                f"- Evidence included: {len(evidence_rows)}",
                f"- Artifacts included: {len(artifacts)}",
                f"- Provider: {run.provider}",
                "",
                "## Destination guidance",
                f"- {destination_language.get(bundle_type, 'Use the attached evidence and provenance data to support the intended workflow.')}",
                "",
                "## Export warnings",
                *warning_lines,
                "",
                "## Intended use",
                f"- {bundle_labels.get(bundle_type, bundle_type)} workflow",
                "",
                "## Evidence index",
                *(evidence_lines or ["- No evidence selected."]),
                "",
                "## Artifacts",
                *(artifact_lines or ["- No reviewed artifacts were available; draft artifacts were exported for internal review only."]),
                "",
                "## Reproduction steps",
                *[f"{idx}. {step}" for idx, step in enumerate(reproduction_steps, start=1)],
            ]
        )

    def _build_bundle_manifest(
        self,
        *,
        run: LabRun,
        bundle_type: str,
        title: str,
        signed_by: str,
        evidence_rows: List[EvidenceArtifact],
        artifacts: List[Any],
        redaction_notes: List[Dict[str, Any]],
        attachment_policy: List[Dict[str, Any]] | Dict[str, Any],
        warnings: List[str],
        review_checklist: Dict[str, Any],
    ) -> Dict[str, Any]:
        reproduction_steps = self._build_reproduction_steps(run=run, evidence_rows=evidence_rows)
        attachment_defaults = {
            "vendor_disclosure": {"include_raw_logs": False, "include_pcap": False, "include_screenshots": False},
            "bug_bounty": {"include_raw_logs": False, "include_pcap": False, "include_screenshots": True},
            "research_submission": {"include_raw_logs": True, "include_pcap": False, "include_screenshots": True},
            "internal_remediation": {"include_raw_logs": True, "include_pcap": False, "include_screenshots": True},
        }
        effective_attachment_policy = {
            **attachment_defaults.get(bundle_type, attachment_defaults["vendor_disclosure"]),
            **(attachment_policy if isinstance(attachment_policy, dict) else {}),
        }
        report_sections = {
            "summary": True,
            "impact_summary": True,
            "reproduction_appendix": True,
            "fix_guidance": True,
            "evidence_index": True,
            "review_history": True,
            "redaction_log": True,
            "provenance_summary": True,
        }
        attachment_inventory = [
            {
                "kind": row.artifact_kind,
                "title": row.title,
                "include": effective_attachment_policy.get(
                    "include_raw_logs" if row.artifact_kind == "service_logs" else (
                        "include_pcap" if row.artifact_kind == "pcap" else "include_screenshots"
                    ),
                    True,
                ),
                "reason": "Included by attachment policy." if effective_attachment_policy else "Included by default.",
            }
            for row in evidence_rows
        ]
        return {
            "title": title,
            "bundle_type": bundle_type,
            "run": self._run_summary(run),
            "signed_by": signed_by,
            "exported_at": utc_now().isoformat(),
            "warnings": warnings,
            "attachment_policy": effective_attachment_policy,
            "attachment_inventory": attachment_inventory,
            "safety_checklist": {
                "requires_external_confirmation": bool(warnings),
                "contains_raw_pcap": any(row.artifact_kind == "pcap" for row in evidence_rows),
                "contains_service_logs": any(row.artifact_kind == "service_logs" for row in evidence_rows),
                "approved_artifact_count": sum(1 for row in artifacts if getattr(row, "status", None) == "approved"),
            },
            "review_state": "approved" if not warnings else "under_review",
            "review_checklist": review_checklist,
            "review_history": [],
            "export_audit": {
                "exported_by": signed_by,
                "bundle_type": bundle_type,
                "provider": run.provider,
                "image_profile": (run.manifest or {}).get("image_profile"),
                "verification_status": "verified",
            },
            "redaction_notes": redaction_notes,
            "redaction_log": {
                "count": len(redaction_notes),
                "items": redaction_notes,
            },
            "reproduction_steps": reproduction_steps,
            "impact_summary": {
                "candidate_id": run.candidate_id,
                "warning_count": len(warnings),
                "artifact_count": len(artifacts),
                "evidence_count": len(evidence_rows),
            },
            "fix_guidance": [row.title for row in artifacts if isinstance(row, MitigationArtifact)],
            "provenance_summary": {
                "run_id": run.id,
                "recipe_revision_id": run.recipe_revision_id,
                "provider": run.provider,
                "signing": (run.manifest or {}).get("provider_contract") or {},
            },
            "report_sections": report_sections,
            "evidence": [
                {
                    "id": row.id,
                    "artifact_kind": row.artifact_kind,
                    "title": row.title,
                    "summary": row.summary,
                    "sha256": row.sha256,
                    "storage_path": row.storage_path,
                }
                for row in evidence_rows
            ],
            "artifacts": [
                self._detection_artifact_payload(row) if isinstance(row, DetectionArtifact) else self._mitigation_artifact_payload(row)
                for row in artifacts
            ],
            "report_markdown": self._render_bundle_report(
                bundle_type=bundle_type,
                title=title,
                run=run,
                evidence_rows=evidence_rows,
                artifacts=artifacts,
                warnings=warnings,
                reproduction_steps=reproduction_steps,
            ),
        }

    def _write_bundle_archive(
        self,
        *,
        manifest: Dict[str, Any],
        evidence_rows: List[EvidenceArtifact],
        detection_rows: List[DetectionArtifact],
        mitigation_rows: List[MitigationArtifact],
    ) -> Dict[str, Any]:
        self.export_root.mkdir(parents=True, exist_ok=True)
        timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        filename = f"sheshnaag-bundle-run-{manifest['run']['id']}-{timestamp}.zip"
        path = self.export_root / filename
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps({k: v for k, v in manifest.items() if k != "report_markdown"}, indent=2, sort_keys=True, default=str))
            archive.writestr("report.md", manifest["report_markdown"])
            archive.writestr("review-history.json", json.dumps(manifest.get("review_history") or [], indent=2, sort_keys=True, default=str))
            archive.writestr("redaction-log.json", json.dumps(manifest.get("redaction_log") or {}, indent=2, sort_keys=True, default=str))
            archive.writestr("impact-summary.json", json.dumps(manifest.get("impact_summary") or {}, indent=2, sort_keys=True, default=str))
            archive.writestr("provenance-summary.json", json.dumps(manifest.get("provenance_summary") or {}, indent=2, sort_keys=True, default=str))
            archive.writestr("attachment-inventory.json", json.dumps(manifest.get("attachment_inventory") or [], indent=2, sort_keys=True, default=str))
            for row in evidence_rows:
                archive.writestr(
                    f"evidence/evidence-{row.id}.json",
                    json.dumps(
                        {
                            "id": row.id,
                            "artifact_kind": row.artifact_kind,
                            "title": row.title,
                            "summary": row.summary,
                            "sha256": row.sha256,
                            "payload": row.payload,
                        },
                        indent=2,
                        sort_keys=True,
                        default=str,
                    ),
                )
            for row in detection_rows:
                archive.writestr(f"artifacts/detection-{row.id}-{row.artifact_type}.txt", row.rule_body)
            for row in mitigation_rows:
                archive.writestr(f"artifacts/mitigation-{row.id}-{row.artifact_type}.md", row.body)
        archive_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "path": str(path),
            "filename": filename,
            "sha256": archive_sha256,
            "size": path.stat().st_size,
        }

    def _disclosure_bundle_payload(self, row: DisclosureBundle) -> Dict[str, Any]:
        archive = (row.manifest or {}).get("archive") or {}
        tenant = self.session.query(Tenant).filter(Tenant.id == row.tenant_id).first()
        tenant_slug = tenant.slug if tenant else "demo-public"
        review_history = [
            {
                "decision": item.decision,
                "reviewer_name": item.reviewer_name,
                "rationale": item.rationale,
                "payload": item.payload,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in (
                self.session.query(ReviewDecision)
                .filter(ReviewDecision.target_type == "disclosure_bundle", ReviewDecision.target_id == str(row.id))
                .order_by(ReviewDecision.created_at.desc())
                .all()
            )
        ]
        return {
            "id": row.id,
            "run_id": row.run_id,
            "bundle_type": row.bundle_type,
            "title": row.title,
            "status": row.status,
            "sha256": row.sha256,
            "signed_by": row.signed_by,
            "manifest": row.manifest,
            "archive": archive,
            "download_url": f"/api/disclosures/{row.id}/download?tenant_slug={tenant_slug}",
            "signing": (row.manifest or {}).get("signing") or {},
            "attachment_policy": (row.manifest or {}).get("attachment_policy") or {},
            "report_sections": (row.manifest or {}).get("report_sections") or {},
            "review_history": review_history,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    def _ensure_analyst_identity(self, tenant: Tenant, analyst_name: Optional[str] = None) -> AnalystIdentity:
        email = f"{(analyst_name or 'demo.analyst').lower().replace(' ', '.')}@sheshnaag.local"
        signing_key = self._ensure_tenant_signing_key(tenant)
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
                public_key_fingerprint=signing_key.fingerprint,
            )
            self.session.add(record)
            self.session.flush()
        else:
            record.public_key_fingerprint = signing_key.fingerprint
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
            if any((item.get("product") or item.get("name") or "").lower() == (affected.product or "").lower() for item in installed if isinstance(item, dict)):
                matches += 1
        return matches

    @staticmethod
    def _version_token_tuple(value: Optional[str]) -> tuple:
        raw = str(value or "").strip()
        if not raw:
            return tuple()
        parts: List[Any] = []
        for token in raw.replace("-", ".").split("."):
            if token.isdigit():
                parts.append(int(token))
            else:
                parts.append(token.lower())
        return tuple(parts)

    def _version_in_range(self, version: Optional[str], row: VersionRange) -> bool:
        candidate = self._version_token_tuple(version)
        if not candidate:
            return False
        start = self._version_token_tuple(row.version_start)
        end = self._version_token_tuple(row.version_end)
        fixed = self._version_token_tuple(row.fixed_version)
        if start:
            if row.is_inclusive_start:
                if candidate < start:
                    return False
            elif candidate <= start:
                return False
        if fixed and candidate >= fixed:
            return False
        if end:
            if row.is_inclusive_end:
                if candidate > end:
                    return False
            elif candidate >= end:
                return False
        return True

    def _compute_environment_applicability(
        self,
        *,
        cve: CVE,
        tenant: Tenant,
        affected: Optional[AffectedProduct],
    ) -> Dict[str, Any]:
        """Compute rich applicability using SBOM components, VEX, and asset mappings."""
        advisory_rows = self.session.query(AdvisoryRecord).filter(AdvisoryRecord.cve_id == cve.id).all()
        advisory_summary = summarize_advisory_records(advisory_rows)
        normalized_packages = advisory_summary.get("normalized_packages") or []
        package_names = {str(pkg.get("name") or "").lower() for pkg in normalized_packages if pkg.get("name")}
        if affected and affected.product:
            package_names.add(str(affected.product).lower())
        result: Dict[str, Any] = {
            "match_sources": [],
            "confidence": 0.0,
            "vex_status": None,
            "vex_justification": None,
            "direct_product_match": False,
            "sbom_component_match": False,
            "asset_match_count": 0,
            "sbom_match_count": 0,
            "asset_matches": [],
            "sbom_matches": [],
            "version_ranges": [],
            "version_match_count": 0,
            "version_match_confidence": 0.2,
            "sbom_vex_applicability": 0.2,
            "normalized_packages": normalized_packages,
        }

        # 1. Legacy asset installed_software match
        assets = self.session.query(Asset).filter(Asset.tenant_id == tenant.id).all()
        asset_matches = 0
        version_match_count = 0
        matched_versions: List[Dict[str, Any]] = []
        package_ranges = (
            self.session.query(VersionRange)
            .filter(VersionRange.cve_id == cve.id, VersionRange.package_record_id.isnot(None))
            .all()
        )
        for asset in assets:
            installed = asset.installed_software or []
            for item in installed:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("product") or item.get("name") or "").lower()
                version = item.get("version")
                if name and name in package_names:
                    asset_matches += 1
                    result["asset_matches"].append(
                        {
                            "asset_id": asset.id,
                            "asset_name": asset.name,
                            "package_name": name,
                            "version": version,
                        }
                    )
                    for range_row in package_ranges:
                        if self._version_in_range(version, range_row):
                            version_match_count += 1
                            matched_versions.append(
                                {
                                    "asset_id": asset.id,
                                    "package_name": name,
                                    "version": version,
                                    "range_type": range_row.range_type,
                                    "fixed_version": range_row.fixed_version,
                                }
                            )
                            break
                    break
        result["asset_match_count"] = asset_matches
        result["version_match_count"] = version_match_count
        result["version_ranges"] = matched_versions
        if asset_matches > 0:
            result["match_sources"].append({"source": "asset_installed_software", "count": asset_matches, "confidence": 0.6})
        if version_match_count > 0:
            result["match_sources"].append({"source": "affected_version", "count": version_match_count, "confidence": 0.9})

        # 2. SBOM component match via SoftwareComponent table
        sbom_matches = 0
        components = (
            self.session.query(SoftwareComponent)
            .filter(SoftwareComponent.tenant_id == tenant.id)
            .all()
        )
        for comp in components:
            name = str(comp.name or "").lower()
            purl = str(comp.purl or "").lower()
            if name and name in package_names:
                sbom_matches += 1
                result["direct_product_match"] = True
                result["sbom_matches"].append({"component_id": comp.id, "name": comp.name, "version": comp.version, "purl": comp.purl})
            elif any(pkg_name and pkg_name in purl for pkg_name in package_names):
                sbom_matches += 1
                result["sbom_component_match"] = True
                result["sbom_matches"].append({"component_id": comp.id, "name": comp.name, "version": comp.version, "purl": comp.purl})

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
        result["patch_available"] = bool(
            result.get("vex_status") in ("fixed", "not_affected")
            or any(match.get("fixed_version") for match in matched_versions)
            or vex_statements
        )
        result["version_match_confidence"] = min(1.0, 0.25 + (0.25 if matched_versions else 0.0) + (0.2 if asset_matches else 0.0) + (0.2 if sbom_matches else 0.0))
        result["sbom_vex_applicability"] = min(
            1.0,
            0.15
            + (0.35 if sbom_matches else 0.0)
            + (0.3 if asset_matches else 0.0)
            + (0.2 if result.get("vex_status") in ("affected", "under_investigation") else 0.0),
        )

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
