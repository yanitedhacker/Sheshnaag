"""Project Sheshnaag domain models."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.time import utc_now


class SourceFeed(Base):
    """Normalized source feed health and freshness records."""

    __tablename__ = "source_feeds"
    __table_args__ = (UniqueConstraint("feed_key", name="uq_source_feed_key"),)

    id = Column(Integer, primary_key=True, index=True)
    feed_key = Column(String(100), nullable=False, index=True)
    display_name = Column(String(200), nullable=False)
    category = Column(String(50), default="intel")
    status = Column(String(30), default="planned")
    source_url = Column(Text)
    freshness_seconds = Column(Integer)
    last_synced_at = Column(DateTime)
    raw_payload_hash = Column(String(128))
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AdvisoryRecord(Base):
    """Normalized advisory records tied to CVEs and products."""

    __tablename__ = "advisory_records"

    id = Column(Integer, primary_key=True, index=True)
    source_feed_id = Column(Integer, ForeignKey("source_feeds.id", ondelete="SET NULL"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    product_id = Column(Integer, ForeignKey("product_records.id", ondelete="SET NULL"), index=True)
    package_record_id = Column(Integer, ForeignKey("package_records.id", ondelete="SET NULL"), index=True)

    external_id = Column(String(120), index=True)
    canonical_id = Column(String(160), index=True)
    advisory_type = Column(String(80), default="advisory", index=True)
    severity = Column(String(40), index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text)
    source_url = Column(Text)
    published_at = Column(DateTime)
    normalization_confidence = Column(Float, default=0.5)
    aliases = Column(JSON, default=list)
    references = Column(JSON, default=list)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AdvisoryPackageLink(Base):
    """Structured package linkage for package-backed advisories."""

    __tablename__ = "advisory_package_links"
    __table_args__ = (
        UniqueConstraint("advisory_record_id", "package_record_id", name="uq_advisory_package_link"),
    )

    id = Column(Integer, primary_key=True, index=True)
    advisory_record_id = Column(Integer, ForeignKey("advisory_records.id", ondelete="CASCADE"), nullable=False, index=True)
    package_record_id = Column(Integer, ForeignKey("package_records.id", ondelete="CASCADE"), nullable=False, index=True)
    package_role = Column(String(80), default="affected")
    purl = Column(String(500))
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class PackageRecord(Base):
    """Package or ecosystem entity used for applicability matching."""

    __tablename__ = "package_records"
    __table_args__ = (UniqueConstraint("ecosystem", "name", name="uq_package_ecosystem_name"),)

    id = Column(Integer, primary_key=True, index=True)
    ecosystem = Column(String(80), nullable=False, index=True)
    name = Column(String(200), nullable=False, index=True)
    purl = Column(String(500))
    description = Column(Text)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class ProductRecord(Base):
    """Enterprise software product record."""

    __tablename__ = "product_records"
    __table_args__ = (UniqueConstraint("vendor", "name", name="uq_product_vendor_name"),)

    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String(120), nullable=False, index=True)
    name = Column(String(200), nullable=False, index=True)
    package_record_id = Column(Integer, ForeignKey("package_records.id", ondelete="SET NULL"), index=True)
    description = Column(Text)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class VersionRange(Base):
    """Version-range normalization for affected products."""

    __tablename__ = "version_ranges"

    id = Column(Integer, primary_key=True, index=True)
    advisory_record_id = Column(Integer, ForeignKey("advisory_records.id", ondelete="CASCADE"), index=True)
    product_id = Column(Integer, ForeignKey("product_records.id", ondelete="CASCADE"), index=True)
    package_record_id = Column(Integer, ForeignKey("package_records.id", ondelete="SET NULL"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    range_type = Column(String(80))
    source_label = Column(String(120))
    version_start = Column(String(120))
    version_end = Column(String(120))
    fixed_version = Column(String(120))
    is_inclusive_start = Column(Boolean, default=True, nullable=False)
    is_inclusive_end = Column(Boolean, default=True, nullable=False)
    normalized_bounds = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class ExploitSignal(Base):
    """Exploitability hints aggregated for candidate scoring."""

    __tablename__ = "exploit_signals"
    __table_args__ = (UniqueConstraint("cve_id", "signal_type", name="uq_exploit_signal_cve_type"),)

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    signal_type = Column(String(60), nullable=False)
    signal_value = Column(Float, default=0.0)
    confidence = Column(Float, default=0.5)
    source_label = Column(String(120))
    source_url = Column(Text)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AnalystIdentity(Base):
    """Analyst identity used for attribution and review."""

    __tablename__ = "analyst_identities"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_analyst_tenant_email"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)
    handle = Column(String(120))
    role = Column(String(80), default="researcher")
    public_key_fingerprint = Column(String(255))
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class TenantSigningKey(Base):
    """Tenant-scoped signing key metadata for attestations."""

    __tablename__ = "tenant_signing_keys"
    __table_args__ = (UniqueConstraint("tenant_id", "key_name", name="uq_signing_key_tenant_name"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    key_name = Column(String(120), nullable=False, default="default")
    algorithm = Column(String(50), nullable=False, default="ed25519")
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String(255), nullable=False, index=True)
    storage_backend = Column(String(80), nullable=False, default="local-file")
    key_path = Column(String(500))
    rotated_at = Column(DateTime)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class WorkstationFingerprint(Base):
    """Host workstation fingerprints for chain-of-custody."""

    __tablename__ = "workstation_fingerprints"
    __table_args__ = (UniqueConstraint("tenant_id", "fingerprint", name="uq_workstation_tenant_fingerprint"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(200))
    os_family = Column(String(120))
    architecture = Column(String(80))
    fingerprint = Column(String(255), nullable=False, index=True)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class RawKnowledgeSource(Base):
    """Raw source preservation layer for advisories, notes, and feed payloads."""

    __tablename__ = "raw_knowledge_sources"
    __table_args__ = (UniqueConstraint("tenant_id", "source_kind", "source_key", name="uq_raw_source_tenant_kind_key"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    source_kind = Column(String(80), nullable=False, index=True)
    source_key = Column(String(255), nullable=False, index=True)
    source_label = Column(String(120))
    source_url = Column(Text)
    raw_payload = Column(JSON, default=dict)
    raw_body = Column(Text)
    sha256 = Column(String(128), nullable=False, index=True)
    collected_at = Column(DateTime, default=utc_now, nullable=False)
    provenance = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class KnowledgeWikiPage(Base):
    """Curated wiki layer linked back to raw-source records."""

    __tablename__ = "knowledge_wiki_pages"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    page_type = Column(String(80), nullable=False, default="wiki")
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    source_ref_ids = Column(JSON, default=list)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class ResearchCandidate(Base):
    """Validation-oriented research candidate derived from CVE + applicability context."""

    __tablename__ = "research_candidates"
    __table_args__ = (UniqueConstraint("tenant_id", "cve_id", name="uq_candidate_tenant_cve"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    package_record_id = Column(Integer, ForeignKey("package_records.id", ondelete="SET NULL"), index=True)
    product_record_id = Column(Integer, ForeignKey("product_records.id", ondelete="SET NULL"), index=True)

    title = Column(String(255), nullable=False)
    summary = Column(Text)
    candidate_score = Column(Float, default=0.0)
    status = Column(String(50), default="queued", index=True)
    status_reason = Column(Text)
    status_changed_at = Column(DateTime)
    status_changed_by = Column(String(200))
    merged_into_id = Column(Integer, ForeignKey("research_candidates.id", ondelete="SET NULL"), index=True)
    assignment_state = Column(String(50), default="unassigned")
    assigned_to = Column(String(200))
    assigned_by = Column(String(200))
    assigned_at = Column(DateTime)
    package_name = Column(String(200))
    product_name = Column(String(200))
    distro_hint = Column(String(120), default="kali")
    environment_fit = Column(String(50), default="local-lab")
    patch_available = Column(Boolean, default=False, nullable=False)
    linux_reproducibility_confidence = Column(Float, default=0.5)
    observability_score = Column(Float, default=0.5)
    explainability = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    cve = relationship("CVE")
    merged_into = relationship("ResearchCandidate", remote_side="ResearchCandidate.id")


class LabTemplate(Base):
    """Reusable runtime template metadata."""

    __tablename__ = "lab_templates"
    __table_args__ = (UniqueConstraint("provider", "name", name="uq_lab_template_provider_name"),)

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(80), nullable=False, default="docker_kali")
    name = Column(String(200), nullable=False)
    distro = Column(String(120), nullable=False, default="kali")
    base_image = Column(String(255), nullable=False)
    image_digest = Column(String(255))
    is_hardened = Column(Boolean, default=True, nullable=False)
    network_mode = Column(String(50), default="isolated")
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class LabRecipe(Base):
    """Versioned recipe root for validation runs."""

    __tablename__ = "lab_recipes"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_id = Column(Integer, ForeignKey("research_candidates.id", ondelete="SET NULL"), index=True)
    template_id = Column(Integer, ForeignKey("lab_templates.id", ondelete="SET NULL"), index=True)

    name = Column(String(255), nullable=False)
    objective = Column(Text)
    provider = Column(String(80), default="docker_kali")
    status = Column(String(50), default="draft")
    created_by = Column(String(200))
    current_revision_number = Column(Integer, default=0)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class RecipeRevision(Base):
    """Immutable recipe revision."""

    __tablename__ = "recipe_revisions"
    __table_args__ = (UniqueConstraint("recipe_id", "revision_number", name="uq_recipe_revision_number"),)

    id = Column(Integer, primary_key=True, index=True)
    recipe_id = Column(Integer, ForeignKey("lab_recipes.id", ondelete="CASCADE"), nullable=False, index=True)

    revision_number = Column(Integer, nullable=False)
    approval_state = Column(String(50), default="draft")
    risk_level = Column(String(50), default="standard")
    requires_acknowledgement = Column(Boolean, default=False, nullable=False)
    approved_by = Column(String(200))
    approved_at = Column(DateTime)
    signed_digest = Column(String(128))
    content = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class LabRun(Base):
    """Validation run record."""

    __tablename__ = "lab_runs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    recipe_revision_id = Column(Integer, ForeignKey("recipe_revisions.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_id = Column(Integer, ForeignKey("research_candidates.id", ondelete="SET NULL"), index=True)
    analyst_id = Column(Integer, ForeignKey("analyst_identities.id", ondelete="SET NULL"), index=True)
    workstation_fingerprint_id = Column(Integer, ForeignKey("workstation_fingerprints.id", ondelete="SET NULL"), index=True)

    provider = Column(String(80), default="docker_kali")
    provider_run_ref = Column(String(120), index=True)
    launch_mode = Column(String(40), default="simulated")
    state = Column(String(50), default="planned", index=True)
    guest_image = Column(String(255))
    image_digest = Column(String(255))
    network_mode = Column(String(80), default="isolated")
    workspace_path = Column(String(255))
    run_transcript = Column(Text)
    manifest = Column(JSON, default=dict)
    requires_acknowledgement = Column(Boolean, default=False, nullable=False)
    acknowledged_by = Column(String(200))
    acknowledged_at = Column(DateTime)
    started_at = Column(DateTime)
    ended_at = Column(DateTime)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class RunEvent(Base):
    """Structured run timeline events."""

    __tablename__ = "run_events"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("lab_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(80), nullable=False, index=True)
    level = Column(String(30), default="info")
    message = Column(Text, nullable=False)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class EvidenceArtifact(Base):
    """Evidence captured from a run."""

    __tablename__ = "evidence_artifacts"
    __table_args__ = (Index("ix_evidence_artifacts_run_kind", "run_id", "artifact_kind"),)

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("lab_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_kind = Column(String(80), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text)
    storage_path = Column(String(255))
    sha256 = Column(String(128), index=True)
    content_type = Column(String(120))
    byte_size = Column(Integer)
    capture_started_at = Column(DateTime)
    capture_ended_at = Column(DateTime)
    collector_name = Column(String(80))
    collector_version = Column(String(40))
    truncated = Column(Boolean, default=False)
    reviewed_state = Column(String(50), default="captured")
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class DetectionArtifact(Base):
    """Generated defensive detection artifacts."""

    __tablename__ = "detection_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("lab_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_artifact_id = Column(Integer, ForeignKey("evidence_artifacts.id", ondelete="SET NULL"), index=True)
    artifact_type = Column(String(80), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    rule_body = Column(Text, nullable=False)
    status = Column(String(50), default="draft")
    sha256 = Column(String(128), index=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class MitigationArtifact(Base):
    """Generated mitigation and workaround guidance."""

    __tablename__ = "mitigation_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("lab_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(80), default="mitigation_checklist")
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(String(50), default="draft")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AttestationRecord(Base):
    """Signed attestation records for runs and exports."""

    __tablename__ = "attestation_records"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("lab_runs.id", ondelete="CASCADE"), index=True)
    disclosure_bundle_id = Column(Integer, ForeignKey("disclosure_bundles.id", ondelete="CASCADE"), index=True)
    subject_type = Column(String(80), nullable=False)
    subject_id = Column(String(120), nullable=False)
    sha256 = Column(String(128), nullable=False)
    signature = Column(String(255), nullable=False)
    signer = Column(String(200), nullable=False)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class ContributionLedgerEntry(Base):
    """Analyst credit and provenance ledger."""

    __tablename__ = "contribution_ledger_entries"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id = Column(Integer, ForeignKey("analyst_identities.id", ondelete="SET NULL"), index=True)
    entry_type = Column(String(80), nullable=False)
    object_type = Column(String(80), nullable=False)
    object_id = Column(String(120), nullable=False)
    score = Column(Float, default=0.0)
    note = Column(Text)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class ReviewDecision(Base):
    """Review and approval decisions for evidence, artifacts, and bundles."""

    __tablename__ = "review_decisions"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    reviewer_name = Column(String(200), nullable=False)
    target_type = Column(String(80), nullable=False)
    target_id = Column(String(120), nullable=False)
    decision = Column(String(50), nullable=False)
    rationale = Column(Text)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class DisclosureBundle(Base):
    """Exportable disclosure or report bundle."""

    __tablename__ = "disclosure_bundles"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("lab_runs.id", ondelete="SET NULL"), index=True)
    bundle_type = Column(String(80), nullable=False, default="vendor_disclosure")
    title = Column(String(255), nullable=False)
    status = Column(String(50), default="draft")
    manifest = Column(JSON, default=dict)
    sha256 = Column(String(128), index=True)
    signed_by = Column(String(200))
    created_at = Column(DateTime, default=utc_now)


class CandidateScoreRecalculationRun(Base):
    """Persisted audit record for candidate score recalculation/backfill operations."""

    __tablename__ = "candidate_score_recalculation_runs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by = Column(String(200), nullable=False)
    status = Column(String(50), default="completed", nullable=False)
    dry_run = Column(Boolean, default=True, nullable=False)
    reason = Column(Text)
    filters = Column(JSON, default=dict)
    summary = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AutonomousAgentRun(Base):
    """Durable record of a V4 autonomous-agent ReAct run.

    Replaces the prior in-memory `AutonomousAgent._runs` list so runs survive
    process restarts and are visible across replicas. The ``steps`` column
    stores the full AgentStep sequence (thought, tool, tool_input,
    tool_output, citations) as JSON so reviewers can replay the trajectory
    without joining a separate steps table.
    """

    __tablename__ = "autonomous_agent_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "run_id", name="uq_autonomous_agent_run_tenant_runid"),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(String(120), nullable=False, index=True)
    goal = Column(Text, nullable=False)
    status = Column(String(40), nullable=False, index=True)  # completed | denied | failed
    reason = Column(Text)
    actor = Column(String(200))
    case_id = Column(Integer, index=True)  # soft FK; case may be deleted, run history persists
    final_summary = Column(Text)
    steps = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    completed_at = Column(DateTime)
