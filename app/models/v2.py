"""V2 domain models for tenancy, threat intelligence, graphing, and simulations."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.time import utc_now


class Tenant(Base):
    """Tenant/workspace boundary for public demo and private orgs."""

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(120), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    is_demo = Column(Boolean, default=False, nullable=False)
    is_read_only = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    assets = relationship("Asset", back_populates="tenant")
    services = relationship("Service", back_populates="tenant", cascade="all, delete-orphan")
    software_components = relationship("SoftwareComponent", back_populates="tenant", cascade="all, delete-orphan")
    network_exposures = relationship("NetworkExposure", back_populates="tenant", cascade="all, delete-orphan")
    identity_principals = relationship("IdentityPrincipal", back_populates="tenant", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceItem", back_populates="tenant", cascade="all, delete-orphan")
    graph_nodes = relationship("ExposureGraphNode", back_populates="tenant", cascade="all, delete-orphan")
    graph_edges = relationship("ExposureGraphEdge", back_populates="tenant", cascade="all, delete-orphan")
    simulation_runs = relationship("SimulationRun", back_populates="tenant", cascade="all, delete-orphan")
    memberships = relationship("TenantMembership", back_populates="tenant", cascade="all, delete-orphan")
    patch_approvals = relationship("PatchApproval", back_populates="tenant", cascade="all, delete-orphan")
    audit_events = relationship("DecisionAuditEvent", back_populates="tenant", cascade="all, delete-orphan")


class Service(Base):
    """Tenant-scoped application or infrastructure service."""

    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_service_tenant_name"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    upstream_service_id = Column(Integer, ForeignKey("services.id", ondelete="SET NULL"), index=True)

    name = Column(String(200), nullable=False)
    slug = Column(String(200), index=True)
    service_type = Column(String(50), default="application")
    environment = Column(String(50))
    owner = Column(String(100))
    business_criticality = Column(String(20), default="medium")
    internet_exposed = Column(Boolean, default=False, nullable=False)
    description = Column(Text)
    meta = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="services")
    asset = relationship("Asset", back_populates="services")
    upstream_service = relationship("Service", remote_side=[id])
    software_links = relationship("AssetSoftware", back_populates="service", cascade="all, delete-orphan")
    network_exposures = relationship("NetworkExposure", back_populates="service", cascade="all, delete-orphan")


class SoftwareComponent(Base):
    """Normalized software inventory entry."""

    __tablename__ = "software_components"
    __table_args__ = (UniqueConstraint("tenant_id", "name", "version", "vendor", name="uq_component_identity"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)

    vendor = Column(String(120))
    name = Column(String(200), nullable=False, index=True)
    version = Column(String(120))
    purl = Column(String(500))
    cpe = Column(String(500))
    component_type = Column(String(50), default="application")
    meta = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="software_components")
    asset_links = relationship("AssetSoftware", back_populates="software_component", cascade="all, delete-orphan")
    vex_statements = relationship("VexStatement", back_populates="software_component", cascade="all, delete-orphan")


class AssetSoftware(Base):
    """Join table between assets and normalized software components."""

    __tablename__ = "asset_software"
    __table_args__ = (
        UniqueConstraint("asset_id", "software_component_id", "service_id", name="uq_asset_software_scope"),
    )

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    software_component_id = Column(Integer, ForeignKey("software_components.id", ondelete="CASCADE"), nullable=False, index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="SET NULL"), index=True)

    discovered_by = Column(String(50), default="manual")
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    asset = relationship("Asset", back_populates="software_components")
    software_component = relationship("SoftwareComponent", back_populates="asset_links")
    service = relationship("Service", back_populates="software_links")


class NetworkExposure(Base):
    """Network exposure facts used by the attack graph and risk engine."""

    __tablename__ = "network_exposures"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="SET NULL"), index=True)

    hostname = Column(String(200))
    protocol = Column(String(20), default="tcp")
    port = Column(Integer)
    exposure_type = Column(String(50), default="public")
    is_public = Column(Boolean, default=True, nullable=False)
    meta = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="network_exposures")
    asset = relationship("Asset", back_populates="network_exposures")
    service = relationship("Service", back_populates="network_exposures")


class IdentityPrincipal(Base):
    """Identity and privilege context for lateral movement reasoning."""

    __tablename__ = "identity_principals"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), index=True)

    name = Column(String(200), nullable=False)
    principal_type = Column(String(50), default="service_account")
    privilege_level = Column(String(50), default="user")
    can_admin = Column(Boolean, default=False, nullable=False)
    can_lateral_move = Column(Boolean, default=False, nullable=False)
    meta = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="identity_principals")
    asset = relationship("Asset", back_populates="identity_principals")


class EvidenceItem(Base):
    """Evidence or citation that can support a recommendation."""

    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    patch_id = Column(String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="CASCADE"), index=True)
    software_component_id = Column(Integer, ForeignKey("software_components.id", ondelete="CASCADE"), index=True)
    technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), index=True)

    evidence_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    summary = Column(Text)
    source_label = Column(String(120))
    source_url = Column(Text)
    citation_key = Column(String(120), index=True)
    meta = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="evidence_items")


class KEVEntry(Base):
    """CISA KEV enrichment for CVEs."""

    __tablename__ = "kev_entries"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_kev_cve"),)

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), nullable=False, index=True)
    vendor_project = Column(String(200))
    product = Column(String(200))
    short_description = Column(Text)
    due_date = Column(DateTime)
    added_date = Column(DateTime)
    known_ransomware_use = Column(String(20))
    source_url = Column(Text)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class EPSSSnapshot(Base):
    """Daily EPSS score snapshots."""

    __tablename__ = "epss_snapshots"
    __table_args__ = (UniqueConstraint("cve_id", "scored_at", name="uq_epss_snapshot"),)

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), nullable=False, index=True)
    score = Column(Float, nullable=False)
    percentile = Column(Float)
    scored_at = Column(DateTime, nullable=False, index=True)
    source_url = Column(Text)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class AttackTechnique(Base):
    """MITRE ATT&CK technique metadata."""

    __tablename__ = "attack_techniques"
    __table_args__ = (UniqueConstraint("external_id", name="uq_attack_external_id"),)

    id = Column(Integer, primary_key=True, index=True)
    external_id = Column(String(50), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    tactic = Column(String(120))
    description = Column(Text)
    source_url = Column(Text)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class CVEAttackTechnique(Base):
    """Mapping between CVEs and ATT&CK techniques used for explanation."""

    __tablename__ = "cve_attack_techniques"
    __table_args__ = (
        UniqueConstraint("cve_id", "technique_id", name="uq_cve_attack_technique"),
    )

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False, index=True)
    rationale = Column(Text)
    confidence = Column(Float, default=0.6)
    created_at = Column(DateTime, default=utc_now)

    cve = relationship("CVE")
    technique = relationship("AttackTechnique")


class KnowledgeDocument(Base):
    """Source-backed documents for citations and future retrieval."""

    __tablename__ = "knowledge_documents"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), index=True)

    document_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    source_label = Column(String(120))
    source_url = Column(Text)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    chunks = relationship("KnowledgeChunk", back_populates="document", cascade="all, delete-orphan")


class ExposureGraphNode(Base):
    """Persisted graph node for attack-path drill-downs."""

    __tablename__ = "exposure_graph_nodes"
    __table_args__ = (UniqueConstraint("tenant_id", "node_type", "node_key", name="uq_graph_node_key"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    node_type = Column(String(50), nullable=False, index=True)
    node_key = Column(String(255), nullable=False, index=True)
    label = Column(String(255), nullable=False)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="graph_nodes")


class ExposureGraphEdge(Base):
    """Persisted graph edge for attack-path drill-downs."""

    __tablename__ = "exposure_graph_edges"
    __table_args__ = (
        UniqueConstraint("tenant_id", "from_node_id", "to_node_id", "edge_type", name="uq_graph_edge_key"),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    from_node_id = Column(Integer, ForeignKey("exposure_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    to_node_id = Column(Integer, ForeignKey("exposure_graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    edge_type = Column(String(50), nullable=False, index=True)
    weight = Column(Float, default=1.0)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="graph_edges")
    from_node = relationship("ExposureGraphNode", foreign_keys=[from_node_id])
    to_node = relationship("ExposureGraphNode", foreign_keys=[to_node_id])


class SimulationRun(Base):
    """Saved risk simulation snapshot."""

    __tablename__ = "simulation_runs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    status = Column(String(30), default="completed", nullable=False)
    parameters = Column(JSON, default=dict, nullable=False)
    before_snapshot = Column(JSON, default=dict, nullable=False)
    after_snapshot = Column(JSON, default=dict, nullable=False)
    summary = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="simulation_runs")


class AnalystFeedback(Base):
    """Captured analyst feedback for trust and future tuning."""

    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    action_id = Column(String(255), nullable=False, index=True)
    feedback_type = Column(String(50), nullable=False)
    note = Column(Text)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)


class VexStatement(Base):
    """Imported VEX statement linked to tenant software inventory."""

    __tablename__ = "vex_statements"
    __table_args__ = (
        UniqueConstraint("tenant_id", "software_component_id", "cve_id", "status", name="uq_vex_statement_identity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    software_component_id = Column(Integer, ForeignKey("software_components.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(20), nullable=False, index=True)
    status = Column(String(50), nullable=False)
    justification = Column(Text)
    source_url = Column(Text)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    software_component = relationship("SoftwareComponent", back_populates="vex_statements")


class TenantUser(Base):
    """Workspace user identity used for private tenant onboarding and RBAC."""

    __tablename__ = "tenant_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(200))
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_system = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    memberships = relationship("TenantMembership", back_populates="user", cascade="all, delete-orphan")
    audit_events = relationship("DecisionAuditEvent", back_populates="actor")


class TenantMembership(Base):
    """Tenant-scoped role binding for RBAC."""

    __tablename__ = "tenant_memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_tenant_membership"),)

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("tenant_users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(50), default="viewer", nullable=False)
    scopes = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    tenant = relationship("Tenant", back_populates="memberships")
    user = relationship("TenantUser", back_populates="memberships")


class KnowledgeChunk(Base):
    """Chunked knowledge index for grounded retrieval and future vector search."""

    __tablename__ = "knowledge_chunks"
    __table_args__ = (UniqueConstraint("document_id", "chunk_index", name="uq_knowledge_chunk"),)

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("knowledge_documents.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), index=True)
    chunk_index = Column(Integer, nullable=False)
    document_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    search_text = Column(Text, nullable=False)
    source_label = Column(String(120))
    source_url = Column(Text)
    embedding_model = Column(String(120))
    embedding_vector = Column(JSON, default=list)
    meta = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    document = relationship("KnowledgeDocument", back_populates="chunks")


class PatchApproval(Base):
    """Change-window approvals and sign-offs for remediation actions."""

    __tablename__ = "patch_approvals"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    patch_id = Column(String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), nullable=False, index=True)
    action_id = Column(String(255), nullable=False, index=True)
    approval_type = Column(String(50), default="signoff", nullable=False)
    approval_state = Column(String(50), default="pending", nullable=False)
    maintenance_window = Column(String(120))
    decided_by = Column(String(255))
    note = Column(Text)
    meta = Column("metadata", JSON, default=dict)
    decided_at = Column(DateTime, default=utc_now)
    created_at = Column(DateTime, default=utc_now)

    tenant = relationship("Tenant", back_populates="patch_approvals")
    patch = relationship("Patch")


class DecisionAuditEvent(Base):
    """Append-only audit trail chained by hashes for visibility and integrity."""

    __tablename__ = "decision_audit_events"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_user_id = Column(Integer, ForeignKey("tenant_users.id", ondelete="SET NULL"), index=True)
    event_type = Column(String(80), nullable=False, index=True)
    entity_type = Column(String(80), nullable=False, index=True)
    entity_id = Column(String(255), nullable=False, index=True)
    summary = Column(String(255), nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    previous_hash = Column(String(64))
    event_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=utc_now)

    tenant = relationship("Tenant", back_populates="audit_events")
    actor = relationship("TenantUser", back_populates="audit_events")
