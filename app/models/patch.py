"""Patch intelligence models (patch-first remediation layer)."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.time import utc_now
from app.core.time import utc_now


# Many-to-many association between patches and CVEs.
patch_cves = Table(
    "patch_cves",
    Base.metadata,
    Column("patch_id", String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), primary_key=True),
    Column("cve_id", Integer, ForeignKey("cves.id", ondelete="CASCADE"), primary_key=True),
)


class Patch(Base):
    """
    Patch is a first-class remediation entity.

    Key principle: a patch can remediate multiple CVEs and a CVE can have multiple patches.
    """

    __tablename__ = "patches"

    patch_id = Column(String(120), primary_key=True)  # e.g., PATCH-APACHE-2.4.59

    vendor = Column(String(100), nullable=False, index=True)
    affected_software = Column(String(200), nullable=False, index=True)

    # Operational cost signals
    requires_reboot = Column(Boolean, default=False, nullable=False)
    estimated_downtime_minutes = Column(Integer, default=0, nullable=False)
    rollback_complexity = Column(Float, default=0.5, nullable=False)  # normalized [0,1]
    historical_failure_rate = Column(Float, default=0.0, nullable=False)  # normalized [0,1]
    change_risk_score = Column(Float, default=0.3, nullable=False)  # normalized [0,1]
    reboot_group = Column(String(50))  # optional grouping to avoid simultaneous reboots

    released_at = Column(DateTime)

    # Future-proofing for vendor feed ingestion
    source = Column(String(50), default="manual")  # manual, vendor_feed, advisory_scrape, etc.
    advisory_url = Column(Text)
    vendor_advisory_id = Column(String(100))

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    cves = relationship("CVE", secondary=patch_cves, back_populates="patches")
    asset_mappings = relationship("AssetPatch", back_populates="patch", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Patch {self.patch_id} vendor={self.vendor} software={self.affected_software}>"


class AssetPatch(Base):
    """Mapping between assets and patches, including scheduling metadata."""

    __tablename__ = "asset_patches"
    __table_args__ = (
        UniqueConstraint("asset_id", "patch_id", name="uq_asset_patch"),
    )

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    patch_id = Column(String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), nullable=False, index=True)

    # Context
    environment = Column(String(50))  # optional override for scheduling context
    maintenance_window = Column(String(50))  # e.g., "02:00–04:00"

    # Lightweight workflow status (optional, keeps API forward-compatible)
    status = Column(String(30), default="recommended")  # recommended, scheduled, applied, deferred

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    asset = relationship("Asset", back_populates="patches")
    patch = relationship("Patch", back_populates="asset_mappings")

    def __repr__(self):
        return f"<AssetPatch asset={self.asset_id} patch={self.patch_id}>"
