"""Operational models: feed sync state and patch planning metadata."""

from datetime import datetime

from sqlalchemy import (
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
from app.core.time import utc_now


class FeedSyncState(Base):
    """Tracks incremental sync state for external feeds."""

    __tablename__ = "feed_sync_state"
    __table_args__ = (UniqueConstraint("source", name="uq_feed_sync_source"),)

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100), nullable=False, index=True)  # e.g., NVD, EXPLOIT_DB

    last_run_at = Column(DateTime)
    last_success_at = Column(DateTime)
    cursor = Column(String(200))  # ISO timestamp or external cursor token
    status = Column(String(30), default="idle")  # idle, running, success, failed
    last_error = Column(Text)

    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    created_at = Column(DateTime, default=utc_now)


class PatchDependency(Base):
    """Directed dependency or conflict between patches."""

    __tablename__ = "patch_dependencies"
    __table_args__ = (UniqueConstraint("patch_id", "depends_on_patch_id", "kind", name="uq_patch_dependency"),)

    id = Column(Integer, primary_key=True, index=True)
    patch_id = Column(String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), nullable=False, index=True)
    depends_on_patch_id = Column(String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(20), default="requires")  # requires | conflicts
    reason = Column(Text)

    created_at = Column(DateTime, default=utc_now)


class PatchPlan(Base):
    """Persisted patch schedule proposal."""

    __tablename__ = "patch_plans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    status = Column(String(30), default="proposed")  # proposed, approved, applied, cancelled

    constraints = Column(JSON)
    objective = Column(String(50), default="max_risk_reduction")
    notes = Column(Text)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    items = relationship("PatchPlanItem", back_populates="plan", cascade="all, delete-orphan")


class PatchPlanItem(Base):
    """Patch entry within a plan."""

    __tablename__ = "patch_plan_items"
    __table_args__ = (UniqueConstraint("plan_id", "patch_id", name="uq_plan_patch"),)

    id = Column(Integer, primary_key=True, index=True)
    plan_id = Column(Integer, ForeignKey("patch_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    patch_id = Column(String(120), ForeignKey("patches.patch_id", ondelete="CASCADE"), nullable=False, index=True)

    window = Column(String(50))
    decision = Column(String(30))  # PATCH_NOW, SCHEDULE, DEFER
    expected_risk_reduction = Column(Float)
    estimated_downtime_minutes = Column(Integer, default=0)
    sort_order = Column(Integer, default=0)

    created_at = Column(DateTime, default=utc_now)

    plan = relationship("PatchPlan", back_populates="items")


class FeedSyncRun(Base):
    """Historical record of each feed sync execution."""

    __tablename__ = "feed_sync_runs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(100), nullable=False, index=True)
    status = Column(String(30), nullable=False)  # running, success, failed
    started_at = Column(DateTime)
    ended_at = Column(DateTime)
    items_fetched = Column(Integer, default=0)
    items_new = Column(Integer, default=0)
    items_updated = Column(Integer, default=0)
    error_summary = Column(Text, nullable=True)
    raw_payload_hash = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utc_now)
