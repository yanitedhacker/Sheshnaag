"""Tests for bounded, tenant-scoped autonomous replay."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.sheshnaag import AutonomousAgentRun
from app.models.v2 import Tenant
from app.services.autonomous_agent import AutonomousAgent


def test_autonomous_replay_has_hard_service_limit_and_tenant_scope():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    tenant = Tenant(slug="replay-a", name="Replay A")
    other = Tenant(slug="replay-b", name="Replay B")
    session.add_all([tenant, other])
    session.flush()
    session.add_all(
        [
            AutonomousAgentRun(
                tenant_id=tenant.id,
                run_id=f"agent_{index:04d}",
                goal="Review bounded evidence",
                status="completed",
                steps=[],
                disposition={"code": "completed_read_only"},
            )
            for index in range(105)
        ]
        + [
            AutonomousAgentRun(
                tenant_id=other.id,
                run_id="agent_other",
                goal="Other tenant",
                status="completed",
                steps=[],
                disposition={"code": "completed_read_only"},
            )
        ]
    )
    session.commit()

    rows = AutonomousAgent(session).list_runs(tenant=tenant, limit=1000)

    assert len(rows) == 100
    assert all(row["goal"] == "Review bounded evidence" for row in rows)
    assert all(row["disposition"]["code"] == "completed_read_only" for row in rows)
