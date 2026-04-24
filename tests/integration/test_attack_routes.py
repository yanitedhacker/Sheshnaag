"""Integration tests for V4 ATT&CK mapping and coverage routes."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.attack_routes import router as attack_router
from app.core.database import Base, get_sync_session
from app.models.malware_lab import AnalysisCase, BehaviorFinding
from app.models.sheshnaag import LabRecipe, LabRun, RecipeRevision
from app.models.v2 import Tenant
from app.services.attack_mapper import AttackMapper


engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_sync_session():
    session = TestingSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


test_app = FastAPI()
test_app.include_router(attack_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
client = TestClient(test_app)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        tenant = Tenant(slug="attack-private", name="Attack Private")
        session.add(tenant)
        session.flush()
        recipe = LabRecipe(
            tenant_id=tenant.id,
            name="ATT&CK recipe",
            objective="Map findings",
            provider="docker_kali",
            created_by="Analyst",
            current_revision_number=1,
        )
        session.add(recipe)
        session.flush()
        revision = RecipeRevision(recipe_id=recipe.id, revision_number=1, approval_state="approved", content={})
        session.add(revision)
        session.flush()
        run = LabRun(tenant_id=tenant.id, recipe_revision_id=revision.id, provider="docker_kali", state="completed")
        case = AnalysisCase(
            tenant_id=tenant.id,
            title="ATT&CK case",
            analyst_name="Analyst",
            specimen_ids=[],
        )
        session.add_all([run, case])
        session.flush()
        session.add_all(
            [
                BehaviorFinding(
                    tenant_id=tenant.id,
                    analysis_case_id=case.id,
                    run_id=run.id,
                    finding_type="memory:windows.malfind",
                    title="malfind",
                    severity="high",
                    confidence=0.93,
                    payload={"source": "volatility", "plugin": "windows.malfind"},
                ),
                BehaviorFinding(
                    tenant_id=tenant.id,
                    analysis_case_id=case.id,
                    run_id=run.id,
                    finding_type="ebpf:execve",
                    title="shell exec",
                    severity="medium",
                    confidence=0.78,
                    payload={"source": "ebpf", "raw": {"syscall": "execve", "command": "/bin/bash -lc id"}},
                ),
                BehaviorFinding(
                    tenant_id=tenant.id,
                    analysis_case_id=case.id,
                    run_id=run.id,
                    finding_type="suspicious_dns",
                    title="Beacon observed",
                    severity="medium",
                    confidence=0.7,
                    payload={"source": "zeek"},
                ),
            ]
        )
        session.flush()
        AttackMapper(session).map_run(run)
        session.commit()
    finally:
        session.close()


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def test_map_run_persists_attack_techniques():
    session = TestingSession()
    try:
        rows = session.query(BehaviorFinding).all()
        assert len(rows) == 3
        assert all(row.payload.get("attack_techniques") for row in rows)
    finally:
        session.close()


def test_attack_coverage_route_groups_by_tactic_and_technique():
    response = client.get("/api/v4/attack/coverage", params={"tenant_slug": "attack-private"})
    assert response.status_code == 200
    body = response.json()
    assert body["tactics"]["Defense Evasion"]["techniques"]["T1055.012"]["count"] == 1
    assert body["tactics"]["Execution"]["techniques"]["T1059.004"]["count"] == 1
    assert body["tactics"]["Command and Control"]["techniques"]["T1071.004"]["count"] == 1


def test_attack_technique_route_lists_contributing_findings():
    response = client.get("/api/v4/attack/technique/T1055.012", params={"tenant_slug": "attack-private"})
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["items"][0]["finding_type"] == "memory:windows.malfind"
