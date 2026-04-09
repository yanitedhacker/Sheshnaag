"""Evidence pipeline: partial failure isolation and timeline metadata."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.tenancy import get_or_create_demo_tenant
from app.lab.interfaces import Collector
from app.services.demo_seed_service import DemoSeedService
from app.services.sheshnaag_service import SheshnaagService


class ExplodingCollector(Collector):
    collector_name = "exploding"
    collector_version = "0.0.1"

    def collect(self, *, run_context, provider_result):
        raise RuntimeError("boom")


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


@pytest.mark.integration
def test_collector_failure_does_not_block_other_evidence(monkeypatch):
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()
    tenant = get_or_create_demo_tenant(session)
    service = SheshnaagService(session)

    import app.services.sheshnaag_service as sns

    real_instantiate = sns.instantiate_collectors

    def mixed(names):
        out = real_instantiate([n for n in names if n != "exploding"])
        if "exploding" in names:
            out.insert(0, ExplodingCollector())
        return out

    monkeypatch.setattr(sns, "instantiate_collectors", mixed)

    candidates = service.list_candidates(tenant, limit=1)
    candidate = candidates["items"][0]
    service.assign_candidate(tenant, candidate_id=candidate["id"], analyst_name="Tester")
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Collector failure test",
        objective="test",
        created_by="Tester",
        content={
            "command": ["sleep", "1"],
            "risk_level": "standard",
            "network_policy": {"allow_egress_hosts": []},
            "collectors": ["exploding", "process_tree"],
        },
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead")
    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Tester",
        workstation={"hostname": "h", "os_family": "linux", "architecture": "x86_64", "fingerprint": "fp"},
        launch_mode="simulated",
    )
    evidence = service.list_evidence(tenant, run_id=run["id"])
    kinds = {e["artifact_kind"] for e in evidence["items"]}
    assert "exploding" in kinds
    assert "process_tree" in kinds
    err_rows = [e for e in evidence["items"] if e["payload"].get("error")]
    assert err_rows


@pytest.mark.integration
def test_get_run_includes_evidence_timeline():
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()
    tenant = get_or_create_demo_tenant(session)
    service = SheshnaagService(session)
    candidates = service.list_candidates(tenant, limit=1)
    candidate = candidates["items"][0]
    service.assign_candidate(tenant, candidate_id=candidate["id"], analyst_name="Tester")
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Timeline test",
        objective="test",
        created_by="Tester",
        content={
            "command": ["sleep", "1"],
            "risk_level": "standard",
            "network_policy": {"allow_egress_hosts": []},
            "collectors": ["process_tree"],
        },
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead")
    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Tester",
        workstation={"hostname": "h", "os_family": "linux", "architecture": "x86_64", "fingerprint": "fp"},
        launch_mode="simulated",
    )
    detail = service.get_run(tenant, run["id"])
    assert "evidence_timeline" in detail
    assert "items" in detail["evidence_timeline"]
    assert len(detail["evidence_timeline"]["items"]) >= 1
    assert "runtime_findings_summary" in detail
    assert "count" in detail["runtime_findings_summary"]
    assert "items" in detail["runtime_findings_summary"]


@pytest.mark.integration
def test_evidence_payload_includes_service_layer_collect_timing():
    """WS7-T7: service layer records wall time for each collect() invocation."""
    session = make_session()
    DemoSeedService(session).seed()
    session.commit()
    tenant = get_or_create_demo_tenant(session)
    service = SheshnaagService(session)
    candidates = service.list_candidates(tenant, limit=1)
    candidate = candidates["items"][0]
    service.assign_candidate(tenant, candidate_id=candidate["id"], analyst_name="Tester")
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Service layer timing",
        objective="test",
        created_by="Tester",
        content={
            "command": ["sleep", "1"],
            "risk_level": "standard",
            "network_policy": {"allow_egress_hosts": []},
            "collectors": ["process_tree", "package_inventory"],
        },
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead")
    run = service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Tester",
        workstation={"hostname": "h", "os_family": "linux", "architecture": "x86_64", "fingerprint": "fp"},
        launch_mode="simulated",
    )
    evidence = service.list_evidence(tenant, run_id=run["id"])
    for item in evidence["items"]:
        sl = item["payload"].get("service_layer")
        assert isinstance(sl, dict), f"missing service_layer on {item['artifact_kind']}"
        assert "collect_wall_ms" in sl
        assert sl["collect_wall_ms"] >= 0
