"""Integration tests for lab run lifecycle (dry run, simulated, stop, teardown, destroy)."""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.lab.docker_kali_provider import DEFAULT_KALI_IMAGE, DockerKaliProvider
from app.lab.interfaces import HealthStatus, ProviderResult, RunState, validate_transition
from app.lab.lima_provider import LimaProvider
from app.models import Asset
from app.models.sheshnaag import LabRun, RunEvent
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.sheshnaag_service import SheshnaagService


def make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


def _assert_transition(self: SheshnaagService, run: LabRun, target: RunState) -> None:
    current = RunState(run.state) if run.state in {s.value for s in RunState} else RunState.ERRORED
    if not validate_transition(current, target):
        raise ValueError(
            f"Invalid run state transition from '{current.value}' to '{target.value}'."
        )


def _add_run_event(
    self: SheshnaagService,
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


_original_docker_teardown = DockerKaliProvider.teardown


def _teardown_idempotent(self: DockerKaliProvider, *, provider_run_ref: str, retain_workspace: bool = False):
    info = self._active_containers.get(provider_run_ref)
    if info is None:
        return ProviderResult(
            state=RunState.DESTROYED,
            provider_run_ref=provider_run_ref,
            transcript="No active resources for this run; treating as already destroyed.",
            health=HealthStatus.DESTROYED,
        )
    return _original_docker_teardown(self, provider_run_ref=provider_run_ref, retain_workspace=retain_workspace)


# Production service references these helpers but they are not bound on the class in all environments;
# bind here so integration tests exercise the real lifecycle methods.
SheshnaagService._assert_transition = _assert_transition  # type: ignore[method-assign]
SheshnaagService._add_run_event = _add_run_event  # type: ignore[method-assign]
DockerKaliProvider.teardown = _teardown_idempotent  # type: ignore[method-assign]


def _workstation() -> Dict[str, Any]:
    return {
        "hostname": "analyst-mbp",
        "os_family": "macOS",
        "architecture": "arm64",
        "fingerprint": "integration-test-fp",
    }


def _recipe_content(*, allow_egress_hosts: Optional[list] = None) -> Dict[str, Any]:
    hosts: list = [] if allow_egress_hosts is None else allow_egress_hosts
    return {
        "base_image": DEFAULT_KALI_IMAGE,
        "command": ["bash", "-lc", "echo sheshnaag-lab-lifecycle"],
        "network_policy": {"allow_egress_hosts": hosts},
        "collectors": ["process_tree", "package_inventory", "file_diff", "network_metadata"],
        "teardown_policy": {"mode": "destroy_immediately", "ephemeral_workspace": True},
        "risk_level": "standard",
        "requires_acknowledgement": False,
    }


def _bootstrap_private_lab_session():
    """Onboard tenant, seed demo data, add a matching asset, return (session, tenant)."""
    session = make_session()
    auth = AuthService(session)
    onboard = auth.onboard_private_tenant(
        tenant_name="Lab Lifecycle Tenant",
        tenant_slug="lab-lifecycle-private",
        admin_email="labowner@sheshnaag.local",
        admin_password="supersecure123",
        admin_name="Lab Owner",
    )
    DemoSeedService(session).seed()
    session.commit()

    tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
    session.add(
        Asset(
            tenant_id=tenant.id,
            name="payments-gateway",
            asset_type="application",
            environment="production",
            criticality="high",
            business_criticality="high",
            installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
        )
    )
    session.commit()
    return session, tenant


def _launch_prepared_run(
    service: SheshnaagService,
    tenant,
    *,
    launch_mode: str,
    recipe_content: Dict[str, Any],
):
    service.sync_candidates(tenant)
    candidates = service.list_candidates(tenant, limit=10)
    assert candidates["count"] >= 1
    candidate = candidates["items"][0]
    service.assign_candidate(tenant, candidate_id=candidate["id"], analyst_name="Lab Owner")
    recipe = service.create_recipe(
        tenant,
        candidate_id=candidate["id"],
        name="Lifecycle recipe",
        objective="Exercise lab lifecycle transitions.",
        created_by="Lab Owner",
        content=recipe_content,
    )
    service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
    return service.launch_run(
        tenant,
        recipe_id=recipe["id"],
        revision_number=1,
        analyst_name="Lab Owner",
        workstation=_workstation(),
        launch_mode=launch_mode,
        acknowledge_sensitive=False,
    )


@pytest.mark.integration
def test_dry_run_lifecycle():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        run = _launch_prepared_run(service, tenant, launch_mode="dry_run", recipe_content=_recipe_content())
        assert run["state"] == "planned"
        assert run.get("timeline"), "expected timeline events on dry run"
    finally:
        session.close()


@pytest.mark.integration
def test_simulated_run_full_lifecycle():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        run = _launch_prepared_run(service, tenant, launch_mode="simulated", recipe_content=_recipe_content())
        run_id = run["id"]
        assert run["state"] == "completed"

        with pytest.raises(ValueError, match="Invalid run state transition"):
            service.stop_run(tenant, run_id=run_id)

        destroyed = service.destroy_run(tenant, run_id=run_id)
        assert destroyed["state"] == "destroyed"
    finally:
        session.close()


@pytest.mark.integration
def test_stop_flow():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        run = _launch_prepared_run(service, tenant, launch_mode="simulated", recipe_content=_recipe_content())
        assert run["state"] == "completed"

        with pytest.raises(ValueError) as excinfo:
            service.stop_run(tenant, run_id=run["id"])
        assert "transition" in str(excinfo.value).lower()
    finally:
        session.close()


@pytest.mark.integration
def test_teardown_flow():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        run = _launch_prepared_run(service, tenant, launch_mode="simulated", recipe_content=_recipe_content())
        assert run["state"] == "completed"

        after = service.teardown_run(tenant, run_id=run["id"])
        assert after["state"] == "destroyed"
        types = {ev["event_type"] for ev in after["timeline"]}
        assert "run_teardown" in types
    finally:
        session.close()


@pytest.mark.integration
def test_destroy_flow():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        run = _launch_prepared_run(service, tenant, launch_mode="simulated", recipe_content=_recipe_content())
        assert run["state"] == "completed"

        after = service.destroy_run(tenant, run_id=run["id"])
        assert after["state"] == "destroyed"
        assert after["ended_at"] is not None
    finally:
        session.close()


@pytest.mark.integration
def test_network_policy_manifest_assertion():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        run = _launch_prepared_run(
            service,
            tenant,
            launch_mode="dry_run",
            recipe_content=_recipe_content(allow_egress_hosts=["example.com"]),
        )
        manifest = run.get("manifest") or {}
        assert "effective_network_policy" in manifest
        enp = manifest["effective_network_policy"]
        assert enp["mode"] == "bridge"
        note = enp.get("enforcement_note", "")
        assert "docker" in note.lower()
        assert "per-host" in note.lower() or "per-host egress" in note.lower()
    finally:
        session.close()


@pytest.mark.integration
def test_template_catalog_listing():
    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        catalog = service.list_templates(tenant)
        items = catalog["items"]
        distros = {row["distro"] for row in items}
        assert {"kali", "ubuntu", "debian", "rocky"}.issubset(distros)
        for row in items:
            if row["distro"] in {"kali", "ubuntu", "debian", "rocky"}:
                for key in ("provider", "name", "distro", "base_image", "is_hardened"):
                    assert key in row, f"missing {key} on template {row!r}"
    finally:
        session.close()


@pytest.mark.integration
def test_lima_provider_is_discoverable_but_not_active():
    assert LimaProvider.is_active is False
    assert LimaProvider.provider_name == "lima"

    lima = LimaProvider()
    plan = lima.build_plan(
        revision_content={"vm": {"cpu": 2}},
        run_context={"tenant_slug": "t", "analyst_name": "a", "run_id": 1},
    )
    assert plan.get("provider") == "lima"

    session, tenant = _bootstrap_private_lab_session()
    try:
        service = SheshnaagService(session)
        service.provider = LimaProvider()
        run = _launch_prepared_run(service, tenant, launch_mode="simulated", recipe_content=_recipe_content())
        assert run["state"] == "blocked"
    finally:
        session.close()
