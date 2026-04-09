#!/usr/bin/env python3
"""Quick Sheshnaag API smoke command for the main operator surfaces."""

from __future__ import annotations

import sys
from hashlib import sha256
from pathlib import Path
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.artifact_routes import router as artifact_router
from app.api.routes.candidate_routes import router as candidate_router
from app.api.routes.disclosure_routes import router as disclosure_router
from app.api.routes.evidence_routes import router as evidence_router
from app.api.routes.intel_routes import router as intel_router
from app.api.routes.ledger_routes import router as ledger_router
from app.api.routes.provenance_routes import router as provenance_router
from app.api.routes.recipe_routes import router as recipe_router
from app.api.routes.run_routes import router as run_router
from app.api.routes.template_routes import router as template_router
from app.core.database import Base, get_sync_session
from app.models import Asset
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService

TENANT_SLUG = "smoke-private"

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
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


def build_client() -> TestClient:
    app = FastAPI()
    for router in (
        intel_router,
        candidate_router,
        recipe_router,
        run_router,
        evidence_router,
        artifact_router,
        provenance_router,
        ledger_router,
        disclosure_router,
        template_router,
    ):
        app.include_router(router)
    app.dependency_overrides[get_sync_session] = override_get_sync_session
    return TestClient(app)


def seed_database() -> None:
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        DemoSeedService(session).seed()
        auth = AuthService(session)
        onboard = auth.onboard_private_tenant(
            tenant_name="Sheshnaag Smoke Tenant",
            tenant_slug=TENANT_SLUG,
            admin_email="smoke@sheshnaag.local",
            admin_password="supersecure123",
            admin_name="Smoke Analyst",
        )
        tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
        session.add(
            Asset(
                tenant_id=tenant.id,
                name="smoke-api",
                asset_type="application",
                environment="production",
                criticality="high",
                business_criticality="high",
                installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
            )
        )
        session.commit()
    finally:
        session.close()


def assert_ok(response, name: str) -> dict:
    if response.status_code >= 400:
        raise RuntimeError(f"{name} failed: {response.status_code} {response.text}")
    return response.json()


def main() -> int:
    seed_database()
    client = build_client()
    report: list[str] = []

    intel = assert_ok(client.get("/api/intel/overview", params={"tenant_slug": TENANT_SLUG}), "intel overview")
    report.append(f"intel overview ok ({len(intel['sources'])} sources)")

    candidates = assert_ok(
        client.get("/api/candidates", params={"tenant_slug": TENANT_SLUG, "limit": 5}),
        "candidate list",
    )
    candidate_id = candidates["items"][0]["id"]
    report.append(f"candidate list ok (candidate #{candidate_id})")

    assert_ok(
        client.post(
            f"/api/candidates/{candidate_id}/assign",
            json={"tenant_slug": TENANT_SLUG, "analyst_name": "Smoke Analyst", "assigned_by": "Smoke Analyst"},
        ),
        "candidate assign",
    )
    report.append("candidate assign ok")

    lint = assert_ok(
        client.post(
            "/api/recipes/lint",
            json={
                "content": {
                    "command": ["bash", "-lc", "echo smoke"],
                    "network_policy": {"allow_egress_hosts": []},
                    "risk_level": "sensitive",
                    "requires_acknowledgement": True,
                },
                "expected_distro": "kali",
            },
        ),
        "recipe lint",
    )
    report.append(f"recipe lint ok ({len(lint['warnings'])} warnings)")

    templates = assert_ok(client.get("/api/templates", params={"tenant_slug": TENANT_SLUG}), "template list")
    report.append(f"template list ok ({templates['count']} templates)")

    with NamedTemporaryFile("wb", dir="/tmp", suffix=".bin", delete=False) as handle:
        handle.write(b"sheshnaag-smoke-input")
        source_path = handle.name
    expected_sha256 = sha256(Path(source_path).read_bytes()).hexdigest()

    recipe = assert_ok(
        client.post(
            "/api/recipes",
            json={
                "tenant_slug": TENANT_SLUG,
                "candidate_id": candidate_id,
                "name": "Smoke recipe",
                "objective": "Exercise the Sheshnaag operator surface.",
                "created_by": "Smoke Analyst",
                "content": {
                    "command": ["bash", "-lc", "echo smoke-run"],
                    "network_policy": {"allow_egress_hosts": []},
                    "risk_level": "sensitive",
                    "requires_acknowledgement": True,
                    "artifact_inputs": [
                        {
                            "source_path": source_path,
                            "name": "smoke-input.bin",
                            "sha256": expected_sha256,
                            "destination": "/workspace/inputs/smoke-input.bin",
                        }
                    ],
                },
            },
        ),
        "recipe create",
    )
    recipe_id = recipe["id"]
    report.append(f"recipe create ok (recipe #{recipe_id})")

    assert_ok(
        client.post(
            f"/api/recipes/{recipe_id}/revisions/1/approve",
            json={"tenant_slug": TENANT_SLUG, "reviewer": "Lead Reviewer"},
        ),
        "recipe approve",
    )
    report.append("recipe approve ok")

    run = assert_ok(
        client.post(
            "/api/runs",
            json={
                "tenant_slug": TENANT_SLUG,
                "recipe_id": recipe_id,
                "revision_number": 1,
                "analyst_name": "Smoke Analyst",
                "launch_mode": "simulated",
                "acknowledge_sensitive": True,
                "workstation": {
                    "hostname": "smoke-host",
                    "os_family": "macOS",
                    "architecture": "arm64",
                    "fingerprint": "smoke-fp",
                },
            },
        ),
        "run launch",
    )
    run_id = run["id"]
    report.append(f"run launch ok (run #{run_id}, state={run['state']})")

    run_detail = assert_ok(
        client.get(f"/api/runs/{run_id}", params={"tenant_slug": TENANT_SLUG}),
        "run detail",
    )
    transfer = (run_detail.get("manifest") or {}).get("artifact_transfer") or {}
    report.append(f"run detail ok (artifact transfer={transfer.get('status', 'missing')})")

    evidence = assert_ok(
        client.get("/api/evidence", params={"tenant_slug": TENANT_SLUG, "run_id": run_id}),
        "evidence list",
    )
    report.append(f"evidence list ok ({evidence['count']} items)")

    artifacts = assert_ok(
        client.get("/api/artifacts", params={"tenant_slug": TENANT_SLUG, "run_id": run_id}),
        "artifact list",
    )
    report.append(
        f"artifact list ok ({len(artifacts['detections'])} detections, {len(artifacts['mitigations'])} mitigations)"
    )
    detection_id = artifacts["detections"][0]["id"]

    assert_ok(
        client.post(
            "/api/artifacts/review",
            json={
                "tenant_slug": TENANT_SLUG,
                "artifact_family": "detection",
                "artifact_id": detection_id,
                "decision": "approved",
                "reviewer": "Lead Reviewer",
                "rationale": "Smoke review approval.",
            },
        ),
        "artifact review",
    )
    report.append("artifact review ok")

    provenance = assert_ok(
        client.get("/api/provenance", params={"tenant_slug": TENANT_SLUG, "run_id": run_id}),
        "provenance",
    )
    report.append(f"provenance ok ({provenance['count']} attestations)")

    ledger = assert_ok(client.get("/api/ledger", params={"tenant_slug": TENANT_SLUG}), "ledger")
    report.append(f"ledger ok ({ledger['count']} entries)")

    bundle = assert_ok(
        client.post(
            "/api/disclosures",
            json={
                "tenant_slug": TENANT_SLUG,
                "run_id": run_id,
                "bundle_type": "vendor_disclosure",
                "title": "Smoke disclosure",
                "signed_by": "Smoke Analyst",
                "confirm_external_export": True,
            },
        ),
        "disclosure export",
    )
    report.append(f"disclosure export ok (bundle #{bundle['id']})")

    download = client.get(
        f"/api/disclosures/{bundle['id']}/download",
        params={"tenant_slug": TENANT_SLUG},
    )
    if download.status_code != 200:
        raise RuntimeError(f"bundle download failed: {download.status_code} {download.text}")
    report.append("bundle download ok")

    print("Sheshnaag API smoke summary")
    for line in report:
        print(f"- {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
