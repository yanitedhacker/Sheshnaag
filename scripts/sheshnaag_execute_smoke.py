#!/usr/bin/env python3
"""Docker-backed execute-mode smoke for the baseline Sheshnaag validation path."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models import Asset
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.sheshnaag_service import SheshnaagService


def docker_ready() -> bool:
    try:
        result = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    except Exception:
        return False


def main() -> int:
    if not docker_ready():
        print("SKIP: docker daemon unavailable; execute smoke not run.")
        return 0

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = session_factory()

    try:
        DemoSeedService(session).seed()
        auth = AuthService(session)
        onboard = auth.onboard_private_tenant(
            tenant_name="Sheshnaag Execute Smoke",
            tenant_slug="execute-smoke-private",
            admin_email="execute@sheshnaag.local",
            admin_password="supersecure123",
            admin_name="Execute Smoke",
        )
        tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
        session.add(
            Asset(
                tenant_id=tenant.id,
                name="execute-smoke-api",
                asset_type="application",
                environment="production",
                criticality="high",
                business_criticality="high",
                installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
            )
        )
        session.commit()

        service = SheshnaagService(session)
        candidate = service.list_candidates(tenant, limit=1)["items"][0]
        recipe = service.create_recipe(
            tenant,
            candidate_id=candidate["id"],
            name="Execute smoke recipe",
            objective="Verify baseline execute-mode validation path.",
            created_by="Execute Smoke",
            content={
                "command": ["bash", "-lc", "echo execute-smoke > /workspace/execute-smoke.txt && sleep 5"],
                "network_policy": {"allow_egress_hosts": []},
                "collectors": [
                    "process_tree",
                    "package_inventory",
                    "file_diff",
                    "network_metadata",
                    "service_logs",
                ],
            },
        )
        service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
        run = service.launch_run(
            tenant,
            recipe_id=recipe["id"],
            revision_number=1,
            analyst_name="Execute Smoke",
            workstation={"hostname": "execute-smoke", "os_family": "macOS", "architecture": "arm64", "fingerprint": "execute-smoke-fp"},
            launch_mode="execute",
            acknowledge_sensitive=False,
        )

        if run["state"] not in {"running", "completed"}:
            raise RuntimeError(f"execute run failed: state={run['state']} transcript={run.get('run_transcript')}")

        evidence = service.list_evidence(tenant, run_id=run["id"])
        artifacts = service.list_artifacts(tenant, run_id=run["id"])
        provenance = service.get_provenance(tenant, run_id=run["id"])
        bundle = service.create_disclosure_bundle(
            tenant,
            run_id=run["id"],
            bundle_type="vendor_disclosure",
            title="Execute smoke bundle",
            signed_by="Execute Smoke",
            confirm_external_export=True,
        )

        if evidence["count"] < 1:
            raise RuntimeError("execute smoke captured no evidence")
        if len(artifacts["detections"]) < 1:
            raise RuntimeError("execute smoke generated no detection artifacts")
        if provenance["count"] < 1:
            raise RuntimeError("execute smoke produced no attestation records")
        if not Path(bundle["archive"]["path"]).exists():
            raise RuntimeError("execute smoke did not write disclosure archive")

        print(f"PASS: execute smoke run #{run['id']} captured {evidence['count']} evidence artifact(s).")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
