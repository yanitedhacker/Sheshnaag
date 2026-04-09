#!/usr/bin/env python3
"""Docker-backed execute-mode smoke for the Tracee-enabled Sheshnaag lab image."""

from __future__ import annotations

import os
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


def image_present(image: str) -> bool:
    try:
        result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    except Exception:
        return False


def main() -> int:
    if not docker_ready():
        print("SKIP: docker daemon unavailable; Tracee smoke not run.")
        return 0

    image = os.environ.get("SHESHNAAG_TRACEE_IMAGE", "sheshnaag-kali-tracee:2026.1")
    if not image_present(image):
        print(f"SKIP: Tracee-capable image {image} is not present. Run scripts/build_sheshnaag_tracee_image.sh first.")
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
            tenant_name="Sheshnaag Tracee Smoke",
            tenant_slug="tracee-smoke-private",
            admin_email="tracee@sheshnaag.local",
            admin_password="supersecure123",
            admin_name="Tracee Smoke",
        )
        tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
        session.add(
            Asset(
                tenant_id=tenant.id,
                name="tracee-smoke-api",
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
            name="tracee smoke recipe",
            objective="Verify Tracee runtime event collection on the trusted Tracee image.",
            created_by="Tracee Smoke",
            content={
                "image_profile": "tracee_capable",
                "command": ["bash", "-lc", "echo tracee-smoke > /workspace/tracee-smoke.txt && sleep 5"],
                "network_policy": {"allow_egress_hosts": []},
                "collectors": ["process_tree", "tracee_events", "file_diff"],
            },
        )
        service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
        run = service.launch_run(
            tenant,
            recipe_id=recipe["id"],
            revision_number=1,
            analyst_name="Tracee Smoke",
            workstation={"hostname": "tracee-smoke", "os_family": "macOS", "architecture": "arm64", "fingerprint": "tracee-smoke-fp"},
            launch_mode="execute",
            acknowledge_sensitive=False,
        )

        if run["state"] not in {"running", "completed"}:
            raise RuntimeError(f"Tracee smoke failed: state={run['state']} transcript={run.get('run_transcript')}")

        evidence = service.list_evidence(tenant, run_id=run["id"])
        tracee_rows = [row for row in evidence["items"] if row["artifact_kind"] == "tracee_events"]
        if not tracee_rows:
            raise RuntimeError("Tracee smoke captured no tracee_events evidence")
        if tracee_rows[0]["payload"].get("collection_state") != "live":
            raise RuntimeError(f"Tracee collector not live: {tracee_rows[0]['payload']}")

        print(f"PASS: Tracee smoke run #{run['id']} captured supported Tracee evidence.")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
