#!/usr/bin/env python3
"""Optional Lima-backed secure-mode smoke for Sheshnaag."""

from __future__ import annotations

import argparse
import json
import shutil
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


def lima_ready() -> bool:
    if shutil.which("limactl") is None:
        return False
    try:
        result = subprocess.run(["limactl", "list"], capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None, help="Optional path to write a secure-mode smoke summary JSON.")
    args = parser.parse_args()
    if not lima_ready():
        print("SKIP: limactl unavailable; secure-mode smoke not run.")
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
            tenant_name="Sheshnaag Secure Smoke",
            tenant_slug="secure-smoke-private",
            admin_email="secure@sheshnaag.local",
            admin_password="supersecure123",
            admin_name="Secure Smoke",
        )
        tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
        session.add(
            Asset(
                tenant_id=tenant.id,
                name="secure-smoke-api",
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
            name="Secure mode smoke recipe",
            objective="Verify secure-mode Lima lifecycle and secure collector packaging.",
            created_by="Secure Smoke",
            content={
                "provider": "lima",
                "image_profile": "secure_lima",
                "execution_policy": {"secure_mode_required": True},
                "command": ["bash", "-lc", "echo secure-smoke > /workspace/secure-smoke.txt && sleep 3"],
                "network_policy": {"allow_egress_hosts": []},
                "collectors": ["process_tree", "pcap"],
            },
        )
        service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
        run = service.launch_run(
            tenant,
            recipe_id=recipe["id"],
            revision_number=1,
            analyst_name="Secure Smoke",
            workstation={"hostname": "secure-smoke", "os_family": "macOS", "architecture": "arm64", "fingerprint": "secure-smoke-fp"},
            launch_mode="execute",
            acknowledge_sensitive=False,
        )

        if run["provider"] != "lima":
            raise RuntimeError(f"secure smoke launched unexpected provider: {run['provider']}")
        if run["state"] not in {"running", "completed", "blocked"}:
            raise RuntimeError(f"secure smoke failed: state={run['state']} transcript={run.get('run_transcript')}")

        evidence = service.list_evidence(tenant, run_id=run["id"])
        pcap_rows = [row for row in evidence["items"] if row["artifact_kind"] == "pcap"]
        if run["state"] != "blocked" and not pcap_rows:
            raise RuntimeError("secure smoke captured no pcap evidence row")

        manifest = run.get("manifest") or {}
        secure_audit = manifest.get("secure_mode_audit") or {}
        execute_result = secure_audit.get("execute_result") or {}
        if run["state"] != "blocked":
            if not execute_result:
                raise RuntimeError("secure smoke missing execute_result audit")
            if execute_result.get("exit_code") != 0:
                raise RuntimeError(f"secure smoke guest command failed: {execute_result}")
            lifecycle = secure_audit.get("lifecycle") or []
            if not any(item.get("event") == "booted" for item in lifecycle):
                raise RuntimeError("secure smoke missing boot lifecycle audit")
            if not any(item.get("event") == "executed" for item in lifecycle):
                raise RuntimeError("secure smoke missing execute lifecycle audit")

        destroyed = service.destroy_run(tenant, run_id=run["id"])
        destroyed_manifest = destroyed.get("manifest") or {}
        destroyed_audit = destroyed_manifest.get("secure_mode_audit") or {}
        if destroyed["state"] != "destroyed":
            raise RuntimeError(f"secure smoke destroy failed: {destroyed['state']}")
        if not any(item.get("event") in {"deleted", "teardown"} for item in (destroyed_audit.get("lifecycle") or [])):
            raise RuntimeError("secure smoke missing teardown/delete lifecycle audit")

        payload = {
            "run_id": run["id"],
            "initial_state": run["state"],
            "destroyed_state": destroyed["state"],
            "pcap_rows": len(pcap_rows),
            "secure_mode_audit": destroyed_audit,
            "execute_result": execute_result,
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(payload, indent=2, sort_keys=True))

        print(f"PASS: secure-mode smoke run #{run['id']} finished in state {destroyed['state']}.")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
