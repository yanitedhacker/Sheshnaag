#!/usr/bin/env python3
"""Optional direct Lima-backed secure-mode smoke for Sheshnaag."""

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

from app.lab.collector_contract import build_provider_result_dict
from app.lab.collectors import instantiate_collectors
from app.lab.interfaces import RunState
from app.lab.lima_provider import LimaProvider


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

    provider = LimaProvider()
    provider_run_ref = ""
    try:
        revision_content = {
            "provider": "lima",
            "image_profile": "secure_lima",
            "execution_policy": {"secure_mode_required": True},
            "command": [
                "bash",
                "-lc",
                "echo secure-smoke > /workspace/secure-smoke.txt && (getent hosts example.invalid || true) && sleep 1",
            ],
            "network_policy": {"allow_egress_hosts": []},
            "collectors": ["process_tree", "file_diff", "network_metadata", "pcap"],
        }
        run_context = {
            "run_id": "secure-smoke",
            "tenant_slug": "secure-smoke-private",
            "analyst_name": "Secure Smoke",
            "launch_mode": "execute",
            "recipe_content": revision_content,
            "provider": "lima",
        }
        result = provider.launch(
            revision_content=revision_content,
            run_context=run_context,
        )
        provider_run_ref = result.provider_run_ref

        if result.state == RunState.BLOCKED:
            payload = {
                "provider_run_ref": provider_run_ref,
                "state": result.state.value,
                "transcript": result.transcript,
                "error": result.error,
                "provider_readiness": result.plan.get("provider_readiness"),
            }
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(payload, indent=2, sort_keys=True))
            print(f"SKIP: secure-mode smoke blocked: {result.error or result.transcript}")
            return 0
        if result.state not in {RunState.RUNNING, RunState.COMPLETED}:
            raise RuntimeError(f"secure smoke failed: state={result.state.value} transcript={result.transcript}")

        provider_result = build_provider_result_dict(
            provider_run_ref=result.provider_run_ref,
            plan=result.plan,
            state=result.state.value,
        )
        evidence = []
        for collector in instantiate_collectors(revision_content["collectors"]):
            evidence.extend(collector.collect(run_context=run_context, provider_result=provider_result))

        kinds = {row["artifact_kind"] for row in evidence}
        expected = {"process_tree", "file_diff", "network_metadata", "pcap"}
        missing = sorted(expected - kinds)
        if missing:
            raise RuntimeError(f"secure smoke missing evidence kinds: {missing}")

        secure_audit = result.plan.get("secure_mode_audit") or {}
        execute_result = secure_audit.get("execute_result") or {}
        if not execute_result:
            raise RuntimeError("secure smoke missing execute_result audit")
        if execute_result.get("exit_code") != 0:
            raise RuntimeError(f"secure smoke guest command failed: {execute_result}")
        lifecycle = secure_audit.get("lifecycle") or []
        if not any(item.get("event") == "booted" for item in lifecycle):
            raise RuntimeError("secure smoke missing boot lifecycle audit")
        if not any(item.get("event") == "executed" for item in lifecycle):
            raise RuntimeError("secure smoke missing execute lifecycle audit")

        destroyed_ref = provider_run_ref
        destroyed = provider.destroy(provider_run_ref=destroyed_ref)
        provider_run_ref = ""
        destroyed_audit = destroyed.plan.get("secure_mode_audit") or {}
        if destroyed.state != RunState.DESTROYED:
            raise RuntimeError(f"secure smoke destroy failed: {destroyed.state.value}")
        if not any(item.get("event") in {"deleted", "teardown"} for item in (destroyed_audit.get("lifecycle") or [])):
            raise RuntimeError("secure smoke missing teardown/delete lifecycle audit")

        payload = {
            "provider_run_ref": destroyed_ref,
            "initial_state": result.state.value,
            "destroyed_state": destroyed.state.value,
            "evidence_kinds": sorted(kinds),
            "secure_mode_audit": destroyed_audit,
            "execute_result": execute_result,
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(payload, indent=2, sort_keys=True))

        print(f"PASS: secure-mode smoke {destroyed_ref} finished in state {destroyed.state.value}.")
        return 0
    finally:
        if provider_run_ref:
            try:
                provider.destroy(provider_run_ref=provider_run_ref)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
