#!/usr/bin/env python3
"""Run the safe OSS maintainer demo through the public CLI and write proof JSON."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data" / "release_metadata" / "maintainer-demo-assessment.json"
DEFAULT_SBOM = ROOT / "examples" / "oss-maintainer" / "demo-sbom.json"
DEFAULT_VEX = ROOT / "examples" / "oss-maintainer" / "demo-vex.json"
DEFAULT_TENANT = "oss-maintainer-demo"
DEFAULT_EMAIL = "oss-maintainer-demo@example.invalid"
DEFAULT_PASSWORD = "SheshnaagDemo123!"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _request_json(method: str, url: str, *, payload: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=body, headers=headers, method=method)
    with urlopen(request, timeout=30) as response:  # noqa: S310 - operator-supplied local URL
        data = response.read()
    return json.loads(data.decode("utf-8")) if data else {}


def _health(base_url: str) -> dict[str, Any]:
    return _request_json("GET", f"{base_url}/health")


def _onboard_or_login(base_url: str, tenant_slug: str) -> str:
    onboard_payload = {
        "tenant_name": "OSS Maintainer Demo",
        "tenant_slug": tenant_slug,
        "admin_email": DEFAULT_EMAIL,
        "admin_password": DEFAULT_PASSWORD,
        "admin_name": "OSS Maintainer Demo",
        "description": "Synthetic tenant used for sanitized OSS program demo evidence.",
    }
    try:
        result = _request_json("POST", f"{base_url}/api/tenants/onboard", payload=onboard_payload)
    except HTTPError as exc:
        if exc.code != 409:
            raise
        result = _request_json(
            "POST",
            f"{base_url}/api/auth/token",
            payload={
                "email": DEFAULT_EMAIL,
                "password": DEFAULT_PASSWORD,
                "tenant_slug": tenant_slug,
            },
        )
    token = ((result.get("token") or result).get("access_token"))
    if not token:
        raise RuntimeError("Demo tenant onboarding/login did not return a bearer token.")
    return str(token)


def _run_cli(base_url: str, tenant_slug: str, token: str, repo_url: str, sbom: Path, vex: Path) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "sheshnaag_maintainer.py"),
        "assess",
        "--base-url",
        base_url,
        "--tenant-slug",
        tenant_slug,
        "--repo-url",
        repo_url,
        "--sbom",
        str(sbom),
        "--vex",
        str(vex),
        "--export-report",
        "--json",
        "--token",
        token,
    ]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "maintainer CLI failed").strip())
    assessment = json.loads(result.stdout)
    return {
        "command": [
            sys.executable,
            "scripts/sheshnaag_maintainer.py",
            "assess",
            "--base-url",
            base_url,
            "--tenant-slug",
            tenant_slug,
            "--repo-url",
            repo_url,
            "--sbom",
            _display_path(sbom),
            "--vex",
            _display_path(vex),
            "--export-report",
            "--json",
            "--token",
            "<redacted>",
        ],
        "assessment": assessment,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Write sanitized OSS maintainer demo proof JSON.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--tenant-slug", default=DEFAULT_TENANT)
    parser.add_argument("--repo-url", default="https://github.com/example/edge-gateway")
    parser.add_argument("--sbom", type=Path, default=DEFAULT_SBOM)
    parser.add_argument("--vex", type=Path, default=DEFAULT_VEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--allow-skip", action="store_true", help="Write skipped proof when no local API is reachable.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    payload: dict[str, Any] = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "tenant_slug": args.tenant_slug,
        "repo_url": args.repo_url,
        "sbom": _display_path(args.sbom),
        "vex": _display_path(args.vex),
        "safe_demo_corpus": True,
    }
    try:
        payload["health"] = _health(base_url)
        token = _onboard_or_login(base_url, args.tenant_slug)
        payload.update(_run_cli(base_url, args.tenant_slug, token, args.repo_url, args.sbom, args.vex))
        payload["status"] = "passed"
    except (HTTPError, URLError, OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        payload["status"] = "skipped" if args.allow_skip else "failed"
        payload["reason"] = "local_api_unavailable_or_demo_tenant_unready"
        payload["detail"] = str(exc)

    output = args.output if args.output.is_absolute() else ROOT / args.output
    _write_json(output, payload)
    print(f"Wrote maintainer demo proof to {output}")
    print(f"status={payload['status']}")
    if payload["status"] == "failed":
        print(f"Maintainer demo failed: {payload['detail']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
