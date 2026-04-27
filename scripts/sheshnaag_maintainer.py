#!/usr/bin/env python3
"""CLI for OSS maintainer security assessments."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def _load_json(path: str) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _request_json(
    method: str,
    url: str,
    *,
    token: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
    output: Optional[str] = None,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, data=body, headers=headers, method=method)
    with urlopen(request, timeout=60) as response:  # noqa: S310 - operator-supplied URL
        content_type = response.headers.get("Content-Type", "")
        data = response.read()
        if output and "application/zip" in content_type:
            Path(output).write_bytes(data)
            return {"output": output, "bytes": len(data)}
        if not data:
            return {}
        return json.loads(data.decode("utf-8"))


def _print_summary(payload: dict[str, Any]) -> None:
    summary = payload.get("summary") or {}
    repo = payload.get("repository") or summary.get("repository") or {}
    print(f"Assessment #{payload.get('id')} - {repo.get('name') or repo.get('url') or 'repository'}")
    print(f"Status: {payload.get('status', 'unknown')}")
    print(f"Matched findings: {summary.get('matched_findings_count', 0)}")
    report = payload.get("report") or {}
    if report:
        print(f"Report: #{report.get('id')} ({report.get('status')})")
        if report.get("download_url"):
            print(f"Download URL: {report['download_url']}")
    findings = summary.get("top_findings") or []
    for item in findings[:5]:
        print(f"- {item.get('cve_id')}: score={item.get('candidate_score')} package={item.get('package_name')}")
    if not findings:
        for step in (summary.get("recommended_next_steps") or [])[:3]:
            print(f"- {step}")


def _emit(payload: dict[str, Any], *, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_summary(payload)


def _token(args: argparse.Namespace) -> Optional[str]:
    return args.token or os.getenv("SHESHNAAG_TOKEN")


def _base_url(args: argparse.Namespace) -> str:
    return args.base_url.rstrip("/")


def cmd_assess(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "tenant_id": args.tenant_id,
        "tenant_slug": args.tenant_slug,
        "repository_url": args.repo_url,
        "repository_name": args.repo_name,
        "sbom": _load_json(args.sbom),
        "created_by": args.created_by,
        "export_report": args.export_report,
    }
    if args.vex:
        payload["vex"] = _load_json(args.vex)
    if args.source_ref:
        payload["source_refs"] = [{"url": item} for item in args.source_ref]
    result = _request_json(
        "POST",
        f"{_base_url(args)}/api/maintainer/assessments",
        token=_token(args),
        payload={key: value for key, value in payload.items() if value is not None},
    )
    _emit(result, json_mode=args.json)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    query = _tenant_query(args)
    result = _request_json(
        "GET",
        f"{_base_url(args)}/api/maintainer/assessments/{args.assessment_id}{query}",
        token=_token(args),
    )
    _emit(result, json_mode=args.json)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    query = _tenant_query(args)
    result = _request_json(
        "POST",
        f"{_base_url(args)}/api/maintainer/assessments/{args.assessment_id}/export{query}",
        token=_token(args),
    )
    if args.output:
        report = result.get("report") or {}
        download_url = report.get("download_url")
        if not download_url:
            raise RuntimeError("Assessment export did not return a report download URL")
        separator = "&" if "?" in download_url else "?"
        download = _request_json(
            "GET",
            f"{_base_url(args)}{download_url}{separator}{_tenant_query(args, leading=False)}",
            token=_token(args),
            output=args.output,
        )
        if args.json:
            print(json.dumps({"assessment": result, "download": download}, indent=2, sort_keys=True))
        else:
            print(f"Wrote {download['bytes']} bytes to {download['output']}")
        return 0
    _emit(result, json_mode=args.json)
    return 0


def _tenant_query(args: argparse.Namespace, *, leading: bool = True) -> str:
    params: dict[str, Any] = {}
    if getattr(args, "tenant_id", None) is not None:
        params["tenant_id"] = args.tenant_id
    if getattr(args, "tenant_slug", None):
        params["tenant_slug"] = args.tenant_slug
    encoded = urlencode(params)
    if not encoded:
        return ""
    return f"?{encoded}" if leading else encoded


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default=None, help="Bearer token. Defaults to SHESHNAAG_TOKEN.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Sheshnaag OSS maintainer assessments.")
    _add_common_args(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)

    assess = subparsers.add_parser("assess", help="Create a maintainer assessment.")
    _add_common_args(assess)
    assess.add_argument("--tenant-id", type=int)
    assess.add_argument("--tenant-slug")
    assess.add_argument("--repo-url", required=True)
    assess.add_argument("--repo-name")
    assess.add_argument("--sbom", required=True)
    assess.add_argument("--vex")
    assess.add_argument("--source-ref", action="append", default=[])
    assess.add_argument("--created-by", default="OSS Maintainer")
    assess.add_argument("--export-report", action="store_true")
    assess.set_defaults(func=cmd_assess)

    show = subparsers.add_parser("show", help="Show an assessment.")
    _add_common_args(show)
    show.add_argument("--tenant-id", type=int)
    show.add_argument("--tenant-slug")
    show.add_argument("--assessment-id", type=int, required=True)
    show.set_defaults(func=cmd_show)

    export = subparsers.add_parser("export", help="Create or fetch a report export for an assessment.")
    _add_common_args(export)
    export.add_argument("--tenant-id", type=int)
    export.add_argument("--tenant-slug")
    export.add_argument("--assessment-id", type=int, required=True)
    export.add_argument("--output")
    export.set_defaults(func=cmd_export)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except HTTPError as exc:
        if exc.code in {401, 403}:
            print("Authentication required or insufficient for this tenant. Pass --token or set SHESHNAAG_TOKEN.", file=sys.stderr)
        else:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else str(exc)
            print(f"API request failed ({exc.code}): {detail}", file=sys.stderr)
        return 2
    except (URLError, OSError, ValueError, RuntimeError) as exc:
        print(f"Maintainer assessment failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
