"""Package inventory collector (Debian/apt style for Kali)."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import (
    build_evidence_dict,
    collector_error_evidence,
    collector_health_meta,
    synthetic_from_plan,
    truncate_text,
    utc_iso,
)
from app.lab.collectors.runtime import is_executable_guest_context, resolve_container_id, run_in_container

MAX_OUTPUT_BYTES = 900_000


class PackageInventoryCollector(Collector):
    collector_name = "package_inventory"
    collector_version = "1.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Package inventory diff",
                    summary="Synthetic package inventory (non-live mode).",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        started = utc_iso()
        code, out, err = run_in_container(
            cid,
            [
                "sh",
                "-c",
                "dpkg-query -W -f '${Package}\t${Version}\n' 2>/dev/null | sort | head -n 20000",
            ],
            timeout_sec=120,
        )
        ended = utc_iso()
        if code != 0:
            return [
                collector_error_evidence(
                    collector_name=self.collector_name,
                    title="Package inventory capture failed",
                    message=err or f"exit {code}",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="dpkg-query",
                )
            ]
        text, trunc = truncate_text(out, MAX_OUTPUT_BYTES)
        packages: List[Dict[str, str]] = []
        for line in text.splitlines():
            if "\t" not in line:
                continue
            name, ver = line.split("\t", 1)
            packages.append({"name": name.strip(), "version": ver.strip()})
        plan = provider_result.get("plan") or {}
        baseline_raw = plan.get("package_baseline")
        cur_map = {p["name"]: p["version"] for p in packages}
        diff_block: Dict[str, Any]
        if isinstance(baseline_raw, list) and len(baseline_raw) > 0:
            base_map: Dict[str, str] = {}
            for row in baseline_raw:
                if isinstance(row, dict) and row.get("name"):
                    base_map[str(row["name"]).strip()] = str(row.get("version") or "").strip()
            added = [{"name": n, "version": v} for n, v in cur_map.items() if n not in base_map]
            removed = [{"name": n, "version": v} for n, v in base_map.items() if n not in cur_map]
            changed = [
                {"name": n, "before": base_map[n], "after": cur_map[n]}
                for n in cur_map
                if n in base_map and base_map[n] != cur_map[n]
            ]
            diff_block = {"added": added, "removed": removed, "version_changed": changed}
        else:
            diff_block = {
                "note": "No package_baseline in recipe/plan; snapshot only. Optional baseline enables diff (WS6-T3).",
            }
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "capture_phase": "post_command",
            "packages": packages,
            "package_count": len(packages),
            "diff": diff_block,
            "truncated": trunc,
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok",
                output_bytes=len(text.encode("utf-8")),
            ),
        }
        summary = f"Captured {len(packages)} packages (post-run snapshot)."
        if isinstance(baseline_raw, list) and len(baseline_raw) > 0:
            d = diff_block
            summary = (
                f"Package diff: +{len(d.get('added', []))} "
                f"-{len(d.get('removed', []))} ~{len(d.get('version_changed', []))} version change(s)."
            )
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Package inventory",
                summary=summary,
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
                truncated=trunc,
            )
        ]
