"""Bounded service / system log excerpts from recipe configuration."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.interfaces import Collector

from app.lab.collectors.common import (
    build_evidence_dict,
    collector_health_meta,
    synthetic_from_plan,
    truncate_text,
    utc_iso,
)
from app.lab.collectors.runtime import is_executable_guest_context, resolve_container_id, run_in_container

MAX_LOG_BYTES = 120_000
DEFAULT_PATHS = ["/var/log/dpkg.log", "/var/log/alternatives.log"]


class ServiceLogsCollector(Collector):
    collector_name = "service_logs"
    collector_version = "1.0.0"

    def _sources(self, recipe: Dict[str, Any]) -> List[Dict[str, str]]:
        raw = recipe.get("log_sources") or recipe.get("service_logs") or []
        out: List[Dict[str, str]] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    out.append({"path": item, "service": "custom"})
                elif isinstance(item, dict) and item.get("path"):
                    out.append(
                        {
                            "path": str(item["path"]),
                            "service": str(item.get("service") or "custom"),
                        }
                    )
        if not out:
            for p in DEFAULT_PATHS:
                out.append({"path": p, "service": "system"})
        return out

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        recipe = run_context.get("recipe_content") or {}
        sources = self._sources(recipe)
        if not is_executable_guest_context(run_context=run_context, provider_result=provider_result):
            return [
                synthetic_from_plan(
                    collector_name=self.collector_name,
                    title="Service logs",
                    summary="Synthetic log excerpts (non-live mode).",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                )
            ]
        cid = resolve_container_id(provider_result)
        assert cid
        started = utc_iso()
        excerpts: List[Dict[str, Any]] = []
        for src in sources:
            path = src["path"]
            code, out, err = run_in_container(
                cid,
                ["sh", "-c", f"tail -n 200 '{path}' 2>/dev/null || true"],
                timeout_sec=30,
            )
            text, trunc = truncate_text(out or "", MAX_LOG_BYTES // max(1, len(sources)))
            excerpts.append(
                {
                    "path": path,
                    "service": src["service"],
                    "exit_code": code,
                    "excerpt": text,
                    "truncated": trunc,
                    "stderr": (err or "")[:500],
                }
            )
        ended = utc_iso()
        payload = {
            "collector": self.collector_name,
            "mode": "live",
            "sources": excerpts,
            "collector_health": collector_health_meta(
                collector=self.collector_name,
                version=self.collector_version,
                started_at=started,
                ended_at=ended,
                status="ok",
                output_bytes=sum(len((e.get("excerpt") or "").encode("utf-8")) for e in excerpts),
            ),
        }
        return [
            build_evidence_dict(
                artifact_kind=self.collector_name,
                title="Service logs",
                summary=f"Captured {len(excerpts)} log source(s).",
                payload=payload,
                capture_started_at=started,
                capture_ended_at=ended,
                collector_name=self.collector_name,
                collector_version=self.collector_version,
                truncated=any(e.get("truncated") for e in excerpts),
            )
        ]
