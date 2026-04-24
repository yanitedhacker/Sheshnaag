"""PCAP capture (profile-driven, secure-mode Lima only).

V4 slice 2 notes
----------------
The old v2 cap of 5-second / 20-packet / 64 KB bounded capture has been
removed. Capture limits are now driven by per-profile configuration at
``plan["collector_config"]["pcap"]`` with generous defaults when the profile
omits the key.

Configuration keys (all optional):

* ``pcap_enabled`` (bool, default ``True``) — master toggle from the profile.
  The capture still requires secure-mode Lima runs and the host-level
  ``SHESHNAAG_ENABLE_PCAP`` environment flag.
* ``duration_seconds`` (int, default ``30``) — tcpdump wall-clock budget.
* ``max_packets`` (int, default ``10000``) — tcpdump ``-c`` value. ``0`` is
  treated as "unlimited" (tcpdump is invoked without ``-c``).
* ``max_bytes`` (int, default ``10_485_760``, i.e. 10 MB) — cap on the
  base64-encoded preview returned to the host. ``0`` means "unlimited"
  (still clamped to whatever tcpdump produces inside the time budget).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.lab.interfaces import Collector

from app.lab.collectors.common import (
    build_advanced_telemetry_evidence,
    build_evidence_dict,
    collector_health_meta,
    utc_iso,
)
from app.lab.collectors.runtime import env_flag_enabled, run_in_guest


# Generous default capture ceilings (the old 5s/20-pkt/64KB cap is gone).
DEFAULT_DURATION_SECONDS = 30
DEFAULT_MAX_PACKETS = 10000
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_PCAP_ENABLED = True


class PcapCollector(Collector):
    collector_name = "pcap"
    collector_version = "2.0.0"

    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        started = utc_iso()
        plan = provider_result.get("plan") or {}
        provider_name = str(plan.get("provider") or run_context.get("provider") or "")
        config = resolve_pcap_config(plan)

        if provider_name != "lima":
            ended = utc_iso()
            return [
                build_advanced_telemetry_evidence(
                    artifact_kind=self.collector_name,
                    title="PCAP disabled",
                    summary="PCAP capture is restricted to secure-mode Lima runs.",
                    run_context=run_context,
                    provider_result=provider_result,
                    collector_version=self.collector_version,
                    tool="tcpdump",
                    mode="skipped",
                    normalized_events=[],
                    findings=[],
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="secure_mode_only",
                    supported=False,
                    support_reason="PCAP capture is restricted to secure-mode Lima runs.",
                    storage_eligible=False,
                    contains_raw_payload=False,
                    sensitivity={
                        "classification": "restricted",
                        "external_export_requires_confirmation": True,
                    },
                )
            ]

        if not config["pcap_enabled"]:
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "disabled",
                "reason": "profile_flag_off",
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="pcap_enabled_false",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="PCAP disabled by profile",
                    summary="Profile configuration sets pcap_enabled=false.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]

        if not env_flag_enabled("SHESHNAAG_ENABLE_PCAP", default=False):
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "disabled",
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="feature_flag_off",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="PCAP capture disabled",
                    summary="Set SHESHNAAG_ENABLE_PCAP=1 to evaluate PCAP (security review required).",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]

        if run_context.get("launch_mode") != "execute":
            ended = utc_iso()
            payload = {
                "collector": self.collector_name,
                "mode": "skipped",
                "collector_health": collector_health_meta(
                    collector=self.collector_name,
                    version=self.collector_version,
                    started_at=started,
                    ended_at=ended,
                    status="skipped",
                    skip_reason="non_execute_mode",
                ),
            }
            return [
                build_evidence_dict(
                    artifact_kind=self.collector_name,
                    title="PCAP skipped",
                    summary="PCAP requires execute launch mode in secure mode.",
                    payload=payload,
                    capture_started_at=started,
                    capture_ended_at=ended,
                    collector_name=self.collector_name,
                    collector_version=self.collector_version,
                )
            ]

        duration = int(config["duration_seconds"])
        max_packets = int(config["max_packets"])
        max_bytes = int(config["max_bytes"])

        # tcpdump bits.
        count_flag = f"-c {max_packets} " if max_packets > 0 else ""
        byte_pipeline = f"head -c {max_bytes} | " if max_bytes > 0 else ""
        session_command = (
            "command -v tcpdump >/dev/null && "
            f"timeout {duration} tcpdump {count_flag}-w - 2>/dev/null | {byte_pipeline}base64 || true"
        )

        code, out, err = run_in_guest(
            provider_result,
            ["sh", "-lc", session_command],
            timeout_sec=duration + 30,
        )
        ended = utc_iso()

        preview_limit_bytes = max_bytes if max_bytes > 0 else len((out or "").encode("utf-8"))
        preview_slice_chars = max(preview_limit_bytes, 1)
        preview = (out or "")[:preview_slice_chars]
        truncated = bool(out) and len(out) > preview_slice_chars

        status = "ok" if preview.strip() else "degraded"

        return [
            build_advanced_telemetry_evidence(
                artifact_kind=self.collector_name,
                title="PCAP capture",
                summary=(
                    "Profile-driven PCAP capture session completed."
                    if preview.strip()
                    else "PCAP session ran but returned no capture preview."
                ),
                run_context=run_context,
                provider_result=provider_result,
                collector_version=self.collector_version,
                tool="tcpdump",
                mode="live" if preview.strip() else "degraded",
                normalized_events=[],
                findings=[],
                started_at=started,
                ended_at=ended,
                command=session_command,
                raw_preview=preview,
                stderr_preview=(err or "")[:2000],
                exit_code=code,
                status=status,
                skip_reason=None if preview.strip() else "tcpdump_unavailable_or_empty",
                error=(err or "")[:2000] or None,
                event_limit=max_packets if max_packets > 0 else None,
                byte_limit=max_bytes if max_bytes > 0 else None,
                time_limit_seconds=duration,
                truncated=truncated,
                supported=True,
                support_reason="PCAP is enabled only for secure-mode Lima runs.",
                storage_eligible=False,
                contains_raw_payload=bool(preview.strip()),
                sensitivity={
                    "classification": "restricted",
                    "external_export_requires_confirmation": True,
                    "requires_operator_review": True,
                },
                extra={
                    "pcap_base64_preview": preview,
                    "secure_mode_only": True,
                    "capture_config": {
                        "pcap_enabled": config["pcap_enabled"],
                        "duration_seconds": duration,
                        "max_packets": max_packets,
                        "max_bytes": max_bytes,
                        "source": config["source"],
                    },
                    "note": (
                        "Capture bounds sourced from collector profile; 0 denotes unlimited."
                    ),
                },
            )
        ]


def resolve_pcap_config(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve the effective PCAP collector config from a provider plan.

    Lookup order:

    1. ``plan["collector_config"]["pcap"]`` (preferred).
    2. ``plan["collectors_config"]["pcap"]`` (back-compat spelling).
    3. ``plan["pcap"]`` (flat overrides).

    Missing keys fall back to the generous V4 defaults (never the old
    5-second / 20-packet cap).
    """
    candidates: List[Optional[Dict[str, Any]]] = []
    for parent_key in ("collector_config", "collectors_config"):
        parent = plan.get(parent_key) if isinstance(plan, dict) else None
        if isinstance(parent, dict):
            candidates.append(parent.get("pcap"))
    flat = plan.get("pcap") if isinstance(plan, dict) else None
    if isinstance(flat, dict):
        candidates.append(flat)

    source = "defaults"
    merged: Dict[str, Any] = {}
    for idx, cand in enumerate(candidates):
        if isinstance(cand, dict):
            merged.update(cand)
            if source == "defaults":
                source = ("collector_config", "collectors_config", "plan.pcap")[idx]

    def _int(value: Any, default: int) -> int:
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _bool(value: Any, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return default

    duration = max(0, _int(merged.get("duration_seconds"), DEFAULT_DURATION_SECONDS))
    max_packets = max(0, _int(merged.get("max_packets"), DEFAULT_MAX_PACKETS))
    max_bytes = max(0, _int(merged.get("max_bytes"), DEFAULT_MAX_BYTES))
    pcap_enabled = _bool(merged.get("pcap_enabled"), DEFAULT_PCAP_ENABLED)

    return {
        "pcap_enabled": pcap_enabled,
        "duration_seconds": duration,
        "max_packets": max_packets,
        "max_bytes": max_bytes,
        "source": source,
    }
