"""Defensive artifact generation for Project Sheshnaag."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List

from app.lab.interfaces import ArtifactGenerator


class DefensiveArtifactGenerator(ArtifactGenerator):
    """Create deterministic detection and mitigation artifacts."""

    def generate(self, *, run_context: Dict[str, Any], evidence: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        evidence_list = list(evidence)
        candidate = run_context.get("candidate", {})
        cve_id = candidate.get("cve_id") or run_context.get("cve_id") or "UNKNOWN"
        title_root = candidate.get("title") or f"Validation for {cve_id}"

        detection_artifacts: List[Dict[str, Any]] = []
        mitigation_artifacts: List[Dict[str, Any]] = []

        if evidence_list:
            first = evidence_list[0]
            sigma_body = "\n".join(
                [
                    "title: Suspicious validation pattern",
                    f"id: {cve_id.lower()}-validation",
                    "status: experimental",
                    "logsource:",
                    "  product: linux",
                    "detection:",
                    "  selection:",
                    f"    sheshnaag.run_id: {run_context.get('run_id')}",
                    "  condition: selection",
                ]
            )
            falco_body = "\n".join(
                [
                    f"- rule: {title_root}",
                    "  desc: Detects process or filesystem activity from a Sheshnaag validation run.",
                    "  condition: evt.type in (execve, openat)",
                    "  output: Sheshnaag validation activity detected",
                    "  priority: NOTICE",
                ]
            )
            detection_artifacts.extend(
                [
                    self._detection("sigma", f"{title_root} Sigma", sigma_body, first.get("id")),
                    self._detection("falco", f"{title_root} Falco", falco_body, first.get("id")),
                ]
            )

        mitigation_body = "\n".join(
            [
                f"Mitigation checklist for {cve_id}:",
                "- Validate version applicability against imported SBOM data.",
                "- Restrict exposed services and outbound network paths to the documented allowlist.",
                "- Apply vendor fix or compensating control before promoting environment changes.",
                "- Review generated detections and provenance manifest before disclosure export.",
            ]
        )
        mitigation_artifacts.append(
            {
                "artifact_type": "mitigation_checklist",
                "title": f"{title_root} mitigation checklist",
                "body": mitigation_body,
                "status": "draft",
            }
        )

        return {
            "detection_artifacts": detection_artifacts,
            "mitigation_artifacts": mitigation_artifacts,
        }

    @staticmethod
    def _detection(artifact_type: str, name: str, body: str, evidence_artifact_id: Any) -> Dict[str, Any]:
        return {
            "artifact_type": artifact_type,
            "name": name,
            "rule_body": body,
            "status": "draft",
            "evidence_artifact_id": evidence_artifact_id,
            "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        }
