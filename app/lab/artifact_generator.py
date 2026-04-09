"""Defensive artifact generation for Project Sheshnaag."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List

from app.lab.interfaces import ArtifactGenerator


class DefensiveArtifactGenerator(ArtifactGenerator):
    """Create deterministic defensive artifacts from observed evidence."""

    def generate(self, *, run_context: Dict[str, Any], evidence: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        evidence_list = list(evidence)
        candidate = run_context.get("candidate", {})
        cve_id = candidate.get("cve_id") or run_context.get("cve_id") or "UNKNOWN"
        title_root = candidate.get("title") or f"Validation for {cve_id}"
        package_name = candidate.get("package_name") or candidate.get("product_name") or "unknown-package"

        process_terms = self._collect_process_terms(evidence_list)
        network_terms = self._collect_network_terms(evidence_list)
        file_terms = self._collect_file_terms(evidence_list)
        findings = self._collect_findings(evidence_list)

        detection_artifacts: List[Dict[str, Any]] = []
        mitigation_artifacts: List[Dict[str, Any]] = []

        if evidence_list:
            evidence_ref = evidence_list[0].get("id")
            selector_lines = [f"    process.name|contains: {term}" for term in process_terms[:4]]
            if not selector_lines:
                selector_lines = [f"    sheshnaag.run_id: {run_context.get('run_id')}"]
            falco_terms = process_terms[:4] or ["sheshnaag_validation"]
            sigma_body = "\n".join(
                [
                    f"title: {title_root} process behavior",
                    f"id: {cve_id.lower()}-validation",
                    "status: experimental",
                    "logsource:",
                    "  product: linux",
                    "detection:",
                    "  selection:",
                    *selector_lines,
                    "  condition: selection",
                ]
            )
            falco_body = "\n".join(
                [
                    f"- rule: {title_root}",
                    "  desc: Detects validation-time process or file behavior observed by Project Sheshnaag.",
                    f"  condition: proc.name in ({', '.join(json.dumps(term) for term in falco_terms)})",
                    f"  output: {title_root} validation activity detected",
                    "  priority: NOTICE",
                ]
            )
            detection_artifacts.extend(
                [
                    self._detection("sigma", f"{title_root} Sigma", sigma_body, evidence_ref),
                    self._detection("falco", f"{title_root} Falco", falco_body, evidence_ref),
                ]
            )

        if evidence_list and network_terms:
            first_network = next((item for item in evidence_list if item.get("artifact_kind") in {"network_metadata", "pcap"}), evidence_list[0])
            suricata_terms = [term for term in network_terms[:4] if term]
            if suricata_terms:
                suricata_body = "\n".join(
                    [
                        "alert http any any -> any any (",
                        f'  msg:"{title_root} validation network indicator";',
                        f'  flowbits:set,{cve_id.lower().replace("-", "_")};',
                        f'  content:"{suricata_terms[0]}"; nocase;',
                        "  sid:4200001;",
                        "  rev:1;",
                        ")",
                    ]
                )
                detection_artifacts.append(
                    self._detection("suricata", f"{title_root} Suricata", suricata_body, first_network.get("id"))
                )

        if evidence_list and file_terms:
            first_file = next((item for item in evidence_list if item.get("artifact_kind") == "file_diff"), evidence_list[0])
            yara_strings = "\n".join(
                f'    $s{i} = "{term}" ascii nocase'
                for i, term in enumerate(file_terms[:4], start=1)
            )
            yara_body = "\n".join(
                [
                    f"rule SHESHNAAG_{cve_id.replace('-', '_')}",
                    "{",
                    "  meta:",
                    f'    description = "{title_root} file indicator"',
                    f'    package = "{package_name}"',
                    "  strings:",
                    yara_strings or '    $fallback = "/tmp" ascii',
                    "  condition:",
                    "    any of them",
                    "}",
                ]
            )
            detection_artifacts.append(
                self._detection("yara", f"{title_root} YARA", yara_body, first_file.get("id"))
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

        openvex_body = "\n".join(
            [
                "{",
                f'  "cve": "{cve_id}",',
                f'  "status": "{self._suggest_vex_status(findings, network_terms)}",',
                f'  "justification": "Derived from observed runtime evidence for run {run_context.get("run_id")}",',
                f'  "impact_statement": "{self._impact_statement(process_terms, network_terms, file_terms)}"',
                "}",
            ]
        )
        mitigation_artifacts.append(
            {
                "artifact_type": "openvex_suggestion",
                "title": f"{title_root} OpenVEX suggestion",
                "body": openvex_body,
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

    @staticmethod
    def _collect_process_terms(evidence: List[Dict[str, Any]]) -> List[str]:
        terms: List[str] = []
        for item in evidence:
            payload = item.get("payload") or {}
            if not isinstance(payload, dict):
                continue
            processes = payload.get("processes") or payload.get("process_tree") or payload.get("events") or []
            if not isinstance(processes, list):
                continue
            for entry in processes:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name") or entry.get("process_name") or entry.get("comm")
                if isinstance(name, str) and name and name not in terms:
                    terms.append(name)
        return terms

    @staticmethod
    def _collect_network_terms(evidence: List[Dict[str, Any]]) -> List[str]:
        terms: List[str] = []
        for item in evidence:
            payload = item.get("payload") or {}
            if not isinstance(payload, dict):
                continue
            for key in ("egress_summary", "connections", "dns_queries", "http_metadata"):
                rows = payload.get(key) or []
                if not isinstance(rows, list):
                    continue
                for row in rows:
                    if isinstance(row, dict):
                        for field in ("host", "domain", "remote_ip", "dest_ip", "server", "path"):
                            value = row.get(field)
                            if isinstance(value, str) and value and value not in terms:
                                terms.append(value)
        return terms

    @staticmethod
    def _collect_file_terms(evidence: List[Dict[str, Any]]) -> List[str]:
        terms: List[str] = []
        for item in evidence:
            payload = item.get("payload") or {}
            if not isinstance(payload, dict):
                continue
            rows = payload.get("changes") or payload.get("files") or []
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                value = row.get("path") or row.get("file") or row.get("sha256")
                if isinstance(value, str) and value and value not in terms:
                    terms.append(value)
        return terms

    @staticmethod
    def _collect_findings(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for item in evidence:
            payload = item.get("payload") or {}
            if not isinstance(payload, dict):
                continue
            rows = payload.get("findings") or []
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict):
                    findings.append(row)
        return findings

    @staticmethod
    def _suggest_vex_status(findings: List[Dict[str, Any]], network_terms: List[str]) -> str:
        if findings:
            return "affected"
        if network_terms:
            return "under_investigation"
        return "not_affected"

    @staticmethod
    def _impact_statement(process_terms: List[str], network_terms: List[str], file_terms: List[str]) -> str:
        parts: List[str] = []
        if process_terms:
            parts.append(f"Observed process activity: {', '.join(process_terms[:3])}")
        if network_terms:
            parts.append(f"Observed network indicators: {', '.join(network_terms[:3])}")
        if file_terms:
            parts.append(f"Observed file indicators: {', '.join(file_terms[:3])}")
        if not parts:
            return "No high-confidence runtime indicators were preserved."
        return "; ".join(parts)
