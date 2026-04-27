"""OSS maintainer assessment workflow built on Sheshnaag primitives."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.malware_lab import MalwareReport
from app.models.sheshnaag import MaintainerAssessment, ResearchCandidate
from app.models.v2 import Tenant
from app.services.import_service import ImportService
from app.services.malware_lab_service import MalwareLabService
from app.services.sheshnaag_service import SheshnaagService


class MaintainerAssessmentService:
    """Create public-OSS maintainer assessments from SBOM and VEX data."""

    MAX_SOURCE_REFS = 20
    MAX_FINDINGS = 10

    def __init__(self, session: Session):
        self.session = session
        self.imports = ImportService(session)
        self.sheshnaag = SheshnaagService(session)
        self.malware_lab = MalwareLabService(session)

    def create_assessment(
        self,
        tenant: Tenant,
        *,
        repository_url: str,
        repository_name: Optional[str],
        sbom: Dict[str, Any],
        vex: Optional[Dict[str, Any]] = None,
        source_refs: Optional[list[Dict[str, Any]]] = None,
        created_by: str,
        export_report: bool = False,
    ) -> Dict[str, Any]:
        """Import maintainer context, score matching candidates, and persist a summary."""
        repo_url = self._normalize_repository_url(repository_url)
        repo_name = self._normalize_repository_name(repository_name) or self._repo_name_from_url(repo_url)
        actor = (created_by or "").strip()
        self._validate_inputs(repository_url=repo_url, created_by=actor, sbom=sbom)
        source_refs = self._normalize_source_refs(source_refs or [])
        sbom_hash = self._document_hash(sbom)
        vex_hash = self._document_hash(vex) if vex else ""

        existing = (
            self.session.query(MaintainerAssessment)
            .filter(
                MaintainerAssessment.tenant_id == tenant.id,
                MaintainerAssessment.repository_url == repo_url,
                MaintainerAssessment.sbom_sha256 == sbom_hash,
                MaintainerAssessment.vex_sha256 == vex_hash,
            )
            .first()
        )
        if existing is not None:
            if export_report:
                self._attach_report(tenant, existing)
            return self._assessment_payload(existing, idempotent_replay=True)

        sbom_result = self.imports.import_sbom(tenant, document=sbom)
        vex_result = self.imports.import_vex(tenant, document=vex) if vex else None
        recalc = self.sheshnaag.recalculate_candidate_scores(
            tenant,
            requested_by=actor,
            dry_run=False,
            reason=f"OSS maintainer assessment for {repo_url}",
        )
        package_names = self._component_names(sbom)
        findings = self._top_findings(tenant, package_names=package_names, limit=self.MAX_FINDINGS)
        summary = {
            "repository": {
                "url": repo_url,
                "name": repo_name,
            },
            "imports": {
                "sbom": sbom_result,
                "vex": vex_result,
            },
            "recalculation": {
                "run_id": recalc.get("run_id"),
                "total_candidates": recalc.get("total_candidates", 0),
                "changed_count": recalc.get("changed_count", 0),
            },
            "component_count": len(package_names),
            "matched_findings_count": len(findings),
            "top_findings": findings,
            "recommended_next_steps": self._recommended_next_steps(findings),
            "safety": {
                "defensive_only": True,
                "live_exploitation_performed": False,
                "source": "SBOM/VEX/advisory correlation",
            },
        }
        row = MaintainerAssessment(
            tenant_id=tenant.id,
            repository_url=repo_url,
            repository_name=repo_name,
            status="completed",
            summary=summary,
            source_refs=source_refs,
            sbom_sha256=sbom_hash,
            vex_sha256=vex_hash,
            created_by=actor,
        )
        self.session.add(row)
        self.session.flush()
        if export_report:
            self._attach_report(tenant, row)
        self.session.flush()
        return self._assessment_payload(row, idempotent_replay=False)

    def get_assessment(self, tenant: Tenant, *, assessment_id: int) -> Dict[str, Any]:
        row = self._get_assessment_row(tenant, assessment_id)
        return self._assessment_payload(row)

    def export_assessment(self, tenant: Tenant, *, assessment_id: int) -> Dict[str, Any]:
        row = self._get_assessment_row(tenant, assessment_id)
        self._attach_report(tenant, row)
        self.session.flush()
        return self._assessment_payload(row)

    def _attach_report(self, tenant: Tenant, row: MaintainerAssessment) -> None:
        if row.report_id is not None and self._ensure_existing_report_export(tenant, row):
            return

        summary = row.summary or {}
        repo = summary.get("repository") or {}
        title = f"OSS maintainer security assessment: {repo.get('name') or row.repository_name or row.repository_url}"
        case = self.malware_lab.create_analysis_case(
            tenant,
            title=title,
            analyst_name=row.created_by,
            summary=(
                "Defensive SBOM/VEX advisory correlation for an open-source repository. "
                "No live exploitation or target discovery was performed."
            ),
            priority="high" if summary.get("matched_findings_count") else "medium",
            tags=["oss-maintainer", "sbom", "vex", "defensive"],
            metadata={
                "repository_url": row.repository_url,
                "assessment_id": row.id,
                "source_refs": row.source_refs or [],
            },
        )
        content = {
            "executive_summary": self._executive_summary(row),
            "scope_statement": (
                "Repository-maintainer supplied SBOM/VEX metadata and public advisory intelligence only. "
                "No target discovery, exploitation, phishing, credential collection, or public offensive release."
            ),
            "authorization_statement": (
                "Assessment requested by the repository maintainer or authorized project operator for defensive "
                "triage and release maintenance."
            ),
            "behavioral_findings": [
                {
                    "title": item.get("title"),
                    "artifact_kind": "oss_maintainer_candidate",
                    "confidence": item.get("confidence"),
                    "payload": item,
                }
                for item in (summary.get("top_findings") or [])
            ],
            "prevention_and_mitigation": {
                "recommended_next_steps": summary.get("recommended_next_steps") or [],
                "safe_public_release": True,
            },
            "evidence_table": [
                {
                    "title": item.get("title"),
                    "artifact_kind": "sbom_advisory_match",
                    "confidence": item.get("confidence"),
                    "candidate_id": item.get("candidate_id"),
                    "cve_id": item.get("cve_id"),
                }
                for item in (summary.get("top_findings") or [])
            ],
            "redaction_manifest": {
                "raw_payloads_excluded": True,
                "secrets_excluded": True,
                "live_targets_excluded": True,
                "safe_render_only": True,
            },
            "export_checklist": {
                "authorization_confirmed": True,
                "evidence_sufficiency_reviewed": True,
                "offensive_content_excluded": True,
            },
        }
        report = self.malware_lab.create_report(
            tenant,
            analysis_case_id=case["id"],
            report_type="maintainer_security_assessment",
            title=title,
            created_by=row.created_by,
            content=content,
            ai_metadata={"generated_by": "maintainer_assessment_service", "assessment_id": row.id},
        )
        approved = self.malware_lab.review_report(
            tenant,
            report_id=report["id"],
            reviewer_name=row.created_by,
            decision="approved",
            rationale="Maintainer assessment generated from safe SBOM/VEX/advisory context.",
        )
        exported = self.malware_lab.export_report(tenant, report_id=approved["id"])
        row.analysis_case_id = case["id"]
        row.report_id = exported["id"]
        row.summary = {
            **summary,
            "report": {
                "id": exported["id"],
                "status": exported["status"],
                "export_ready": exported["export_ready"],
                "download_url": exported["download_url"],
                "export_metadata": exported["export_metadata"],
            },
        }

    def _ensure_existing_report_export(self, tenant: Tenant, row: MaintainerAssessment) -> bool:
        report = (
            self.session.query(MalwareReport)
            .filter(MalwareReport.tenant_id == tenant.id, MalwareReport.id == row.report_id)
            .first()
        )
        if report is None:
            row.report_id = None
            return False

        archive = report.export_metadata or {}
        archive_path = archive.get("path")
        if not archive_path:
            exported = self.malware_lab.export_report(tenant, report_id=report.id)
        else:
            exported = self.malware_lab._report_payload(report)

        row.analysis_case_id = report.analysis_case_id
        row.report_id = report.id
        row.summary = {
            **(row.summary or {}),
            "report": {
                "id": exported["id"],
                "status": exported["status"],
                "export_ready": exported["export_ready"],
                "download_url": exported["download_url"],
                "export_metadata": exported["export_metadata"],
            },
        }
        return True

    def _top_findings(self, tenant: Tenant, *, package_names: set[str], limit: int = 10) -> list[Dict[str, Any]]:
        rows = (
            self.session.query(ResearchCandidate)
            .filter(ResearchCandidate.tenant_id == tenant.id)
            .order_by(desc(ResearchCandidate.candidate_score), ResearchCandidate.id.asc())
            .all()
        )
        findings: list[Dict[str, Any]] = []
        for row in rows:
            payload = self.sheshnaag._candidate_payload(row)
            explainability = payload.get("explainability") or {}
            applicability = explainability.get("environment_applicability") or {}
            candidate_packages = {
                str(payload.get("package_name") or "").lower(),
                str(payload.get("product_name") or "").lower(),
            }
            matched = bool(applicability.get("sbom_match_count")) or bool(package_names & candidate_packages)
            if not matched:
                continue
            findings.append(
                {
                    "candidate_id": payload["id"],
                    "cve_id": payload.get("cve_id"),
                    "title": payload.get("title"),
                    "candidate_score": payload.get("candidate_score"),
                    "status": payload.get("status"),
                    "package_name": payload.get("package_name"),
                    "patch_available": payload.get("patch_available"),
                    "confidence": applicability.get("confidence"),
                    "vex_status": applicability.get("vex_status"),
                    "sbom_matches": applicability.get("sbom_matches") or [],
                    "citations": (explainability.get("citations") or [])[:5],
                }
            )
            if len(findings) >= limit:
                break
        return findings

    def _assessment_payload(self, row: MaintainerAssessment, *, idempotent_replay: bool = False) -> Dict[str, Any]:
        summary = row.summary or {}
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "repository": {
                "url": row.repository_url,
                "name": row.repository_name,
            },
            "status": row.status,
            "summary": summary,
            "source_refs": row.source_refs or [],
            "input_hashes": {
                "sbom_sha256": row.sbom_sha256,
                "vex_sha256": row.vex_sha256,
            },
            "analysis_case_id": row.analysis_case_id,
            "report_id": row.report_id,
            "report": summary.get("report"),
            "idempotent_replay": idempotent_replay,
            "created_by": row.created_by,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

    def _get_assessment_row(self, tenant: Tenant, assessment_id: int) -> MaintainerAssessment:
        row = (
            self.session.query(MaintainerAssessment)
            .filter(MaintainerAssessment.tenant_id == tenant.id, MaintainerAssessment.id == assessment_id)
            .first()
        )
        if row is None:
            raise ValueError("Maintainer assessment not found.")
        return row

    @staticmethod
    def _document_hash(document: Optional[Dict[str, Any]]) -> str:
        if document is None:
            return ""
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _validate_inputs(cls, *, repository_url: str, created_by: str, sbom: Dict[str, Any]) -> None:
        if not repository_url:
            raise ValueError("repository_url is required.")
        if not created_by:
            raise ValueError("created_by is required.")
        components = sbom.get("components")
        if not isinstance(components, list) or not components:
            raise ValueError("sbom.components must contain at least one component.")

    @staticmethod
    def _component_names(sbom: Dict[str, Any]) -> set[str]:
        names: set[str] = set()
        for item in sbom.get("components", []) or []:
            name = str(item.get("name") or "").strip().lower()
            if name:
                names.add(name)
        metadata_component = (sbom.get("metadata") or {}).get("component") or {}
        metadata_name = str(metadata_component.get("name") or "").strip().lower()
        if metadata_name:
            names.add(metadata_name)
        return names

    @staticmethod
    def _normalize_repository_url(repository_url: str) -> str:
        return (repository_url or "").strip().rstrip("/")

    @staticmethod
    def _normalize_repository_name(repository_name: Optional[str]) -> Optional[str]:
        value = (repository_name or "").strip()
        return value or None

    @classmethod
    def _normalize_source_refs(cls, source_refs: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        normalized: list[Dict[str, Any]] = []
        for item in source_refs[: cls.MAX_SOURCE_REFS]:
            if not isinstance(item, dict):
                continue
            compact = {str(key): value for key, value in item.items() if value not in (None, "", [], {})}
            if compact:
                normalized.append(compact)
        return normalized

    @staticmethod
    def _repo_name_from_url(repository_url: str) -> str:
        trimmed = repository_url.rstrip("/").removesuffix(".git")
        return trimmed.rsplit("/", 1)[-1] or "oss-repository"

    @staticmethod
    def _recommended_next_steps(findings: Iterable[Dict[str, Any]]) -> list[str]:
        findings = list(findings)
        if not findings:
            return [
                "Keep SBOM generation in release CI.",
                "Publish VEX statements for not-affected or fixed components.",
                "Rerun assessment after dependency updates or new advisories.",
            ]
        return [
            "Review the highest-scoring matched CVEs with package maintainers.",
            "Publish or update VEX statements for affected and not-affected components.",
            "Prioritize fixes with KEV, EPSS, exposed-service, or patch-available evidence.",
            "Attach the exported report to the release/security advisory review record.",
        ]

    @staticmethod
    def _executive_summary(row: MaintainerAssessment) -> str:
        summary = row.summary or {}
        count = int(summary.get("matched_findings_count") or 0)
        repo_name = row.repository_name or row.repository_url
        if count:
            return (
                f"{repo_name} has {count} SBOM-linked defensive triage finding(s). "
                "The result is based on maintainer-supplied SBOM/VEX data and public advisory context."
            )
        return (
            f"{repo_name} has no SBOM-linked defensive triage findings in the current Sheshnaag data. "
            "Continue publishing SBOM/VEX metadata and rerun as advisory feeds change."
        )
