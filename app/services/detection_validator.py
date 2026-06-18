"""Validate proposed detection rules against the lab telemetry corpus."""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy.orm import Session

from app.models.malware_lab import BehaviorFinding
from app.models.sheshnaag import DetectionArtifact, LabRun
from app.models.v2 import Tenant

_SUPPORTED_KINDS = frozenset({"sigma", "yara", "snort", "falco"})
_TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]{3,}")


def _draft_text(kind: str, draft: dict[str, Any]) -> str:
    if kind == "yara":
        for key in ("rule", "source", "body"):
            value = draft.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return json.dumps(draft, sort_keys=True, default=str)


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text)}


class DetectionValidatorService:
    """Lightweight validator used by the AI ``propose_detection`` tool."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def validate(self, tenant: Tenant, *, kind: str, draft: dict[str, Any]) -> dict[str, Any]:
        normalized_kind = (kind or "").strip().lower()
        if normalized_kind not in _SUPPORTED_KINDS:
            return {
                "valid": False,
                "errors": [f"unsupported_kind:{normalized_kind or 'empty'}"],
                "warnings": [],
                "validator": {
                    "precision": None,
                    "recall": None,
                    "f1": None,
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                },
                "corpus_size": 0,
            }

        draft_dict = draft if isinstance(draft, dict) else {"raw": str(draft)}
        errors = self._validate_structure(normalized_kind, draft_dict)
        warnings: list[str] = []

        if normalized_kind == "yara":
            compile_error = self._compile_yara(_draft_text(normalized_kind, draft_dict))
            if compile_error:
                errors.append(compile_error)

        corpus = self._load_corpus(tenant)
        metrics = self._score_against_corpus(_draft_text(normalized_kind, draft_dict), corpus)
        if metrics["corpus_size"] == 0:
            warnings.append("empty_validation_corpus")

        return {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "validator": {
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "true_positives": metrics["true_positives"],
                "false_positives": metrics["false_positives"],
                "false_negatives": metrics["false_negatives"],
            },
            "corpus_size": metrics["corpus_size"],
        }

    @staticmethod
    def _validate_structure(kind: str, draft: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        if kind == "sigma":
            for field in ("title", "logsource", "detection"):
                if field not in draft:
                    errors.append(f"missing_{field}")
        elif kind == "yara":
            if not any(isinstance(draft.get(key), str) and draft[key].strip() for key in ("rule", "source", "body")):
                errors.append("missing_rule_body")
        elif kind in {"snort", "falco"}:
            if not any(
                isinstance(draft.get(key), str) and draft[key].strip()
                for key in ("rule", "body", "condition", "output")
            ):
                errors.append("missing_rule_body")
        return errors

    @staticmethod
    def _compile_yara(rule_text: str) -> str | None:
        try:
            import yara  # type: ignore
        except ImportError:
            return "yara_python_not_installed"
        try:
            yara.compile(source=rule_text)
        except Exception as exc:
            return f"yara_compile_error:{type(exc).__name__}:{exc}"
        return None

    def _load_corpus(self, tenant: Tenant) -> list[str]:
        texts: list[str] = []
        findings = (
            self._session.query(BehaviorFinding)
            .filter(BehaviorFinding.tenant_id == tenant.id)
            .order_by(BehaviorFinding.updated_at.desc())
            .limit(500)
            .all()
        )
        for row in findings:
            parts = [row.title or "", row.finding_type or "", row.severity or ""]
            payload = row.payload if isinstance(row.payload, dict) else {}
            parts.append(json.dumps(payload, sort_keys=True, default=str))
            texts.append("\n".join(parts))

        detections = (
            self._session.query(DetectionArtifact)
            .join(LabRun, LabRun.id == DetectionArtifact.run_id)
            .filter(LabRun.tenant_id == tenant.id)
            .order_by(DetectionArtifact.updated_at.desc())
            .limit(200)
            .all()
        )
        for row in detections:
            texts.append("\n".join([row.name or "", row.artifact_type or "", row.rule_body or ""]))
        return texts

    @staticmethod
    def _score_against_corpus(rule_text: str, corpus: list[str]) -> dict[str, Any]:
        draft_tokens = _tokenize(rule_text)
        if not draft_tokens:
            return {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "true_positives": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "corpus_size": len(corpus),
            }

        matched = 0
        for item in corpus:
            overlap = draft_tokens & _tokenize(item)
            if len(overlap) >= max(1, min(3, len(draft_tokens) // 4 or 1)):
                matched += 1

        corpus_size = len(corpus)
        true_positives = matched
        false_negatives = max(corpus_size - matched, 0)
        false_positives = max(len(draft_tokens) - len({t for text in corpus for t in _tokenize(text) if t in draft_tokens}), 0)
        precision = true_positives / max(true_positives + false_positives, 1)
        recall = true_positives / max(corpus_size, 1)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "corpus_size": corpus_size,
        }
