"""Behavior similarity + variant diff over specimens.

Builds a 1024-dim feature embedding per specimen from its analysis case
material (indicators, behavior findings, ATT&CK techniques, declared
labels, finding payload tags). The embedding is the existing
HashFallback hash-bow projection so this works deterministically without
ML deps and stays compatible with the existing pgvector column.

Two reads on top of the embeddings:

* :meth:`find_similar` — cosine-rank other specimens in the tenant
* :meth:`variant_diff` — feature-set diff (shared / unique by category)
  plus the cosine of the two embeddings, so analysts get both a
  numerical similarity score and a human-readable explanation of *what*
  the two specimens share.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.embeddings import SpecimenBehaviorEmbedding
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
)
from app.models.v2 import Tenant
from app.services.knowledge_service import (
    HashFallbackEmbeddingProvider,
    cosine_similarity,
)

logger = logging.getLogger(__name__)


def _embed_text(text: str) -> List[float]:
    return HashFallbackEmbeddingProvider().embed(text)


class BehaviorSimilarityService:
    """Specimen-level similarity + variant diff."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # ------------------------------------------------------------- features

    def _collect_features(self, tenant: Tenant, specimen: Specimen) -> Dict[str, Any]:
        """Gather the feature set used for both the embedding and the diff."""

        cases = (
            self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id)
            .all()
        )
        case_ids = [
            c.id for c in cases if specimen.id in (c.specimen_ids or [])
        ]

        indicator_kinds: List[str] = []
        indicator_values: List[str] = []
        finding_types: List[str] = []
        finding_titles: List[str] = []
        attack_techniques: List[str] = []

        if case_ids:
            for ind in (
                self.session.query(IndicatorArtifact)
                .filter(
                    IndicatorArtifact.tenant_id == tenant.id,
                    IndicatorArtifact.analysis_case_id.in_(case_ids),
                )
                .all()
            ):
                indicator_kinds.append(ind.indicator_kind)
                indicator_values.append(ind.value)

            for f in (
                self.session.query(BehaviorFinding)
                .filter(
                    BehaviorFinding.tenant_id == tenant.id,
                    BehaviorFinding.analysis_case_id.in_(case_ids),
                )
                .all()
            ):
                finding_types.append(f.finding_type)
                finding_titles.append(f.title)
                for tech in (f.payload or {}).get("attack_techniques", []) or []:
                    tid = tech.get("technique_id") if isinstance(tech, dict) else tech
                    if tid:
                        attack_techniques.append(str(tid))

        labels = list(specimen.labels or [])
        return {
            "specimen_kind": specimen.specimen_kind,
            "labels": sorted(set(labels)),
            "indicator_kinds": sorted(set(indicator_kinds)),
            "indicator_values": sorted(set(indicator_values)),
            "finding_types": sorted(set(finding_types)),
            "finding_titles": finding_titles,
            "attack_techniques": sorted(set(attack_techniques)),
            "case_count": len(case_ids),
        }

    @staticmethod
    def _features_to_text(features: Dict[str, Any]) -> str:
        """Flatten the feature dict into a deterministic embedding-input string."""

        parts: List[str] = [f"kind:{features.get('specimen_kind') or ''}"]
        for label in features.get("labels", []):
            parts.append(f"label:{label}")
        for k in features.get("indicator_kinds", []):
            parts.append(f"indkind:{k}")
        for v in features.get("indicator_values", []):
            parts.append(f"ioc:{v}")
        for t in features.get("finding_types", []):
            parts.append(f"ftype:{t}")
        for t in features.get("attack_techniques", []):
            parts.append(f"attck:{t}")
        # finding titles bring lexical signal (e.g. "beacon", "persistence")
        for title in features.get("finding_titles", []):
            parts.append(title)
        return " ".join(parts)

    @staticmethod
    def _feature_digest(features: Dict[str, Any]) -> str:
        """Stable digest of the feature set so we can detect re-embed-no-op."""

        canonical = "\n".join(
            f"{k}={features[k]!r}"
            for k in sorted(features.keys())
            if k != "case_count"  # case_count is informational, not a feature
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------- embedding

    def embed_specimen(
        self,
        tenant: Tenant,
        *,
        specimen_id: int,
    ) -> Dict[str, Any]:
        """Compute and persist (upsert by specimen_id) a behavior embedding."""

        specimen = (
            self.session.query(Specimen)
            .filter(Specimen.tenant_id == tenant.id, Specimen.id == specimen_id)
            .first()
        )
        if specimen is None:
            raise ValueError("specimen_not_found")

        features = self._collect_features(tenant, specimen)
        digest = self._feature_digest(features)
        embedding = _embed_text(self._features_to_text(features))

        existing = (
            self.session.query(SpecimenBehaviorEmbedding)
            .filter(SpecimenBehaviorEmbedding.specimen_id == specimen.id)
            .order_by(desc(SpecimenBehaviorEmbedding.created_at))
            .first()
        )
        if existing is not None and existing.feature_digest == digest:
            return {
                "specimen_id": specimen.id,
                "feature_digest": digest,
                "status": "unchanged",
                "created_at": existing.created_at.isoformat() if existing.created_at else None,
            }

        row = SpecimenBehaviorEmbedding(
            specimen_id=specimen.id,
            feature_digest=digest,
            embedding_model=HashFallbackEmbeddingProvider.model_label,
            embedding=embedding,
            created_at=utc_now(),
        )
        self.session.add(row)
        self.session.flush()
        return {
            "specimen_id": specimen.id,
            "feature_digest": digest,
            "embedding_model": HashFallbackEmbeddingProvider.model_label,
            "status": "stored",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    # ------------------------------------------------------------- search

    def find_similar(
        self,
        tenant: Tenant,
        *,
        specimen_id: int,
        top_k: int = 10,
        min_score: float = 0.0,
    ) -> Dict[str, Any]:
        anchor = (
            self.session.query(Specimen)
            .filter(Specimen.tenant_id == tenant.id, Specimen.id == specimen_id)
            .first()
        )
        if anchor is None:
            raise ValueError("specimen_not_found")

        anchor_emb_row = (
            self.session.query(SpecimenBehaviorEmbedding)
            .filter(SpecimenBehaviorEmbedding.specimen_id == anchor.id)
            .order_by(desc(SpecimenBehaviorEmbedding.created_at))
            .first()
        )
        if anchor_emb_row is None:
            # Auto-embed on first lookup so the API has data to compare.
            self.embed_specimen(tenant, specimen_id=anchor.id)
            anchor_emb_row = (
                self.session.query(SpecimenBehaviorEmbedding)
                .filter(SpecimenBehaviorEmbedding.specimen_id == anchor.id)
                .order_by(desc(SpecimenBehaviorEmbedding.created_at))
                .first()
            )
        anchor_vec = list(anchor_emb_row.embedding or [])

        # Tenant-scoped: join through Specimen so we never compare against
        # another tenant's specimens even if their PKs collide on indices.
        candidates: List[Tuple[Specimen, SpecimenBehaviorEmbedding]] = (
            self.session.query(Specimen, SpecimenBehaviorEmbedding)
            .join(
                SpecimenBehaviorEmbedding,
                SpecimenBehaviorEmbedding.specimen_id == Specimen.id,
            )
            .filter(Specimen.tenant_id == tenant.id, Specimen.id != anchor.id)
            .all()
        )

        scored: List[Dict[str, Any]] = []
        for spec, emb in candidates:
            score = cosine_similarity(anchor_vec, list(emb.embedding or []))
            if score < min_score:
                continue
            scored.append({
                "specimen_id": spec.id,
                "name": spec.name,
                "specimen_kind": spec.specimen_kind,
                "score": round(float(score), 6),
                "feature_digest": emb.feature_digest,
            })
        scored.sort(key=lambda r: r["score"], reverse=True)
        return {
            "specimen_id": anchor.id,
            "matches": scored[: max(1, min(int(top_k), 100))],
            "count": min(len(scored), max(1, min(int(top_k), 100))),
        }

    # ------------------------------------------------------------- diff

    def variant_diff(
        self,
        tenant: Tenant,
        *,
        specimen_id_a: int,
        specimen_id_b: int,
    ) -> Dict[str, Any]:
        if specimen_id_a == specimen_id_b:
            raise ValueError("specimens_must_differ")

        a = (
            self.session.query(Specimen)
            .filter(Specimen.tenant_id == tenant.id, Specimen.id == specimen_id_a)
            .first()
        )
        b = (
            self.session.query(Specimen)
            .filter(Specimen.tenant_id == tenant.id, Specimen.id == specimen_id_b)
            .first()
        )
        if a is None or b is None:
            raise ValueError("specimen_not_found")

        feat_a = self._collect_features(tenant, a)
        feat_b = self._collect_features(tenant, b)

        # Cosine score from stored embeddings; auto-embed if missing.
        for spec in (a, b):
            row = (
                self.session.query(SpecimenBehaviorEmbedding)
                .filter(SpecimenBehaviorEmbedding.specimen_id == spec.id)
                .first()
            )
            if row is None:
                self.embed_specimen(tenant, specimen_id=spec.id)

        emb_a = (
            self.session.query(SpecimenBehaviorEmbedding)
            .filter(SpecimenBehaviorEmbedding.specimen_id == a.id)
            .order_by(desc(SpecimenBehaviorEmbedding.created_at))
            .first()
        )
        emb_b = (
            self.session.query(SpecimenBehaviorEmbedding)
            .filter(SpecimenBehaviorEmbedding.specimen_id == b.id)
            .order_by(desc(SpecimenBehaviorEmbedding.created_at))
            .first()
        )
        cosine = cosine_similarity(
            list(emb_a.embedding or []) if emb_a else [],
            list(emb_b.embedding or []) if emb_b else [],
        )

        diff = {}
        for category in (
            "labels",
            "indicator_kinds",
            "indicator_values",
            "finding_types",
            "attack_techniques",
        ):
            set_a = set(feat_a.get(category, []))
            set_b = set(feat_b.get(category, []))
            shared = sorted(set_a & set_b)
            only_a = sorted(set_a - set_b)
            only_b = sorted(set_b - set_a)
            jaccard = (
                len(set_a & set_b) / len(set_a | set_b)
                if (set_a or set_b) else 0.0
            )
            diff[category] = {
                "shared": shared,
                "only_a": only_a,
                "only_b": only_b,
                "jaccard": round(jaccard, 4),
            }

        return {
            "specimen_a": {"id": a.id, "name": a.name, "specimen_kind": a.specimen_kind},
            "specimen_b": {"id": b.id, "name": b.name, "specimen_kind": b.specimen_kind},
            "cosine_similarity": round(float(cosine), 6),
            "feature_diff": diff,
        }
