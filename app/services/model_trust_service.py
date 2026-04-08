"""Model trust and explainability metadata for the v2 UI."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from app.core.time import utc_now
from pathlib import Path
from typing import Dict, List

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.core.config import settings
from app.ml.model_registry import get_predictor
from app.models.risk_score import RiskScore
from app.models.v2 import AnalystFeedback, EPSSSnapshot, KnowledgeChunk
from app.services.governance_service import GovernanceService


class ModelTrustService:
    """Expose practical trust metadata without depending on a hosted model."""

    def __init__(self, session: Session):
        self.session = session
        self.governance = GovernanceService(session)

    def get_trust_snapshot(self) -> Dict[str, object]:
        """Return trust metadata consumed by the frontend trust center."""
        predictor = get_predictor()
        recent_scores = self.session.query(RiskScore).order_by(desc(RiskScore.created_at)).limit(200).all()
        latest_epss = self._latest_epss_scores()

        calibration_buckets = defaultdict(list)
        for score in recent_scores:
            bucket = round((score.exploit_probability or 0.0) * 10) / 10
            calibration_buckets[bucket].append(score.overall_score or 0.0)

        calibration_curve = [
            {
                "predicted_probability_bucket": bucket,
                "average_risk_score": round(sum(values) / len(values), 2),
                "sample_size": len(values),
            }
            for bucket, values in sorted(calibration_buckets.items())
        ]

        epss_average = round(sum(latest_epss.values()) / len(latest_epss), 4) if latest_epss else 0.0
        exploit_average = round(
            sum(score.exploit_probability or 0.0 for score in recent_scores) / len(recent_scores),
            4,
        ) if recent_scores else 0.0

        drift_delta = round(abs(epss_average - exploit_average), 4)
        if drift_delta < 0.05:
            drift_status = "stable"
        elif drift_delta < 0.15:
            drift_status = "monitor"
        else:
            drift_status = "review"

        top_feature_counts = defaultdict(int)
        for score in recent_scores:
            for feature in score.top_features or []:
                name = feature.get("feature")
                if name:
                    top_feature_counts[name] += 1

        feature_importance = [
            {"feature": name, "frequency": count}
            for name, count in sorted(top_feature_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        ]

        feedback_rows = (
            self.session.query(AnalystFeedback)
            .order_by(desc(AnalystFeedback.created_at))
            .limit(50)
            .all()
        )
        feedback_summary = defaultdict(int)
        for row in feedback_rows:
            feedback_summary[row.feedback_type] += 1

        score_history = [
            {
                "created_at": score.created_at.isoformat() if score.created_at else None,
                "overall_score": round(score.overall_score or 0.0, 2),
                "exploit_probability": round(score.exploit_probability or 0.0, 4),
            }
            for score in recent_scores[:20]
        ]
        score_history.reverse()

        retrieval_chunk_count = self.session.query(KnowledgeChunk).count()
        training_date = self._model_training_date()

        return {
            "model_version": predictor.model_version,
            "generated_at": utc_now().isoformat(),
            "training_date": training_date,
            "calibration_curve": calibration_curve,
            "feature_importance": feature_importance,
            "drift": {
                "status": drift_status,
                "delta_vs_epss": drift_delta,
                "average_model_exploit_probability": exploit_average,
                "average_epss_score": epss_average,
            },
            "coverage": {
                "recent_scores": len(recent_scores),
                "latest_epss_samples": len(latest_epss),
                "knowledge_chunks": retrieval_chunk_count,
            },
            "score_history": score_history,
            "analyst_feedback": {
                "summary": dict(feedback_summary),
                "recent_items": [self.governance._serialize_feedback(row) for row in feedback_rows[:8]],
            },
            "retrieval": {
                "embedding_model": settings.default_embedding_model,
                "chunk_count": retrieval_chunk_count,
                "index_status": "ready" if retrieval_chunk_count else "empty",
            },
            "baselines": {
                "epss_average": epss_average,
                "model_average": exploit_average,
                "comparison_window": len(recent_scores),
            },
            "notes": [
                "Core prioritization remains deterministic and does not depend on a language model.",
                "Drift status compares recent model exploit probability outputs against latest EPSS baselines.",
                "Analyst feedback and approval history are stored separately so human overrides remain auditable.",
            ],
        }

    def _latest_epss_scores(self) -> Dict[str, float]:
        rows = self.session.query(EPSSSnapshot).order_by(desc(EPSSSnapshot.scored_at)).all()
        latest: Dict[str, float] = {}
        for row in rows:
            if row.cve_id not in latest:
                latest[row.cve_id] = float(row.score)
        return latest

    @staticmethod
    def _model_training_date() -> str | None:
        model_file = Path(settings.model_path) / "risk_model.joblib"
        if model_file.exists():
            return datetime.utcfromtimestamp(model_file.stat().st_mtime).isoformat()
        return None
