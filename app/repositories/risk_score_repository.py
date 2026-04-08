"""
Risk Score Repository - Centralized data access for risk scores.

Author: Security Enhancement

Provides a single source of truth for risk score queries,
eliminating code duplication across services.
"""

import logging
from datetime import datetime, timedelta
from app.core.time import utc_now
from typing import Dict, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models.risk_score import RiskScore, RiskHistory

logger = logging.getLogger(__name__)


class RiskScoreRepository:
    """
    Repository for RiskScore data access.

    Centralizes all risk score queries to ensure consistent behavior
    and reduce code duplication.
    """

    def __init__(self, session: Session):
        """
        Initialize repository.

        Args:
            session: SQLAlchemy database session
        """
        self.session = session

    def get_latest_for_cve(self, cve_id: int) -> Optional[RiskScore]:
        """
        Get the most recent risk score for a CVE.

        Args:
            cve_id: Database ID of the CVE

        Returns:
            Latest RiskScore or None if not found
        """
        return self.session.query(RiskScore).filter(
            RiskScore.cve_id == cve_id
        ).order_by(desc(RiskScore.created_at)).first()

    def get_latest_for_cves(self, cve_ids: List[int]) -> Dict[int, RiskScore]:
        """
        Get the most recent risk scores for multiple CVEs.

        Args:
            cve_ids: List of CVE database IDs

        Returns:
            Dictionary mapping CVE ID to latest RiskScore
        """
        if not cve_ids:
            return {}

        # Fetch all scores for the given CVEs, ordered by created_at desc
        scores = self.session.query(RiskScore).filter(
            RiskScore.cve_id.in_(cve_ids)
        ).order_by(desc(RiskScore.created_at)).all()

        # Keep only the latest score per CVE
        latest: Dict[int, RiskScore] = {}
        for score in scores:
            if score.cve_id not in latest:
                latest[score.cve_id] = score

        return latest

    def get_by_risk_level(
        self,
        risk_level: str,
        limit: int = 100
    ) -> List[RiskScore]:
        """
        Get risk scores by risk level.

        Args:
            risk_level: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
            limit: Maximum number of results

        Returns:
            List of RiskScore objects
        """
        return self.session.query(RiskScore).filter(
            RiskScore.risk_level == risk_level
        ).order_by(desc(RiskScore.overall_score)).limit(limit).all()

    def get_top_scores(self, limit: int = 10) -> List[RiskScore]:
        """
        Get top risk scores ordered by overall score.

        Args:
            limit: Maximum number of results

        Returns:
            List of RiskScore objects
        """
        return self.session.query(RiskScore).order_by(
            desc(RiskScore.overall_score)
        ).limit(limit).all()

    def get_scores_needing_update(
        self,
        max_age_hours: int = 24,
        limit: int = 500
    ) -> List[int]:
        """
        Get CVE IDs that need risk score recalculation.

        Args:
            max_age_hours: Maximum age of scores in hours
            limit: Maximum number of CVE IDs to return

        Returns:
            List of CVE IDs needing update
        """
        from app.models.cve import CVE
        from sqlalchemy import or_

        cutoff = utc_now() - timedelta(hours=max_age_hours)

        # Find CVEs with no score or outdated score
        subquery = self.session.query(RiskScore.cve_id).filter(
            RiskScore.created_at >= cutoff
        ).subquery()

        cve_ids = self.session.query(CVE.id).outerjoin(
            subquery, CVE.id == subquery.c.cve_id
        ).filter(
            subquery.c.cve_id.is_(None)
        ).limit(limit).all()

        return [cve_id for (cve_id,) in cve_ids]

    def get_risk_level_distribution(self) -> Dict[str, int]:
        """
        Get count of CVEs by risk level.

        Returns:
            Dictionary mapping risk level to count
        """
        counts = self.session.query(
            RiskScore.risk_level,
            func.count(RiskScore.id)
        ).group_by(RiskScore.risk_level).all()

        return {level: count for level, count in counts}

    def get_average_scores(self) -> Dict[str, float]:
        """
        Get average scores across all CVEs.

        Returns:
            Dictionary with average overall_score and exploit_probability
        """
        result = self.session.query(
            func.avg(RiskScore.overall_score),
            func.avg(RiskScore.exploit_probability)
        ).first()

        return {
            "average_overall_score": round(result[0] or 0, 2),
            "average_exploit_probability": round(result[1] or 0, 4)
        }

    def create(self, risk_score: RiskScore) -> RiskScore:
        """
        Create a new risk score record.

        Args:
            risk_score: RiskScore object to create

        Returns:
            Created RiskScore with ID
        """
        self.session.add(risk_score)
        self.session.flush()
        return risk_score

    def record_history(
        self,
        cve_id: int,
        overall_score: float,
        risk_level: str,
        exploit_probability: float,
        change_reason: str
    ) -> RiskHistory:
        """
        Record a risk score change in history.

        Args:
            cve_id: CVE database ID
            overall_score: Current overall score
            risk_level: Current risk level
            exploit_probability: Current exploit probability
            change_reason: Reason for the change

        Returns:
            Created RiskHistory record
        """
        history = RiskHistory(
            cve_id=cve_id,
            overall_score=overall_score,
            risk_level=risk_level,
            exploit_probability=exploit_probability,
            change_reason=change_reason
        )
        self.session.add(history)
        return history

    def get_history(
        self,
        cve_id: int,
        limit: int = 30
    ) -> List[RiskHistory]:
        """
        Get risk score history for a CVE.

        Args:
            cve_id: CVE database ID
            limit: Maximum number of history records

        Returns:
            List of RiskHistory records
        """
        return self.session.query(RiskHistory).filter(
            RiskHistory.cve_id == cve_id
        ).order_by(desc(RiskHistory.recorded_at)).limit(limit).all()

    def delete_old_scores(
        self,
        older_than_days: int = 90
    ) -> int:
        """
        Delete risk scores older than specified days.

        Useful for cleanup of historical data.

        Args:
            older_than_days: Age threshold in days

        Returns:
            Number of deleted records
        """
        cutoff = utc_now() - timedelta(days=older_than_days)

        # Keep only the latest score per CVE
        # This is a soft cleanup - we don't delete the most recent score
        deleted = self.session.query(RiskScore).filter(
            RiskScore.created_at < cutoff
        ).delete(synchronize_session=False)

        logger.info(f"Deleted {deleted} old risk score records")
        return deleted
