"""
Risk aggregation engine for prioritizing CVE patches.

Author: Archishman Paul

This is the command center. All the ML predictions, feature scores, and 
business context come together here to produce a single, actionable 
priority list.

The philosophy is simple: a vulnerability's risk isn't just about its 
CVSS score. It's about:
  - Likelihood of exploitation (our ML prediction)
  - Impact if exploited (CVSS helps here)
  - Exposure in YOUR environment (asset context)
  - How long it's been in the wild (temporal factors)

I weighted these factors based on what I've learned from security 
practitioners. The weights are configurable, but the defaults reflect 
real-world prioritization needs.

The goal? Help security teams sleep better at night by patching what 
actually matters first.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.cve import CVE
from app.models.risk_score import RiskScore, RiskHistory
from app.models.asset import Asset, AssetVulnerability
from app.ml.feature_engineering import FeatureEngineer
from app.ml.model_registry import get_explainer, get_predictor

logger = logging.getLogger(__name__)


class RiskAggregator:
    """
    Aggregates risk scores and prioritizes patches across the organization.
    
    Combines ML predictions with business context to create actionable
    prioritization lists for security teams.
    """
    
    def __init__(self, session: Session):
        self.session = session
        self.feature_engineer = FeatureEngineer(session)
        self.predictor = get_predictor()
        self.explainer = get_explainer()
    
    def calculate_cve_risk(self, cve: CVE) -> RiskScore:
        """
        Calculate and store risk score for a single CVE.
        
        Args:
            cve: CVE model instance
            
        Returns:
            Created RiskScore instance
        """
        # Extract features
        features = self.feature_engineer.extract_features(cve)
        
        # Predict exploit probability
        exploit_prob, conf_lower, conf_upper = self.predictor.predict_exploit_probability(features)
        
        # Calculate full risk score
        risk_scores = self.predictor.calculate_risk_score(features, exploit_prob)
        
        # Generate explanation
        explanation = self.explainer.explain_prediction(features, risk_scores)
        
        # Create RiskScore record
        risk_score = RiskScore(
            cve_id=cve.id,
            overall_score=risk_scores["overall_score"],
            exploit_probability=exploit_prob,
            impact_score=risk_scores["impact_score"],
            exposure_score=risk_scores["exposure_score"],
            temporal_score=risk_scores["temporal_score"],
            risk_level=risk_scores["risk_level"],
            confidence_score=1.0 - (conf_upper - conf_lower),  # Narrower band = higher confidence
            confidence_band_lower=conf_lower,
            confidence_band_upper=conf_upper,
            top_features=explanation["top_features"],
            explanation=explanation["text_explanation"],
            model_version=self.predictor.model_version
        )
        
        self.session.add(risk_score)
        
        return risk_score
    
    def calculate_all_risks(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Calculate risk scores for all CVEs without recent scores.
        
        Args:
            limit: Maximum number of CVEs to process
            
        Returns:
            Summary of processing results
        """
        logger.info("Starting batch risk calculation")
        
        # Find CVEs needing risk calculation
        # (no score or score older than 24 hours)
        from sqlalchemy import or_
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=24)
        
        query = self.session.query(CVE).outerjoin(RiskScore).filter(
            or_(
                RiskScore.id.is_(None),
                RiskScore.created_at < cutoff
            )
        )
        
        if limit:
            query = query.limit(limit)
        
        cves = query.all()
        
        results = {
            "total_processed": 0,
            "scores_created": 0,
            "errors": []
        }
        
        if not cves:
            return results

        try:
            features_df = self.feature_engineer.extract_features_batch(cves)
            probas, lowers, uppers = self.predictor.predict_exploit_probabilities_batch(features_df)

            for idx, cve in enumerate(cves):
                try:
                    features = features_df.iloc[idx].to_dict()
                    exploit_prob = float(probas[idx])
                    conf_lower = float(lowers[idx])
                    conf_upper = float(uppers[idx])
                    risk_scores = self.predictor.calculate_risk_score(features, exploit_prob)
                    explanation = self.explainer.explain_prediction(features, risk_scores)

                    risk_score = RiskScore(
                        cve_id=cve.id,
                        overall_score=risk_scores["overall_score"],
                        exploit_probability=exploit_prob,
                        impact_score=risk_scores["impact_score"],
                        exposure_score=risk_scores["exposure_score"],
                        temporal_score=risk_scores["temporal_score"],
                        risk_level=risk_scores["risk_level"],
                        confidence_score=1.0 - (conf_upper - conf_lower),
                        confidence_band_lower=conf_lower,
                        confidence_band_upper=conf_upper,
                        top_features=explanation["top_features"],
                        explanation=explanation["text_explanation"],
                        model_version=self.predictor.model_version,
                    )
                    self.session.add(risk_score)
                    results["scores_created"] += 1
                except Exception as e:
                    logger.error(f"Error calculating risk for {cve.cve_id}: {e}")
                    results["errors"].append({"cve_id": cve.cve_id, "error": str(e)})
                finally:
                    results["total_processed"] += 1
        except Exception as e:
            logger.error(f"Batch risk calculation failed: {e}")
            results["errors"].append({"error": str(e)})
        
        # Update priority rankings
        self._update_priority_rankings()
        
        self.session.commit()
        
        logger.info(f"Risk calculation complete: {results['scores_created']} scores created")
        return results
    
    def _update_priority_rankings(self):
        """Update priority_rank field based on overall scores."""
        # Get all risk scores ordered by score descending
        scores = self.session.query(RiskScore).order_by(
            desc(RiskScore.overall_score)
        ).all()
        
        for rank, score in enumerate(scores, 1):
            score.priority_rank = rank
    
    def get_top_priorities(
        self,
        limit: int = 10,
        risk_level: Optional[str] = None,
        has_exploit: Optional[bool] = None,
        asset_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get top priority CVEs for patching.
        
        Args:
            limit: Number of results to return
            risk_level: Filter by risk level (CRITICAL, HIGH, MEDIUM, LOW)
            asset_id: Filter by specific asset
            
        Returns:
            List of prioritized CVE data
        """
        query = self.session.query(RiskScore, CVE).join(CVE)
        
        if risk_level:
            query = query.filter(RiskScore.risk_level == risk_level)

        if has_exploit is not None:
            query = query.filter(CVE.exploit_available == has_exploit)
        
        if asset_id:
            query = query.join(AssetVulnerability, AssetVulnerability.cve_id == CVE.id)
            query = query.filter(AssetVulnerability.asset_id == asset_id)
            query = query.filter(AssetVulnerability.status == "open")
        
        query = query.order_by(desc(RiskScore.overall_score)).limit(limit)
        
        results = []
        for risk_score, cve in query.all():
            results.append({
                "cve_id": cve.cve_id,
                "description": cve.description[:200] + "..." if len(cve.description or "") > 200 else cve.description,
                "cvss_score": cve.cvss_v3_score,
                "overall_risk_score": risk_score.overall_score,
                "risk_level": risk_score.risk_level,
                "exploit_probability": risk_score.exploit_probability,
                "priority_rank": risk_score.priority_rank,
                "explanation": risk_score.explanation,
                "top_features": risk_score.top_features,
                "published_date": cve.published_date.isoformat() if cve.published_date else None,
                "exploit_available": cve.exploit_available,
                "exploit_count": cve.exploit_count
            })
        
        return results
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary statistics."""
        from sqlalchemy import func
        
        # Count by risk level
        level_counts = self.session.query(
            RiskScore.risk_level,
            func.count(RiskScore.id)
        ).group_by(RiskScore.risk_level).all()
        
        level_summary = {level: count for level, count in level_counts}
        
        # Average scores
        avg_scores = self.session.query(
            func.avg(RiskScore.overall_score),
            func.avg(RiskScore.exploit_probability)
        ).first()
        
        # Recent high-risk CVEs
        recent_critical = self.session.query(func.count(RiskScore.id)).join(CVE).filter(
            RiskScore.risk_level == "CRITICAL",
            CVE.published_date >= datetime.utcnow() - timedelta(days=7)
        ).scalar()
        
        # Exploited CVEs
        exploited_count = self.session.query(func.count(CVE.id)).filter(
            CVE.exploit_available == True
        ).scalar()
        
        return {
            "total_cves_scored": sum(level_summary.values()),
            "risk_level_distribution": level_summary,
            "average_risk_score": round(avg_scores[0] or 0, 2),
            "average_exploit_probability": round(avg_scores[1] or 0, 4),
            "recent_critical_cves": recent_critical or 0,
            "cves_with_exploits": exploited_count or 0,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    def get_risk_heatmap_data(self) -> Dict[str, Any]:
        """Generate data for risk heatmap visualization."""
        from sqlalchemy import func
        
        # Get counts by CVSS score buckets and exploit status
        data = []
        
        cvss_buckets = [
            (0, 4, "Low"),
            (4, 7, "Medium"),
            (7, 9, "High"),
            (9, 10.1, "Critical")
        ]
        
        for low, high, label in cvss_buckets:
            # With exploit
            with_exploit = self.session.query(func.count(CVE.id)).filter(
                CVE.cvss_v3_score >= low,
                CVE.cvss_v3_score < high,
                CVE.exploit_available == True
            ).scalar() or 0
            
            # Without exploit
            without_exploit = self.session.query(func.count(CVE.id)).filter(
                CVE.cvss_v3_score >= low,
                CVE.cvss_v3_score < high,
                CVE.exploit_available == False
            ).scalar() or 0
            
            data.append({
                "severity": label,
                "with_exploit": with_exploit,
                "without_exploit": without_exploit
            })
        
        return {"heatmap_data": data}
    
    def record_risk_history(self, cve_id: int, reason: str):
        """Record a risk score change in history."""
        current_score = self.session.query(RiskScore).filter(
            RiskScore.cve_id == cve_id
        ).order_by(desc(RiskScore.created_at)).first()
        
        if current_score:
            history = RiskHistory(
                cve_id=cve_id,
                overall_score=current_score.overall_score,
                risk_level=current_score.risk_level,
                exploit_probability=current_score.exploit_probability,
                change_reason=reason
            )
            self.session.add(history)
