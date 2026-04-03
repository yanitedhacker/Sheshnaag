"""CVE management service."""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_

from app.models.cve import CVE, AffectedProduct
from app.models.risk_score import RiskScore
from app.services.intel_service import ThreatIntelService

logger = logging.getLogger(__name__)


class CVEService:
    """Service for CVE queries and management."""
    
    def __init__(self, session: Session):
        self.session = session
        self.intel_service = ThreatIntelService(session)
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed CVE information by CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            
        Returns:
            CVE data dictionary or None
        """
        cve = self.session.query(CVE).filter(CVE.cve_id == cve_id).first()
        
        if not cve:
            return None
        
        # Get latest risk score
        risk_score = self.session.query(RiskScore).filter(
            RiskScore.cve_id == cve.id
        ).order_by(desc(RiskScore.created_at)).first()
        
        return self._cve_to_dict(cve, risk_score)
    
    def search_cves(
        self,
        keyword: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        min_cvss: Optional[float] = None,
        max_cvss: Optional[float] = None,
        risk_level: Optional[str] = None,
        has_exploit: Optional[bool] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        """
        Search CVEs with filters.
        
        Returns:
            Dictionary with results and pagination info
        """
        query = self.session.query(CVE)
        
        # Keyword search in description and CVE ID
        if keyword:
            keyword_filter = f"%{keyword}%"
            query = query.filter(
                or_(
                    CVE.description.ilike(keyword_filter),
                    CVE.cve_id.ilike(keyword_filter)
                )
            )
        
        # Vendor/Product filter
        if vendor or product:
            query = query.join(AffectedProduct)
            if vendor:
                query = query.filter(AffectedProduct.vendor.ilike(f"%{vendor}%"))
            if product:
                query = query.filter(AffectedProduct.product.ilike(f"%{product}%"))
        
        # CVSS range
        if min_cvss is not None:
            query = query.filter(CVE.cvss_v3_score >= min_cvss)
        if max_cvss is not None:
            query = query.filter(CVE.cvss_v3_score <= max_cvss)
        
        # Risk level filter
        if risk_level:
            query = query.join(RiskScore).filter(RiskScore.risk_level == risk_level)
        
        # Exploit filter
        if has_exploit is not None:
            query = query.filter(CVE.exploit_available == has_exploit)
        
        # Date range
        if start_date:
            query = query.filter(CVE.published_date >= start_date)
        if end_date:
            query = query.filter(CVE.published_date <= end_date)
        
        # Get total count
        total = query.count()
        
        # Pagination
        offset = (page - 1) * page_size
        cves = query.order_by(desc(CVE.published_date)).offset(offset).limit(page_size).all()
        
        # Get risk scores for results
        cve_ids = [c.id for c in cves]
        risk_scores = {}
        if cve_ids:
            scores = self.session.query(RiskScore).filter(
                RiskScore.cve_id.in_(cve_ids)
            ).all()
            for score in scores:
                if score.cve_id not in risk_scores:
                    risk_scores[score.cve_id] = score
        
        results = [
            self._cve_to_dict(cve, risk_scores.get(cve.id))
            for cve in cves
        ]
        
        return {
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size
        }
    
    def get_recent_cves(self, days: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """Get CVEs published in the last N days."""
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        cves = self.session.query(CVE).filter(
            CVE.published_date >= cutoff
        ).order_by(desc(CVE.published_date)).limit(limit).all()
        
        cve_ids = [c.id for c in cves]
        risk_scores = {}
        if cve_ids:
            scores = self.session.query(RiskScore).filter(
                RiskScore.cve_id.in_(cve_ids)
            ).all()
            for score in scores:
                if score.cve_id not in risk_scores:
                    risk_scores[score.cve_id] = score
        
        return [
            self._cve_to_dict(cve, risk_scores.get(cve.id))
            for cve in cves
        ]
    
    def get_trending_cves(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get trending CVEs based on recent activity and risk.
        
        Considers: new exploits, high risk, recently modified, etc.
        """
        from datetime import timedelta
        
        # Recent + high risk
        cutoff = datetime.utcnow() - timedelta(days=14)
        
        cves = self.session.query(CVE).join(RiskScore).filter(
            or_(
                CVE.published_date >= cutoff,
                and_(
                    CVE.last_modified_date >= cutoff,
                    RiskScore.risk_level.in_(["CRITICAL", "HIGH"])
                ),
                CVE.exploit_available == True
            )
        ).order_by(
            desc(RiskScore.overall_score),
            desc(CVE.published_date)
        ).limit(limit).all()
        
        cve_ids = [c.id for c in cves]
        risk_scores = {}
        if cve_ids:
            scores = self.session.query(RiskScore).filter(
                RiskScore.cve_id.in_(cve_ids)
            ).all()
            for score in scores:
                if score.cve_id not in risk_scores:
                    risk_scores[score.cve_id] = score
        
        return [
            self._cve_to_dict(cve, risk_scores.get(cve.id))
            for cve in cves
        ]
    
    def get_cve_statistics(self) -> Dict[str, Any]:
        """Get overall CVE statistics."""
        from sqlalchemy import func
        
        total_cves = self.session.query(func.count(CVE.id)).scalar()
        
        # By severity
        severity_dist = {}
        for bucket, label in [(9, "Critical"), (7, "High"), (4, "Medium"), (0, "Low")]:
            if bucket == 9:
                count = self.session.query(func.count(CVE.id)).filter(
                    CVE.cvss_v3_score >= bucket
                ).scalar()
            elif bucket == 0:
                count = self.session.query(func.count(CVE.id)).filter(
                    or_(CVE.cvss_v3_score < 4, CVE.cvss_v3_score.is_(None))
                ).scalar()
            else:
                count = self.session.query(func.count(CVE.id)).filter(
                    CVE.cvss_v3_score >= bucket,
                    CVE.cvss_v3_score < bucket + 2
                ).scalar()
            severity_dist[label] = count
        
        # With exploits
        with_exploits = self.session.query(func.count(CVE.id)).filter(
            CVE.exploit_available == True
        ).scalar()
        
        # Recent (7 days)
        from datetime import timedelta
        recent = self.session.query(func.count(CVE.id)).filter(
            CVE.published_date >= datetime.utcnow() - timedelta(days=7)
        ).scalar()
        
        return {
            "total_cves": total_cves,
            "severity_distribution": severity_dist,
            "with_exploits": with_exploits,
            "recent_7_days": recent,
            "last_updated": datetime.utcnow().isoformat()
        }
    
    def _cve_to_dict(self, cve: CVE, risk_score: Optional[RiskScore] = None) -> Dict[str, Any]:
        """Convert CVE model to dictionary."""
        data = {
            "id": cve.id,
            "cve_id": cve.cve_id,
            "description": cve.description,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "last_modified_date": cve.last_modified_date.isoformat() if cve.last_modified_date else None,
            "cvss_v3_score": cve.cvss_v3_score,
            "cvss_v3_vector": cve.cvss_v3_vector,
            "cvss_v2_score": cve.cvss_v2_score,
            "attack_vector": cve.attack_vector,
            "attack_complexity": cve.attack_complexity,
            "privileges_required": cve.privileges_required,
            "user_interaction": cve.user_interaction,
            "cwe_id": cve.cwe_id,
            "exploit_available": cve.exploit_available,
            "exploit_count": cve.exploit_count,
            "source": cve.source,
        }
        
        # Add affected products
        if hasattr(cve, 'affected_products') and cve.affected_products:
            data["affected_products"] = [
                {
                    "vendor": ap.vendor,
                    "product": ap.product,
                    "version": ap.version
                }
                for ap in cve.affected_products[:10]  # Limit for response size
            ]
        
        # Add risk score if available
        if risk_score:
            data["risk"] = {
                "overall_score": risk_score.overall_score,
                "risk_level": risk_score.risk_level,
                "exploit_probability": risk_score.exploit_probability,
                "priority_rank": risk_score.priority_rank,
                "explanation": risk_score.explanation,
                "top_features": risk_score.top_features
            }

        kev = self.intel_service.get_kev_map([cve.cve_id]).get(cve.cve_id)
        epss = self.intel_service.get_latest_epss_map([cve.cve_id]).get(cve.cve_id)
        techniques = self.intel_service.get_attack_techniques_for_cves([cve.id]).get(cve.id, [])
        documents = self.intel_service.get_knowledge_documents(cve_id=cve.id, limit=5)

        data["intel"] = {
            "kev": {
                "present": True,
                "short_description": kev.short_description,
                "known_ransomware_use": kev.known_ransomware_use,
                "source_url": kev.source_url,
            } if kev else {"present": False},
            "epss": {
                "score": epss.score,
                "percentile": epss.percentile,
                "scored_at": epss.scored_at.isoformat() if epss.scored_at else None,
                "source_url": epss.source_url,
            } if epss else None,
            "attack_techniques": [
                {
                    "external_id": technique.external_id,
                    "name": technique.name,
                    "tactic": technique.tactic,
                    "source_url": technique.source_url,
                }
                for technique in techniques
            ],
            "knowledge_documents": [
                {
                    "title": doc.title,
                    "document_type": doc.document_type,
                    "source_label": doc.source_label,
                    "source_url": doc.source_url,
                }
                for doc in documents
            ],
        }
        
        return data
