"""Risk scoring models for ML predictions."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.time import utc_now
from app.core.time import utc_now


class RiskScore(Base):
    """ML-generated risk scores for CVEs."""
    
    __tablename__ = "risk_scores"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Overall Risk Score (0-100)
    overall_score = Column(Float, nullable=False, index=True)
    
    # Component Scores (0-100)
    exploit_probability = Column(Float)  # ML-predicted likelihood of exploitation
    impact_score = Column(Float)  # Based on CVSS impact metrics
    exposure_score = Column(Float)  # Based on affected products popularity
    temporal_score = Column(Float)  # Time-based risk decay/increase
    
    # Risk Classification
    risk_level = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    priority_rank = Column(Integer)  # 1 = highest priority
    
    # Confidence
    confidence_score = Column(Float)  # Model confidence (0-1)
    confidence_band_lower = Column(Float)
    confidence_band_upper = Column(Float)
    
    # Explainability (SHAP-based)
    top_features = Column(JSON)  # [{"feature": "exploit_available", "contribution": 0.25}, ...]
    explanation = Column(Text)  # Human-readable explanation
    
    # Model Info
    model_version = Column(String(50))
    
    created_at = Column(DateTime, default=utc_now)
    
    # Relationships
    cve = relationship("CVE", back_populates="risk_scores")
    
    def __repr__(self):
        return f"<RiskScore CVE={self.cve_id} Score={self.overall_score}>"


class RiskHistory(Base):
    """Historical tracking of risk score changes."""
    
    __tablename__ = "risk_history"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    
    overall_score = Column(Float, nullable=False)
    risk_level = Column(String(20))
    exploit_probability = Column(Float)
    
    # What changed
    change_reason = Column(String(200))  # e.g., "New exploit discovered", "CVSS updated"
    
    recorded_at = Column(DateTime, default=utc_now, index=True)
