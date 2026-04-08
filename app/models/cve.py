"""CVE (Common Vulnerabilities and Exposures) database models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.core.time import utc_now
from app.core.time import utc_now


class CVE(Base):
    """Main CVE entity storing vulnerability information."""
    
    __tablename__ = "cves"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, index=True, nullable=False)  # e.g., CVE-2024-1234
    
    # Basic Info
    description = Column(Text)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    
    # CVSS Scores
    cvss_v3_score = Column(Float)
    cvss_v3_vector = Column(String(100))
    cvss_v2_score = Column(Float)
    cvss_v2_vector = Column(String(100))
    
    # CVSS Components (for feature engineering)
    attack_vector = Column(String(20))  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity = Column(String(20))  # LOW, HIGH
    privileges_required = Column(String(20))  # NONE, LOW, HIGH
    user_interaction = Column(String(20))  # NONE, REQUIRED
    scope = Column(String(20))  # UNCHANGED, CHANGED
    confidentiality_impact = Column(String(20))  # NONE, LOW, HIGH
    integrity_impact = Column(String(20))  # NONE, LOW, HIGH
    availability_impact = Column(String(20))  # NONE, LOW, HIGH
    
    # CWE (Weakness Type)
    cwe_id = Column(String(20))  # e.g., CWE-79 (XSS)
    cwe_name = Column(String(200))
    
    # Exploit Status
    exploit_available = Column(Boolean, default=False)
    exploit_count = Column(Integer, default=0)
    
    # Metadata
    source = Column(String(50))  # NVD, MITRE, etc.
    raw_data = Column(JSON)  # Store original JSON for reference
    
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
    
    # Relationships
    references = relationship("CVEReference", back_populates="cve", cascade="all, delete-orphan")
    affected_products = relationship("AffectedProduct", back_populates="cve", cascade="all, delete-orphan")
    exploits = relationship("Exploit", back_populates="cve", cascade="all, delete-orphan")
    risk_scores = relationship("RiskScore", back_populates="cve", cascade="all, delete-orphan")
    patches = relationship("Patch", secondary="patch_cves", back_populates="cves")
    
    def __repr__(self):
        return f"<CVE {self.cve_id}>"


class CVEReference(Base):
    """References and links associated with a CVE."""
    
    __tablename__ = "cve_references"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    
    url = Column(Text, nullable=False)
    source = Column(String(100))
    tags = Column(JSON)  # e.g., ["Exploit", "Patch", "Vendor Advisory"]
    
    created_at = Column(DateTime, default=utc_now)
    
    # Relationships
    cve = relationship("CVE", back_populates="references")


class AffectedProduct(Base):
    """Products/software affected by a CVE (CPE data)."""
    
    __tablename__ = "affected_products"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    
    # CPE Components
    vendor = Column(String(100), index=True)
    product = Column(String(100), index=True)
    version = Column(String(50))
    version_start = Column(String(50))
    version_end = Column(String(50))
    cpe_uri = Column(Text)  # Full CPE URI
    
    created_at = Column(DateTime, default=utc_now)
    
    # Relationships
    cve = relationship("CVE", back_populates="affected_products")
