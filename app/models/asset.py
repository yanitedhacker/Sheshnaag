"""Asset management models for tracking organizational vulnerabilities."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base


class Asset(Base):
    """Organizational assets (servers, applications, etc.)."""
    
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Asset Identification
    name = Column(String(200), nullable=False)
    asset_type = Column(String(50))  # server, application, network_device, etc.
    
    # Asset Details
    hostname = Column(String(200))
    ip_address = Column(String(50))
    environment = Column(String(50))  # production, staging, development
    criticality = Column(String(20))  # critical, high, medium, low
    
    # Software Stack (for matching against CVEs)
    installed_software = Column(JSON)  # [{"vendor": "apache", "product": "httpd", "version": "2.4.51"}, ...]
    operating_system = Column(String(100))
    os_version = Column(String(50))
    
    # Ownership
    owner = Column(String(100))
    department = Column(String(100))
    
    # Status
    is_active = Column(Boolean, default=True)
    last_scan_date = Column(DateTime)
    
    # Metadata
    tags = Column(JSON)  # Arbitrary tags for filtering
    notes = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    vulnerabilities = relationship("AssetVulnerability", back_populates="asset", cascade="all, delete-orphan")
    patches = relationship("AssetPatch", back_populates="asset", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Asset {self.name}>"


class AssetVulnerability(Base):
    """Mapping between assets and their vulnerabilities."""
    
    __tablename__ = "asset_vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Vulnerability Status
    status = Column(String(30), default="open")  # open, in_progress, patched, accepted_risk, false_positive
    
    # Detection
    detected_date = Column(DateTime, default=datetime.utcnow)
    detection_source = Column(String(50))  # scanner, manual, feed_match
    
    # Resolution
    resolved_date = Column(DateTime)
    resolution_notes = Column(Text)
    
    # Risk Override (manual adjustment)
    risk_override = Column(String(20))  # If org wants to override calculated risk
    override_reason = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")
