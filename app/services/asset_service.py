"""Asset management service."""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.models.asset import Asset, AssetVulnerability
from app.models.cve import CVE, AffectedProduct
from app.models.risk_score import RiskScore

logger = logging.getLogger(__name__)


class AssetService:
    """Service for asset and vulnerability management."""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_asset(self, asset_data: Dict[str, Any]) -> Asset:
        """Create a new asset."""
        asset = Asset(
            tenant_id=asset_data.get("tenant_id"),
            name=asset_data["name"],
            asset_type=asset_data.get("asset_type"),
            hostname=asset_data.get("hostname"),
            ip_address=asset_data.get("ip_address"),
            environment=asset_data.get("environment"),
            criticality=asset_data.get("criticality", "medium"),
            business_criticality=asset_data.get("business_criticality", asset_data.get("criticality", "medium")),
            is_crown_jewel=asset_data.get("is_crown_jewel", False),
            installed_software=asset_data.get("installed_software", []),
            operating_system=asset_data.get("operating_system"),
            os_version=asset_data.get("os_version"),
            owner=asset_data.get("owner"),
            department=asset_data.get("department"),
            tags=asset_data.get("tags", []),
            notes=asset_data.get("notes")
        )
        
        self.session.add(asset)
        self.session.flush()
        
        return asset
    
    def get_asset(self, asset_id: int) -> Optional[Dict[str, Any]]:
        """Get asset by ID with vulnerability summary."""
        asset = self.session.query(Asset).filter(Asset.id == asset_id).first()
        
        if not asset:
            return None
        
        # Get vulnerability counts
        vuln_counts = self.session.query(
            AssetVulnerability.status,
            func.count(AssetVulnerability.id)
        ).filter(
            AssetVulnerability.asset_id == asset_id
        ).group_by(AssetVulnerability.status).all()
        
        vuln_summary = {status: count for status, count in vuln_counts}
        
        return {
            "id": asset.id,
            "name": asset.name,
            "tenant_id": asset.tenant_id,
            "asset_type": asset.asset_type,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "business_criticality": asset.business_criticality,
            "is_crown_jewel": asset.is_crown_jewel,
            "installed_software": asset.installed_software,
            "operating_system": asset.operating_system,
            "os_version": asset.os_version,
            "owner": asset.owner,
            "department": asset.department,
            "tags": asset.tags,
            "is_active": asset.is_active,
            "last_scan_date": asset.last_scan_date.isoformat() if asset.last_scan_date else None,
            "vulnerability_summary": vuln_summary,
            "total_open_vulnerabilities": vuln_summary.get("open", 0)
        }
    
    def list_assets(
        self,
        tenant_id: Optional[int] = None,
        environment: Optional[str] = None,
        criticality: Optional[str] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Dict[str, Any]:
        """List assets with filters."""
        query = self.session.query(Asset).filter(Asset.is_active == True)

        if tenant_id is not None:
            query = query.filter(Asset.tenant_id == tenant_id)
        
        if environment:
            query = query.filter(Asset.environment == environment)
        if criticality:
            query = query.filter(Asset.criticality == criticality)
        
        total = query.count()
        offset = (page - 1) * page_size
        
        assets = query.order_by(Asset.name).offset(offset).limit(page_size).all()
        
        results = []
        for asset in assets:
            open_vulns = self.session.query(func.count(AssetVulnerability.id)).filter(
                AssetVulnerability.asset_id == asset.id,
                AssetVulnerability.status == "open"
            ).scalar()
            
            results.append({
                "id": asset.id,
                "name": asset.name,
                "tenant_id": asset.tenant_id,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "criticality": asset.criticality,
                "business_criticality": asset.business_criticality,
                "is_crown_jewel": asset.is_crown_jewel,
                "open_vulnerabilities": open_vulns
            })
        
        return {
            "results": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size
        }
    
    def scan_asset_for_vulnerabilities(self, asset_id: int) -> Dict[str, Any]:
        """
        Scan an asset's software stack against known CVEs.
        
        Matches installed software versions against CVE affected products.
        """
        asset = self.session.query(Asset).filter(Asset.id == asset_id).first()
        
        if not asset:
            return {"error": "Asset not found"}
        
        results = {
            "asset_id": asset_id,
            "asset_name": asset.name,
            "vulnerabilities_found": 0,
            "new_vulnerabilities": 0,
            "matches": []
        }
        
        installed_software = asset.installed_software or []
        
        for software in installed_software:
            vendor = software.get("vendor", "").lower()
            product = software.get("product", "").lower()
            version = software.get("version", "")
            
            if not vendor or not product:
                continue
            
            # Find matching CVEs
            matching_cves = self.session.query(CVE).join(AffectedProduct).filter(
                func.lower(AffectedProduct.vendor) == vendor,
                func.lower(AffectedProduct.product) == product
            ).all()
            
            for cve in matching_cves:
                results["vulnerabilities_found"] += 1
                
                # Check if already tracked
                existing = self.session.query(AssetVulnerability).filter(
                    AssetVulnerability.asset_id == asset_id,
                    AssetVulnerability.cve_id == cve.id
                ).first()
                
                if not existing:
                    # Create new vulnerability record
                    vuln = AssetVulnerability(
                        asset_id=asset_id,
                        cve_id=cve.id,
                        status="open",
                        detection_source="feed_match",
                        detected_date=datetime.utcnow()
                    )
                    self.session.add(vuln)
                    results["new_vulnerabilities"] += 1
                
                # Get risk score
                risk_score = self.session.query(RiskScore).filter(
                    RiskScore.cve_id == cve.id
                ).order_by(desc(RiskScore.created_at)).first()
                
                results["matches"].append({
                    "cve_id": cve.cve_id,
                    "software": f"{vendor}/{product}",
                    "version": version,
                    "cvss_score": cve.cvss_v3_score,
                    "risk_level": risk_score.risk_level if risk_score else None,
                    "is_new": existing is None
                })
        
        # Update scan date
        asset.last_scan_date = datetime.utcnow()
        self.session.commit()
        
        return results
    
    def get_asset_vulnerabilities(
        self,
        asset_id: int,
        status: Optional[str] = None,
        risk_level: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific asset."""
        query = self.session.query(
            AssetVulnerability, CVE, RiskScore
        ).join(CVE).outerjoin(
            RiskScore, RiskScore.cve_id == CVE.id
        ).filter(
            AssetVulnerability.asset_id == asset_id
        )
        
        if status:
            query = query.filter(AssetVulnerability.status == status)
        if risk_level:
            query = query.filter(RiskScore.risk_level == risk_level)
        
        query = query.order_by(desc(RiskScore.overall_score))
        
        results = []
        for vuln, cve, risk_score in query.all():
            results.append({
                "vulnerability_id": vuln.id,
                "cve_id": cve.cve_id,
                "description": cve.description[:200] if cve.description else None,
                "cvss_score": cve.cvss_v3_score,
                "status": vuln.status,
                "detected_date": vuln.detected_date.isoformat() if vuln.detected_date else None,
                "risk_level": risk_score.risk_level if risk_score else None,
                "overall_risk_score": risk_score.overall_score if risk_score else None,
                "exploit_available": cve.exploit_available
            })
        
        return results
    
    def update_vulnerability_status(
        self,
        vulnerability_id: int,
        status: str,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update vulnerability status."""
        vuln = self.session.query(AssetVulnerability).filter(
            AssetVulnerability.id == vulnerability_id
        ).first()
        
        if not vuln:
            return {"error": "Vulnerability not found"}
        
        vuln.status = status
        if notes:
            vuln.resolution_notes = notes
        
        if status in ["patched", "accepted_risk", "false_positive"]:
            vuln.resolved_date = datetime.utcnow()
        
        self.session.commit()
        
        return {"status": "updated", "new_status": status}
    
    def get_organization_risk_summary(self, tenant_id: Optional[int] = None) -> Dict[str, Any]:
        """Get organization-wide vulnerability risk summary."""
        asset_filter = [Asset.is_active == True]
        if tenant_id is not None:
            asset_filter.append(Asset.tenant_id == tenant_id)

        # Total assets
        total_assets = self.session.query(func.count(Asset.id)).filter(
            *asset_filter
        ).scalar()
        
        # Assets by criticality
        criticality_dist = self.session.query(
            Asset.criticality,
            func.count(Asset.id)
        ).filter(*asset_filter).group_by(Asset.criticality).all()
        
        # Open vulnerabilities by risk level
        vuln_by_risk = self.session.query(
            RiskScore.risk_level,
            func.count(AssetVulnerability.id)
        ).join(
            CVE, CVE.id == RiskScore.cve_id
        ).join(
            AssetVulnerability, AssetVulnerability.cve_id == CVE.id
        ).join(
            Asset, Asset.id == AssetVulnerability.asset_id
        ).filter(
            AssetVulnerability.status == "open",
            *asset_filter
        ).group_by(RiskScore.risk_level).all()
        
        # Most vulnerable assets
        most_vulnerable = self.session.query(
            Asset.id,
            Asset.name,
            Asset.criticality,
            func.count(AssetVulnerability.id).label("vuln_count")
        ).join(AssetVulnerability).filter(
            AssetVulnerability.status == "open",
            *asset_filter
        ).group_by(Asset.id).order_by(desc("vuln_count")).limit(5).all()
        
        return {
            "total_assets": total_assets,
            "criticality_distribution": {c: count for c, count in criticality_dist},
            "open_vulnerabilities_by_risk": {r: count for r, count in vuln_by_risk},
            "total_open_vulnerabilities": sum(count for _, count in vuln_by_risk),
            "most_vulnerable_assets": [
                {"id": a[0], "name": a[1], "criticality": a[2], "vulnerability_count": a[3]}
                for a in most_vulnerable
            ],
            "last_updated": datetime.utcnow().isoformat()
        }
