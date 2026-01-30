"""Feed aggregator for coordinating multiple threat intelligence sources."""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from app.ingestion.nvd_client import NVDClient
from app.ingestion.exploitdb_client import ExploitDBClient
from app.models.cve import CVE

logger = logging.getLogger(__name__)


class FeedAggregator:
    """Coordinates ingestion from multiple threat intelligence feeds."""
    
    def __init__(self, session: Session):
        self.session = session
        self.nvd_client = NVDClient()
        self.exploitdb_client = ExploitDBClient()
    
    async def sync_recent_cves(self, days: int = 7) -> Dict[str, Any]:
        """
        Synchronize recent CVEs from NVD.
        
        Args:
            days: Number of days to look back
            
        Returns:
            Summary of synchronization results
        """
        logger.info(f"Starting CVE sync for last {days} days")
        
        results = {
            "total_fetched": 0,
            "new_cves": 0,
            "updated_cves": 0,
            "errors": []
        }
        
        try:
            # Fetch CVEs from NVD
            raw_cves = await self.nvd_client.fetch_recent_cves(days=days)
            results["total_fetched"] = len(raw_cves)
            
            for raw_cve in raw_cves:
                try:
                    # Parse CVE
                    parsed_cve = self.nvd_client.parse_cve(raw_cve)
                    
                    # Check if exists
                    existing = self.session.query(CVE).filter(
                        CVE.cve_id == parsed_cve["cve_id"]
                    ).first()
                    
                    # Save to database
                    self.nvd_client.save_cve_to_db(self.session, parsed_cve)
                    
                    if existing:
                        results["updated_cves"] += 1
                    else:
                        results["new_cves"] += 1
                        
                except Exception as e:
                    cve_id = raw_cve.get("cve", {}).get("id", "unknown")
                    logger.error(f"Error processing CVE {cve_id}: {e}")
                    results["errors"].append({"cve_id": cve_id, "error": str(e)})
            
            self.session.commit()
            logger.info(f"CVE sync complete: {results['new_cves']} new, {results['updated_cves']} updated")
            
        except Exception as e:
            logger.error(f"CVE sync failed: {e}")
            results["errors"].append({"error": str(e)})
            self.session.rollback()
        
        return results
    
    async def sync_exploits_for_cves(self, cve_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Synchronize exploit information for CVEs.
        
        Args:
            cve_ids: Optional list of specific CVE IDs to sync. If None, sync for all CVEs.
            
        Returns:
            Summary of synchronization results
        """
        logger.info("Starting exploit sync")
        
        results = {
            "cves_processed": 0,
            "exploits_found": 0,
            "new_exploits": 0,
            "errors": []
        }
        
        try:
            # Get CVEs to process
            if cve_ids:
                cves = self.session.query(CVE).filter(CVE.cve_id.in_(cve_ids)).all()
            else:
                # Process CVEs without exploit info or with high severity
                cves = self.session.query(CVE).filter(
                    (CVE.exploit_count == 0) | (CVE.exploit_count.is_(None)),
                    CVE.cvss_v3_score >= 7.0  # Only check high/critical severity
                ).limit(100).all()
            
            for cve in cves:
                try:
                    # Fetch exploits for this CVE
                    exploits = await self.exploitdb_client.fetch_exploits_by_cve(cve.cve_id)
                    results["cves_processed"] += 1
                    
                    for exploit_data in exploits:
                        results["exploits_found"] += 1
                        
                        # Save exploit
                        exploit = self.exploitdb_client.save_exploit_to_db(
                            self.session, 
                            exploit_data,
                            cve=cve
                        )
                        
                        if exploit:
                            results["new_exploits"] += 1
                    
                    # Rate limiting
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Error fetching exploits for {cve.cve_id}: {e}")
                    results["errors"].append({"cve_id": cve.cve_id, "error": str(e)})
            
            self.session.commit()
            logger.info(f"Exploit sync complete: {results['new_exploits']} new exploits found")
            
        except Exception as e:
            logger.error(f"Exploit sync failed: {e}")
            results["errors"].append({"error": str(e)})
            self.session.rollback()
        
        return results
    
    async def full_sync(self, days: int = 30) -> Dict[str, Any]:
        """
        Perform a full synchronization of all feeds.
        
        Args:
            days: Number of days to look back for CVEs
            
        Returns:
            Combined summary of all synchronization results
        """
        logger.info(f"Starting full sync for last {days} days")
        
        results = {
            "cve_sync": {},
            "exploit_sync": {},
            "started_at": datetime.utcnow().isoformat(),
            "completed_at": None
        }
        
        # Sync CVEs first
        results["cve_sync"] = await self.sync_recent_cves(days=days)
        
        # Then sync exploits for new/updated CVEs
        results["exploit_sync"] = await self.sync_exploits_for_cves()
        
        results["completed_at"] = datetime.utcnow().isoformat()
        
        logger.info("Full sync completed")
        return results
