"""
NVD (National Vulnerability Database) API client.

Author: Archishman Paul

The NVD is the gold standard for vulnerability data. This client handles 
all the quirks of their API:
  - Rate limiting (6 seconds between requests without API key)
  - Pagination for large result sets
  - CVSS vector parsing
  - CPE (product identifier) extraction

Pro tip: Get an NVD API key! It increases your rate limit by 10x.
https://nvd.nist.gov/developers/request-an-api-key

Fun fact: I wrote this client at 2 AM after discovering that the NVD API 
returns dates in a format that Python's datetime doesn't like by default.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

import aiohttp
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.cve import CVE, CVEReference, AffectedProduct

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for fetching CVE data from NVD API v2.0."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6  # seconds between requests (NVD rate limit)
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.nvd_api_key
        self.headers = {}
        if self.api_key:
            self.headers["apiKey"] = self.api_key
            self.RATE_LIMIT_DELAY = 0.6  # With API key, can go faster
    
    async def fetch_cves(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        keyword: Optional[str] = None,
        cve_id: Optional[str] = None,
        results_per_page: int = 100,
        start_index: int = 0
    ) -> Dict[str, Any]:
        """
        Fetch CVEs from NVD API.
        
        Args:
            start_date: Filter by last modified date (start)
            end_date: Filter by last modified date (end)
            keyword: Search keyword
            cve_id: Specific CVE ID to fetch
            results_per_page: Number of results per page (max 2000)
            start_index: Starting index for pagination
            
        Returns:
            Dictionary containing CVE data and metadata
        """
        params = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index
        }
        
        if start_date:
            params["lastModStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if end_date:
            params["lastModEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if keyword:
            params["keywordSearch"] = keyword
        if cve_id:
            params["cveId"] = cve_id
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    self.BASE_URL,
                    params=params,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    elif response.status == 403:
                        logger.error("NVD API rate limit exceeded")
                        raise Exception("Rate limit exceeded")
                    else:
                        logger.error(f"NVD API error: {response.status}")
                        raise Exception(f"API error: {response.status}")
            except asyncio.TimeoutError:
                logger.error("NVD API request timeout")
                raise
    
    async def fetch_recent_cves(self, days: int = 7, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch CVEs modified in the last N days or since a given timestamp."""
        end_date = datetime.now(timezone.utc)
        start_date = since or (end_date - timedelta(days=days))
        
        all_cves = []
        start_index = 0
        
        while True:
            data = await self.fetch_cves(
                start_date=start_date,
                end_date=end_date,
                start_index=start_index
            )
            
            vulnerabilities = data.get("vulnerabilities", [])
            all_cves.extend(vulnerabilities)
            
            total_results = data.get("totalResults", 0)
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += len(vulnerabilities)
            await asyncio.sleep(self.RATE_LIMIT_DELAY)
        
        logger.info(f"Fetched {len(all_cves)} CVEs since {start_date.isoformat()}")
        return all_cves
    
    def parse_cve(self, nvd_cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse NVD CVE data into our model format.
        
        Args:
            nvd_cve: Raw CVE data from NVD API
            
        Returns:
            Parsed CVE dictionary ready for database insertion
        """
        cve_data = nvd_cve.get("cve", {})
        cve_id = cve_data.get("id", "")
        
        # Extract descriptions (prefer English)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else ""
        )
        
        # Extract CVSS v3 data
        metrics = cve_data.get("metrics", {})
        cvss_v3 = None
        cvss_v3_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v3_data:
            cvss_v3 = cvss_v3_data[0].get("cvssData", {})
        
        # Extract CVSS v2 data
        cvss_v2 = None
        cvss_v2_data = metrics.get("cvssMetricV2", [])
        if cvss_v2_data:
            cvss_v2 = cvss_v2_data[0].get("cvssData", {})
        
        # Extract CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_id = None
        cwe_name = None
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_id = desc["value"]
                    break
        
        # Extract references
        references = []
        for ref in cve_data.get("references", []):
            references.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })
        
        # Extract affected products (CPE)
        affected_products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe_uri = cpe_match.get("criteria", "")
                        parts = cpe_uri.split(":")
                        if len(parts) >= 5:
                            affected_products.append({
                                "vendor": parts[3] if len(parts) > 3 else None,
                                "product": parts[4] if len(parts) > 4 else None,
                                "version": parts[5] if len(parts) > 5 else None,
                                "cpe_uri": cpe_uri,
                                "version_start": cpe_match.get("versionStartIncluding"),
                                "version_end": cpe_match.get("versionEndExcluding")
                            })
        
        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": self._parse_date(cve_data.get("published")),
            "last_modified_date": self._parse_date(cve_data.get("lastModified")),
            "cvss_v3_score": cvss_v3.get("baseScore") if cvss_v3 else None,
            "cvss_v3_vector": cvss_v3.get("vectorString") if cvss_v3 else None,
            "cvss_v2_score": cvss_v2.get("baseScore") if cvss_v2 else None,
            "cvss_v2_vector": cvss_v2.get("vectorString") if cvss_v2 else None,
            "attack_vector": cvss_v3.get("attackVector") if cvss_v3 else None,
            "attack_complexity": cvss_v3.get("attackComplexity") if cvss_v3 else None,
            "privileges_required": cvss_v3.get("privilegesRequired") if cvss_v3 else None,
            "user_interaction": cvss_v3.get("userInteraction") if cvss_v3 else None,
            "scope": cvss_v3.get("scope") if cvss_v3 else None,
            "confidentiality_impact": cvss_v3.get("confidentialityImpact") if cvss_v3 else None,
            "integrity_impact": cvss_v3.get("integrityImpact") if cvss_v3 else None,
            "availability_impact": cvss_v3.get("availabilityImpact") if cvss_v3 else None,
            "cwe_id": cwe_id,
            "source": "NVD",
            "raw_data": nvd_cve,
            "references": references,
            "affected_products": affected_products
        }
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            return None
    
    def save_cve_to_db(self, session: Session, parsed_cve: Dict[str, Any]) -> CVE:
        """
        Save parsed CVE data to database.
        
        Args:
            session: Database session
            parsed_cve: Parsed CVE dictionary
            
        Returns:
            Created or updated CVE model instance
        """
        # Check if CVE already exists
        existing_cve = session.query(CVE).filter(CVE.cve_id == parsed_cve["cve_id"]).first()
        
        if existing_cve:
            # Update existing CVE
            for key, value in parsed_cve.items():
                if key not in ["references", "affected_products", "raw_data"] and value is not None:
                    setattr(existing_cve, key, value)
            existing_cve.raw_data = parsed_cve["raw_data"]
            cve = existing_cve
        else:
            # Create new CVE
            cve = CVE(
                cve_id=parsed_cve["cve_id"],
                description=parsed_cve["description"],
                published_date=parsed_cve["published_date"],
                last_modified_date=parsed_cve["last_modified_date"],
                cvss_v3_score=parsed_cve["cvss_v3_score"],
                cvss_v3_vector=parsed_cve["cvss_v3_vector"],
                cvss_v2_score=parsed_cve["cvss_v2_score"],
                cvss_v2_vector=parsed_cve["cvss_v2_vector"],
                attack_vector=parsed_cve["attack_vector"],
                attack_complexity=parsed_cve["attack_complexity"],
                privileges_required=parsed_cve["privileges_required"],
                user_interaction=parsed_cve["user_interaction"],
                scope=parsed_cve["scope"],
                confidentiality_impact=parsed_cve["confidentiality_impact"],
                integrity_impact=parsed_cve["integrity_impact"],
                availability_impact=parsed_cve["availability_impact"],
                cwe_id=parsed_cve["cwe_id"],
                source=parsed_cve["source"],
                raw_data=parsed_cve["raw_data"]
            )
            session.add(cve)
            session.flush()  # Get the ID
        
        # Update references (replace for idempotency)
        if existing_cve:
            session.query(CVEReference).filter(CVEReference.cve_id == cve.id).delete()
        for ref_data in parsed_cve.get("references", []):
            ref = CVEReference(
                cve_id=cve.id,
                url=ref_data["url"],
                source=ref_data["source"],
                tags=ref_data["tags"]
            )
            session.add(ref)

        # Update affected products (replace for idempotency)
        if existing_cve:
            session.query(AffectedProduct).filter(AffectedProduct.cve_id == cve.id).delete()
        for prod_data in parsed_cve.get("affected_products", []):
            prod = AffectedProduct(
                cve_id=cve.id,
                vendor=prod_data["vendor"],
                product=prod_data["product"],
                version=prod_data["version"],
                version_start=prod_data["version_start"],
                version_end=prod_data["version_end"],
                cpe_uri=prod_data["cpe_uri"]
            )
            session.add(prod)
        
        return cve
