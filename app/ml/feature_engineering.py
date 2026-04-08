"""
Feature engineering for CVE risk prediction.

Author: Archishman Paul

This is where the magic happens. After spending way too many hours reading 
security research papers and analyzing real-world exploit patterns, I 
distilled everything into 40+ features that actually matter.

The key insight? CVSS scores alone are terrible predictors. What really 
matters is the combination of:
  - How easy is it to exploit? (attack complexity, privileges needed)
  - Is there already exploit code in the wild?
  - How many systems are affected?
  - Is this a "sexy" vulnerability type that attackers love? (RCE, SQLi, etc.)

Feature engineering is an art. These features represent my understanding 
of what makes a vulnerability dangerous in practice, not just in theory.
"""

import logging
from datetime import datetime, timedelta
from app.core.time import utc_now
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.models.cve import CVE, AffectedProduct
from app.models.exploit import Exploit

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Transforms raw CVE data into ML-ready features."""
    
    # Categorical mappings for CVSS components
    ATTACK_VECTOR_MAP = {"NETWORK": 4, "ADJACENT_NETWORK": 3, "LOCAL": 2, "PHYSICAL": 1, None: 0}
    ATTACK_COMPLEXITY_MAP = {"LOW": 2, "HIGH": 1, None: 0}
    PRIVILEGES_MAP = {"NONE": 3, "LOW": 2, "HIGH": 1, None: 0}
    USER_INTERACTION_MAP = {"NONE": 2, "REQUIRED": 1, None: 0}
    SCOPE_MAP = {"CHANGED": 2, "UNCHANGED": 1, None: 0}
    IMPACT_MAP = {"HIGH": 3, "LOW": 2, "NONE": 1, None: 0}
    
    # High-risk CWE categories
    HIGH_RISK_CWES = {
        "CWE-79",   # XSS
        "CWE-89",   # SQL Injection
        "CWE-94",   # Code Injection
        "CWE-78",   # OS Command Injection
        "CWE-22",   # Path Traversal
        "CWE-434",  # Unrestricted File Upload
        "CWE-502",  # Deserialization
        "CWE-287",  # Improper Authentication
        "CWE-306",  # Missing Authentication
        "CWE-798",  # Hardcoded Credentials
        "CWE-862",  # Missing Authorization
        "CWE-918",  # SSRF
        "CWE-77",   # Command Injection
        "CWE-20",   # Input Validation
    }
    
    # Popular/Critical vendors and products
    CRITICAL_VENDORS = {
        "microsoft", "linux", "apache", "oracle", "cisco", "vmware",
        "adobe", "google", "apple", "ibm", "redhat", "wordpress",
        "jenkins", "docker", "kubernetes", "nginx", "openssh"
    }
    
    def __init__(self, session: Optional[Session] = None):
        self.session = session
    
    def extract_features(self, cve: CVE) -> Dict[str, Any]:
        """
        Extract all features for a single CVE.
        
        Args:
            cve: CVE model instance
            
        Returns:
            Dictionary of feature names to values
        """
        features = {}
        
        # CVSS-based features
        features.update(self._extract_cvss_features(cve))
        
        # Temporal features
        features.update(self._extract_temporal_features(cve))
        
        # Exploit features
        features.update(self._extract_exploit_features(cve))
        
        # Product/Vendor features
        features.update(self._extract_product_features(cve))
        
        # CWE features
        features.update(self._extract_cwe_features(cve))
        
        # Text-based features
        features.update(self._extract_text_features(cve))
        
        return features
    
    def _extract_cvss_features(self, cve: CVE) -> Dict[str, Any]:
        """Extract CVSS-related features."""
        return {
            # Base scores
            "cvss_v3_score": cve.cvss_v3_score or 0.0,
            "cvss_v2_score": cve.cvss_v2_score or 0.0,
            "has_cvss_v3": 1 if cve.cvss_v3_score else 0,
            
            # CVSS v3 components (encoded)
            "attack_vector": self.ATTACK_VECTOR_MAP.get(cve.attack_vector, 0),
            "attack_complexity": self.ATTACK_COMPLEXITY_MAP.get(cve.attack_complexity, 0),
            "privileges_required": self.PRIVILEGES_MAP.get(cve.privileges_required, 0),
            "user_interaction": self.USER_INTERACTION_MAP.get(cve.user_interaction, 0),
            "scope": self.SCOPE_MAP.get(cve.scope, 0),
            "confidentiality_impact": self.IMPACT_MAP.get(cve.confidentiality_impact, 0),
            "integrity_impact": self.IMPACT_MAP.get(cve.integrity_impact, 0),
            "availability_impact": self.IMPACT_MAP.get(cve.availability_impact, 0),
            
            # Derived CVSS features
            "is_critical": 1 if (cve.cvss_v3_score or 0) >= 9.0 else 0,
            "is_high_severity": 1 if (cve.cvss_v3_score or 0) >= 7.0 else 0,
            "is_network_exploitable": 1 if cve.attack_vector == "NETWORK" else 0,
            "is_easy_exploit": 1 if cve.attack_complexity == "LOW" and cve.privileges_required == "NONE" else 0,
        }
    
    def _extract_temporal_features(self, cve: CVE) -> Dict[str, Any]:
        """Extract time-based features."""
        now = utc_now()
        
        # Days since published
        days_since_published = 0
        if cve.published_date:
            days_since_published = (now - cve.published_date).days
        
        # Days since last modified
        days_since_modified = 0
        if cve.last_modified_date:
            days_since_modified = (now - cve.last_modified_date).days
        
        # Recently modified flag
        recently_modified = 1 if days_since_modified <= 30 else 0
        
        # Publication age buckets
        age_bucket = 0
        if days_since_published <= 7:
            age_bucket = 5  # Very new
        elif days_since_published <= 30:
            age_bucket = 4  # New
        elif days_since_published <= 90:
            age_bucket = 3  # Recent
        elif days_since_published <= 365:
            age_bucket = 2  # This year
        else:
            age_bucket = 1  # Old
        
        return {
            "days_since_published": days_since_published,
            "days_since_modified": days_since_modified,
            "recently_modified": recently_modified,
            "age_bucket": age_bucket,
            "is_new_cve": 1 if days_since_published <= 30 else 0,
            "log_age": np.log1p(days_since_published),
        }
    
    def _extract_exploit_features(self, cve: CVE) -> Dict[str, Any]:
        """Extract exploit-related features."""
        exploit_count = cve.exploit_count or 0
        has_exploit = cve.exploit_available or exploit_count > 0
        
        # Check for specific exploit characteristics
        has_metasploit = False
        has_poc = False
        exploit_types = set()
        
        if hasattr(cve, 'exploits') and cve.exploits:
            for exploit in cve.exploits:
                if exploit.has_metasploit_module:
                    has_metasploit = True
                if exploit.has_poc:
                    has_poc = True
                if exploit.exploit_type:
                    exploit_types.add(exploit.exploit_type)
        
        return {
            "has_exploit": 1 if has_exploit else 0,
            "exploit_count": exploit_count,
            "log_exploit_count": np.log1p(exploit_count),
            "has_metasploit": 1 if has_metasploit else 0,
            "has_poc": 1 if has_poc else 0,
            "exploit_type_count": len(exploit_types),
            "has_remote_exploit": 1 if "remote" in exploit_types else 0,
        }
    
    def _extract_product_features(self, cve: CVE) -> Dict[str, Any]:
        """Extract affected product features."""
        vendors = set()
        products = set()
        
        if hasattr(cve, 'affected_products') and cve.affected_products:
            for ap in cve.affected_products:
                if ap.vendor:
                    vendors.add(ap.vendor.lower())
                if ap.product:
                    products.add(ap.product.lower())
        
        # Check for critical vendors
        has_critical_vendor = bool(vendors & self.CRITICAL_VENDORS)
        
        return {
            "vendor_count": len(vendors),
            "product_count": len(products),
            "has_critical_vendor": 1 if has_critical_vendor else 0,
            "is_multi_vendor": 1 if len(vendors) > 1 else 0,
            "log_product_count": np.log1p(len(products)),
        }
    
    def _extract_cwe_features(self, cve: CVE) -> Dict[str, Any]:
        """Extract CWE-related features."""
        cwe_id = cve.cwe_id or ""
        
        return {
            "has_cwe": 1 if cwe_id else 0,
            "is_high_risk_cwe": 1 if cwe_id in self.HIGH_RISK_CWES else 0,
            "is_injection_cwe": 1 if any(c in cwe_id for c in ["CWE-89", "CWE-78", "CWE-77", "CWE-94"]) else 0,
            "is_auth_cwe": 1 if any(c in cwe_id for c in ["CWE-287", "CWE-306", "CWE-862"]) else 0,
        }
    
    def _extract_text_features(self, cve: CVE) -> Dict[str, Any]:
        """Extract features from description text."""
        description = (cve.description or "").lower()
        
        # Keywords indicating severity/exploitability
        keywords = {
            "remote_code_exec": ["remote code execution", "rce", "arbitrary code"],
            "privilege_escalation": ["privilege escalation", "elevate privileges", "root access"],
            "denial_of_service": ["denial of service", "dos", "crash", "hang"],
            "information_disclosure": ["information disclosure", "leak", "sensitive data"],
            "authentication_bypass": ["authentication bypass", "bypass authentication"],
            "sql_injection": ["sql injection", "sqli"],
            "xss": ["cross-site scripting", "xss"],
            "buffer_overflow": ["buffer overflow", "stack overflow", "heap overflow"],
        }
        
        features = {}
        for key, terms in keywords.items():
            features[f"text_{key}"] = 1 if any(term in description for term in terms) else 0
        
        # Description length (longer often means more complex)
        features["description_length"] = len(description)
        features["log_description_length"] = np.log1p(len(description))
        
        return features
    
    def extract_features_batch(self, cves: List[CVE]) -> pd.DataFrame:
        """
        Extract features for multiple CVEs.
        
        Args:
            cves: List of CVE model instances
            
        Returns:
            DataFrame with features for all CVEs
        """
        all_features = []
        
        for cve in cves:
            features = self.extract_features(cve)
            features["cve_id"] = cve.cve_id
            features["db_id"] = cve.id
            all_features.append(features)
        
        return pd.DataFrame(all_features)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names used in model training."""
        return [
            # CVSS features
            "cvss_v3_score", "cvss_v2_score", "has_cvss_v3",
            "attack_vector", "attack_complexity", "privileges_required",
            "user_interaction", "scope", "confidentiality_impact",
            "integrity_impact", "availability_impact",
            "is_critical", "is_high_severity", "is_network_exploitable", "is_easy_exploit",
            
            # Temporal features
            "days_since_published", "days_since_modified", "recently_modified",
            "age_bucket", "is_new_cve", "log_age",
            
            # Exploit features
            "has_exploit", "exploit_count", "log_exploit_count",
            "has_metasploit", "has_poc", "exploit_type_count", "has_remote_exploit",
            
            # Product features
            "vendor_count", "product_count", "has_critical_vendor",
            "is_multi_vendor", "log_product_count",
            
            # CWE features
            "has_cwe", "is_high_risk_cwe", "is_injection_cwe", "is_auth_cwe",
            
            # Text features
            "text_remote_code_exec", "text_privilege_escalation",
            "text_denial_of_service", "text_information_disclosure",
            "text_authentication_bypass", "text_sql_injection",
            "text_xss", "text_buffer_overflow",
            "description_length", "log_description_length",
        ]
