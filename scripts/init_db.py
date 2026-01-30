#!/usr/bin/env python3
"""Initialize database and create sample data."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta, timezone
import random

from app.core.database import engine, Base, SessionLocal
from app.models.cve import CVE, CVEReference, AffectedProduct
from app.models.exploit import Exploit
from app.models.risk_score import RiskScore
from app.models.asset import Asset, AssetVulnerability


def get_utc_now():
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


def create_tables():
    """Create all database tables."""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ Tables created successfully!")


def create_sample_data():
    """Create sample data for demonstration."""
    session = SessionLocal()
    
    try:
        # Check if data already exists
        existing = session.query(CVE).first()
        if existing:
            print("✓ Sample data already exists. Skipping...")
            return
        
        print("Creating sample CVE data...")
        now = get_utc_now()
        
        # Sample CVEs - Real-world critical vulnerabilities
        sample_cves = [
            {
                "cve_id": "CVE-2024-21762",
                "description": "A out-of-bounds write vulnerability in Fortinet FortiOS allows remote unauthenticated attackers to execute arbitrary code via specially crafted HTTP requests.",
                "cvss_v3_score": 9.8,
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "cwe_id": "CWE-787",
                "published_date": now - timedelta(days=5),
                "exploit_available": True,
                "exploit_count": 3,
            },
            {
                "cve_id": "CVE-2024-23897",
                "description": "Jenkins has a feature that allows replacing certain values in configuration files with the contents of files. This feature can be abused by unauthenticated attackers to read arbitrary files.",
                "cvss_v3_score": 9.8,
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "cwe_id": "CWE-22",
                "published_date": now - timedelta(days=10),
                "exploit_available": True,
                "exploit_count": 5,
            },
            {
                "cve_id": "CVE-2024-1086",
                "description": "A use-after-free vulnerability in the Linux kernel's netfilter allows local attackers to escalate privileges.",
                "cvss_v3_score": 7.8,
                "cvss_v3_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "attack_vector": "LOCAL",
                "attack_complexity": "LOW",
                "privileges_required": "LOW",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "cwe_id": "CWE-416",
                "published_date": now - timedelta(days=15),
                "exploit_available": True,
                "exploit_count": 2,
            },
            {
                "cve_id": "CVE-2024-20931",
                "description": "Oracle WebLogic Server vulnerability allows remote code execution via T3/IIOP protocols.",
                "cvss_v3_score": 9.1,
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "NONE",
                "cwe_id": "CWE-502",
                "published_date": now - timedelta(days=20),
                "exploit_available": False,
                "exploit_count": 0,
            },
            {
                "cve_id": "CVE-2024-27198",
                "description": "JetBrains TeamCity authentication bypass allows unauthenticated attackers to gain administrative access.",
                "cvss_v3_score": 9.8,
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "UNCHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "cwe_id": "CWE-287",
                "published_date": now - timedelta(days=3),
                "exploit_available": True,
                "exploit_count": 4,
            },
            {
                "cve_id": "CVE-2024-3400",
                "description": "Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability that allows unauthenticated remote code execution.",
                "cvss_v3_score": 10.0,
                "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "attack_vector": "NETWORK",
                "attack_complexity": "LOW",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "scope": "CHANGED",
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "HIGH",
                "cwe_id": "CWE-77",
                "published_date": now - timedelta(days=7),
                "exploit_available": True,
                "exploit_count": 6,
            },
        ]
        
        # Add more sample CVEs with varying severity
        for i in range(20):
            cvss = round(random.uniform(3.0, 9.9), 1)
            has_exploit = random.choice([True, False])
            sample_cves.append({
                "cve_id": f"CVE-2024-{10000 + i}",
                "description": f"Sample vulnerability #{i+1} affecting various software components with potential security implications.",
                "cvss_v3_score": cvss,
                "attack_vector": random.choice(["NETWORK", "LOCAL", "ADJACENT_NETWORK"]),
                "attack_complexity": random.choice(["LOW", "HIGH"]),
                "privileges_required": random.choice(["NONE", "LOW", "HIGH"]),
                "user_interaction": random.choice(["NONE", "REQUIRED"]),
                "cwe_id": random.choice(["CWE-79", "CWE-89", "CWE-94", "CWE-22", "CWE-287"]),
                "published_date": now - timedelta(days=random.randint(1, 60)),
                "exploit_available": has_exploit,
                "exploit_count": random.randint(1, 3) if has_exploit else 0,
            })
        
        # Create CVEs
        for cve_data in sample_cves:
            cve = CVE(
                cve_id=cve_data["cve_id"],
                description=cve_data["description"],
                cvss_v3_score=cve_data["cvss_v3_score"],
                cvss_v3_vector=cve_data.get("cvss_v3_vector"),
                attack_vector=cve_data.get("attack_vector"),
                attack_complexity=cve_data.get("attack_complexity"),
                privileges_required=cve_data.get("privileges_required"),
                user_interaction=cve_data.get("user_interaction"),
                scope=cve_data.get("scope"),
                confidentiality_impact=cve_data.get("confidentiality_impact"),
                integrity_impact=cve_data.get("integrity_impact"),
                availability_impact=cve_data.get("availability_impact"),
                cwe_id=cve_data.get("cwe_id"),
                published_date=cve_data.get("published_date"),
                last_modified_date=now,
                exploit_available=cve_data.get("exploit_available", False),
                exploit_count=cve_data.get("exploit_count", 0),
                source="SAMPLE"
            )
            session.add(cve)
        
        session.commit()
        print(f"✓ Created {len(sample_cves)} sample CVEs")
        
        # Create sample assets
        print("Creating sample assets...")
        sample_assets = [
            {
                "name": "Production Web Server",
                "asset_type": "server",
                "hostname": "web-prod-01",
                "ip_address": "10.0.1.10",
                "environment": "production",
                "criticality": "critical",
                "installed_software": [
                    {"vendor": "apache", "product": "httpd", "version": "2.4.51"},
                    {"vendor": "oracle", "product": "weblogic_server", "version": "14.1.1"},
                ],
                "operating_system": "linux",
                "owner": "Platform Team",
            },
            {
                "name": "CI/CD Server",
                "asset_type": "server",
                "hostname": "jenkins-01",
                "ip_address": "10.0.2.20",
                "environment": "production",
                "criticality": "high",
                "installed_software": [
                    {"vendor": "jenkins", "product": "jenkins", "version": "2.426"},
                    {"vendor": "jetbrains", "product": "teamcity", "version": "2023.11"},
                ],
                "operating_system": "linux",
                "owner": "DevOps Team",
            },
            {
                "name": "Development Database",
                "asset_type": "server",
                "hostname": "db-dev-01",
                "ip_address": "10.0.3.30",
                "environment": "development",
                "criticality": "medium",
                "installed_software": [
                    {"vendor": "postgresql", "product": "postgresql", "version": "15.2"},
                ],
                "operating_system": "linux",
                "owner": "Backend Team",
            },
        ]
        
        for asset_data in sample_assets:
            asset = Asset(
                name=asset_data["name"],
                asset_type=asset_data["asset_type"],
                hostname=asset_data["hostname"],
                ip_address=asset_data["ip_address"],
                environment=asset_data["environment"],
                criticality=asset_data["criticality"],
                installed_software=asset_data["installed_software"],
                operating_system=asset_data["operating_system"],
                owner=asset_data["owner"],
            )
            session.add(asset)
        
        session.commit()
        print(f"✓ Created {len(sample_assets)} sample assets")
        
        # Calculate risk scores for sample CVEs
        print("Calculating risk scores...")
        from app.services.risk_aggregator import RiskAggregator
        aggregator = RiskAggregator(session)
        aggregator.calculate_all_risks()
        
        print("✓ Sample data creation complete!")
        
    except Exception as e:
        print(f"✗ Error creating sample data: {e}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    create_tables()
    create_sample_data()
