"""Database models."""

from app.models.cve import CVE, CVEReference, AffectedProduct
from app.models.exploit import Exploit
from app.models.risk_score import RiskScore, RiskHistory
from app.models.asset import Asset, AssetVulnerability
from app.models.patch import Patch, AssetPatch, patch_cves
from app.models.ops import FeedSyncState, PatchDependency, PatchPlan, PatchPlanItem

__all__ = [
    "CVE",
    "CVEReference", 
    "AffectedProduct",
    "Exploit",
    "RiskScore",
    "RiskHistory",
    "Asset",
    "AssetVulnerability",
    "Patch",
    "AssetPatch",
    "patch_cves",
    "FeedSyncState",
    "PatchDependency",
    "PatchPlan",
    "PatchPlanItem",
]
