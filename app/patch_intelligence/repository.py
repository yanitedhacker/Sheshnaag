"""Persistence layer for patches and mappings."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.cve import CVE
from app.models.patch import AssetPatch, Patch


class PatchRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_patch(self, patch_id: str) -> Patch | None:
        return self.session.query(Patch).filter(Patch.patch_id == patch_id).first()

    def list_patches(self, vendor: str | None = None) -> list[Patch]:
        q = self.session.query(Patch)
        if vendor:
            q = q.filter(Patch.vendor == vendor.lower())
        return q.order_by(Patch.vendor, Patch.affected_software, Patch.patch_id).all()

    def create_patch(self, patch_data: dict[str, Any], cve_ids: list[str] | None = None) -> Patch:
        patch = Patch(**patch_data)
        if cve_ids:
            cves = (
                self.session.query(CVE).filter(CVE.cve_id.in_([c.upper() for c in cve_ids])).all()
            )
            patch.cves = cves
        self.session.add(patch)
        return patch

    def map_patch_to_asset(
        self,
        asset_id: int,
        patch_id: str,
        maintenance_window: str | None = None,
        environment: str | None = None,
        status: str = "recommended",
    ) -> AssetPatch:
        mapping = AssetPatch(
            asset_id=asset_id,
            patch_id=patch_id,
            maintenance_window=maintenance_window,
            environment=environment,
            status=status,
        )
        self.session.add(mapping)
        return mapping

    def list_assets_for_patch(self, patch_id: str) -> list[Asset]:
        return (
            self.session.query(Asset)
            .join(AssetPatch, AssetPatch.asset_id == Asset.id)
            .filter(AssetPatch.patch_id == patch_id)
            .all()
        )

    def list_patches_for_asset(self, asset_id: int) -> list[Patch]:
        return (
            self.session.query(Patch)
            .join(AssetPatch, AssetPatch.patch_id == Patch.patch_id)
            .filter(AssetPatch.asset_id == asset_id)
            .all()
        )
