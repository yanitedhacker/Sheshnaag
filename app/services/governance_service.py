"""Analyst feedback, approvals, and append-only audit history."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.v2 import AnalystFeedback, DecisionAuditEvent, PatchApproval, Tenant, TenantUser


class GovernanceService:
    """Capture human decisions that shape trust, approvals, and auditability."""

    def __init__(self, session: Session):
        self.session = session

    def submit_feedback(
        self,
        tenant: Tenant,
        *,
        action_id: str,
        feedback_type: str,
        note: Optional[str] = None,
        actor: Optional[TenantUser] = None,
        metadata: Optional[dict] = None,
    ) -> Dict[str, object]:
        """Persist analyst feedback and append an audit event."""
        record = AnalystFeedback(
            tenant_id=tenant.id,
            action_id=action_id,
            feedback_type=feedback_type,
            note=note,
            meta=metadata or {},
        )
        self.session.add(record)
        self.session.flush()

        self._record_event(
            tenant=tenant,
            actor=actor,
            event_type="analyst_feedback.created",
            entity_type="action",
            entity_id=action_id,
            summary=f"{feedback_type} feedback captured for {action_id}",
            details={
                "feedback_id": record.id,
                "feedback_type": feedback_type,
                "note": note,
                "metadata": metadata or {},
            },
        )

        return self._serialize_feedback(record)

    def list_feedback(self, tenant: Tenant, *, limit: int = 25) -> Dict[str, object]:
        """List recent analyst feedback for a tenant."""
        rows = (
            self.session.query(AnalystFeedback)
            .filter(AnalystFeedback.tenant_id == tenant.id)
            .order_by(desc(AnalystFeedback.created_at))
            .limit(limit)
            .all()
        )
        counts = Counter(row.feedback_type for row in rows)
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "summary": dict(counts),
            "items": [self._serialize_feedback(row) for row in rows],
        }

    def get_latest_feedback_map(self, tenant: Tenant, action_ids: Iterable[str]) -> Dict[str, AnalystFeedback]:
        """Return the latest feedback per action id."""
        wanted = {action_id for action_id in action_ids if action_id}
        if not wanted:
            return {}
        rows = (
            self.session.query(AnalystFeedback)
            .filter(AnalystFeedback.tenant_id == tenant.id, AnalystFeedback.action_id.in_(wanted))
            .order_by(desc(AnalystFeedback.created_at))
            .all()
        )
        latest: Dict[str, AnalystFeedback] = {}
        for row in rows:
            if row.action_id not in latest:
                latest[row.action_id] = row
        return latest

    def create_patch_approval(
        self,
        tenant: Tenant,
        *,
        patch_id: str,
        action_id: str,
        approval_type: str,
        approval_state: str,
        maintenance_window: Optional[str] = None,
        note: Optional[str] = None,
        decided_by: Optional[str] = None,
        actor: Optional[TenantUser] = None,
        metadata: Optional[dict] = None,
    ) -> Dict[str, object]:
        """Create an approval or sign-off record."""
        record = PatchApproval(
            tenant_id=tenant.id,
            patch_id=patch_id,
            action_id=action_id,
            approval_type=approval_type,
            approval_state=approval_state,
            maintenance_window=maintenance_window,
            note=note,
            decided_by=decided_by or (actor.email if actor else None),
            meta=metadata or {},
            decided_at=datetime.utcnow(),
        )
        self.session.add(record)
        self.session.flush()

        self._record_event(
            tenant=tenant,
            actor=actor,
            event_type="patch_approval.created",
            entity_type="patch",
            entity_id=patch_id,
            summary=f"{approval_state} {approval_type} for {patch_id}",
            details={
                "approval_id": record.id,
                "action_id": action_id,
                "approval_type": approval_type,
                "approval_state": approval_state,
                "maintenance_window": maintenance_window,
                "note": note,
            },
        )

        return self._serialize_approval(record)

    def list_approvals(self, tenant: Tenant, *, limit: int = 50) -> Dict[str, object]:
        """Return recent patch approvals and sign-offs."""
        rows = (
            self.session.query(PatchApproval)
            .filter(PatchApproval.tenant_id == tenant.id)
            .order_by(desc(PatchApproval.decided_at), desc(PatchApproval.created_at))
            .limit(limit)
            .all()
        )
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "items": [self._serialize_approval(row) for row in rows],
        }

    def get_latest_patch_approval_map(self, tenant: Tenant, patch_ids: Iterable[str]) -> Dict[str, PatchApproval]:
        """Return the latest approval per patch."""
        wanted = {patch_id for patch_id in patch_ids if patch_id}
        if not wanted:
            return {}
        rows = (
            self.session.query(PatchApproval)
            .filter(PatchApproval.tenant_id == tenant.id, PatchApproval.patch_id.in_(wanted))
            .order_by(desc(PatchApproval.decided_at), desc(PatchApproval.created_at))
            .all()
        )
        latest: Dict[str, PatchApproval] = {}
        for row in rows:
            if row.patch_id not in latest:
                latest[row.patch_id] = row
        return latest

    def list_audit_events(self, tenant: Tenant, *, limit: int = 100) -> Dict[str, object]:
        """Return append-only audit events for a tenant."""
        rows = (
            self.session.query(DecisionAuditEvent)
            .filter(DecisionAuditEvent.tenant_id == tenant.id)
            .order_by(desc(DecisionAuditEvent.created_at), desc(DecisionAuditEvent.id))
            .limit(limit)
            .all()
        )
        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "items": [self._serialize_audit(row) for row in rows],
        }

    def _record_event(
        self,
        *,
        tenant: Tenant,
        event_type: str,
        entity_type: str,
        entity_id: str,
        summary: str,
        details: dict,
        actor: Optional[TenantUser] = None,
    ) -> DecisionAuditEvent:
        previous = (
            self.session.query(DecisionAuditEvent)
            .filter(DecisionAuditEvent.tenant_id == tenant.id)
            .order_by(desc(DecisionAuditEvent.id))
            .first()
        )
        previous_hash = previous.event_hash if previous else ""
        payload = json.dumps(
            {
                "tenant_id": tenant.id,
                "actor_user_id": actor.id if actor else None,
                "event_type": event_type,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "summary": summary,
                "details": details,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
        )
        event_hash = hashlib.sha256(f"{previous_hash}:{payload}".encode("utf-8")).hexdigest()
        record = DecisionAuditEvent(
            tenant_id=tenant.id,
            actor_user_id=actor.id if actor else None,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            summary=summary,
            details=details,
            previous_hash=previous_hash or None,
            event_hash=event_hash,
        )
        self.session.add(record)
        self.session.flush()
        return record

    @staticmethod
    def feedback_adjustment(feedback: Optional[AnalystFeedback]) -> float:
        """Translate analyst feedback into a deterministic score adjustment."""
        if feedback is None:
            return 0.0
        mapping = {
            "escalate": 8.0,
            "confirm": 4.0,
            "deprioritize": -10.0,
            "accept_risk": -18.0,
            "false_positive": -40.0,
        }
        return mapping.get(feedback.feedback_type, 0.0)

    @staticmethod
    def feedback_confidence_multiplier(feedback: Optional[AnalystFeedback]) -> float:
        """Adjust confidence based on analyst input."""
        if feedback is None:
            return 1.0
        if feedback.feedback_type in {"confirm", "escalate"}:
            return 1.08
        if feedback.feedback_type in {"deprioritize", "accept_risk"}:
            return 1.02
        if feedback.feedback_type == "false_positive":
            return 0.85
        return 1.0

    @staticmethod
    def _serialize_feedback(record: AnalystFeedback) -> dict:
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "action_id": record.action_id,
            "feedback_type": record.feedback_type,
            "note": record.note,
            "metadata": record.meta or {},
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }

    @staticmethod
    def _serialize_approval(record: PatchApproval) -> dict:
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "patch_id": record.patch_id,
            "action_id": record.action_id,
            "approval_type": record.approval_type,
            "approval_state": record.approval_state,
            "maintenance_window": record.maintenance_window,
            "decided_by": record.decided_by,
            "note": record.note,
            "metadata": record.meta or {},
            "decided_at": record.decided_at.isoformat() if record.decided_at else None,
        }

    @staticmethod
    def _serialize_audit(record: DecisionAuditEvent) -> dict:
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "actor_user_id": record.actor_user_id,
            "event_type": record.event_type,
            "entity_type": record.entity_type,
            "entity_id": record.entity_id,
            "summary": record.summary,
            "details": record.details or {},
            "previous_hash": record.previous_hash,
            "event_hash": record.event_hash,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }
