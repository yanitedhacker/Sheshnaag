"""V5 W0b — case lifecycle state machine.

Owns the legal-transition table and the ``transition()`` operation that
moves an :class:`~app.models.malware_lab.AnalysisCase` from one
``lifecycle_state`` to another. Every successful transition writes an
append-only row to :class:`~app.models.malware_lab.CaseStateTransition`.

The transition table itself is the authoritative gate: each rule names
the roles permitted to perform that transition. ``lab_lead`` is *not*
auto-allowed everywhere — it is listed explicitly on each rule. This is
intentional: the V5 kill-criteria gate item 4 requires that "no
transition can be made by a role without permission", and silent
``lab_lead`` superuser carve-outs make that test toothless.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.malware_lab import AnalysisCase, CaseStateTransition


class CaseLifecycleState(str, Enum):
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    REVIEW = "review"
    READY_TO_SHIP = "ready_to_ship"
    SHIPPED = "shipped"
    ARCHIVED = "archived"


@dataclass(frozen=True)
class TransitionRule:
    """A legal (from_state, to_state) edge plus the roles that may walk it."""

    from_state: CaseLifecycleState
    to_state: CaseLifecycleState
    allowed_roles: frozenset[str]


_ANALYST_TRIO = frozenset({"analyst", "senior_analyst", "lab_lead"})
_REVIEWER_DUO = frozenset({"reviewer", "lab_lead"})
_SHIPPING_DUO = frozenset({"senior_analyst", "lab_lead"})
_LAB_LEAD_ONLY = frozenset({"lab_lead"})


# Authoritative legal-transition table. Order is documentation only;
# lookup is by (from_state, to_state) pair.
TRANSITIONS: tuple[TransitionRule, ...] = (
    # Triage outbound
    TransitionRule(CaseLifecycleState.TRIAGE, CaseLifecycleState.ANALYSIS, _ANALYST_TRIO),
    TransitionRule(CaseLifecycleState.TRIAGE, CaseLifecycleState.ARCHIVED, _ANALYST_TRIO),
    # Analysis outbound
    TransitionRule(CaseLifecycleState.ANALYSIS, CaseLifecycleState.REVIEW, _ANALYST_TRIO),
    TransitionRule(CaseLifecycleState.ANALYSIS, CaseLifecycleState.ARCHIVED, _ANALYST_TRIO),
    # Review outbound
    TransitionRule(CaseLifecycleState.REVIEW, CaseLifecycleState.ANALYSIS, _REVIEWER_DUO),
    TransitionRule(CaseLifecycleState.REVIEW, CaseLifecycleState.READY_TO_SHIP, _REVIEWER_DUO),
    TransitionRule(CaseLifecycleState.REVIEW, CaseLifecycleState.ARCHIVED, _REVIEWER_DUO),
    # Ready-to-ship outbound
    TransitionRule(CaseLifecycleState.READY_TO_SHIP, CaseLifecycleState.SHIPPED, _SHIPPING_DUO),
    TransitionRule(CaseLifecycleState.READY_TO_SHIP, CaseLifecycleState.REVIEW, _REVIEWER_DUO),
    TransitionRule(CaseLifecycleState.READY_TO_SHIP, CaseLifecycleState.ARCHIVED, _REVIEWER_DUO),
    # Shipped outbound
    TransitionRule(CaseLifecycleState.SHIPPED, CaseLifecycleState.ARCHIVED, _LAB_LEAD_ONLY),
    # Archived outbound (re-open)
    TransitionRule(CaseLifecycleState.ARCHIVED, CaseLifecycleState.TRIAGE, _LAB_LEAD_ONLY),
)


# Indexed lookup: (from, to) -> rule. Built once at import time.
_TRANSITION_INDEX: dict[
    tuple[CaseLifecycleState, CaseLifecycleState], TransitionRule
] = {(t.from_state, t.to_state): t for t in TRANSITIONS}


class IllegalTransitionError(ValueError):
    """The (from_state, to_state) pair is not a legal transition."""


class RoleNotPermittedError(PermissionError):
    """The caller's roles do not include any role allowed for this transition."""


class CaseNotFoundError(LookupError):
    """The named case_id does not exist."""


class CaseWorkflowService:
    """State-machine service for AnalysisCase lifecycle transitions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def transition(
        self,
        *,
        case_id: int,
        to_state: CaseLifecycleState,
        actor: str,
        actor_roles: Iterable[str],
        reason: Optional[str] = None,
    ) -> CaseStateTransition:
        """Attempt a transition. Returns the audit row on success.

        Raises:
            CaseNotFoundError: case_id does not exist.
            IllegalTransitionError: (current, to_state) is not in the rule table.
            RoleNotPermittedError: rule exists but no role in ``actor_roles``
                is in ``rule.allowed_roles``.
        """

        case = (
            self._session.query(AnalysisCase).filter_by(id=case_id).first()
        )
        if case is None:
            raise CaseNotFoundError(f"case_id={case_id}")

        from_state = CaseLifecycleState(case.lifecycle_state)
        to_state_enum = (
            to_state
            if isinstance(to_state, CaseLifecycleState)
            else CaseLifecycleState(to_state)
        )

        rule = _TRANSITION_INDEX.get((from_state, to_state_enum))
        if rule is None:
            raise IllegalTransitionError(
                f"no rule: {from_state.value} -> {to_state_enum.value}"
            )

        held = set(actor_roles or ())
        intersection = held & rule.allowed_roles
        if not intersection:
            raise RoleNotPermittedError(
                f"role {sorted(held)} cannot transition "
                f"{from_state.value} -> {to_state_enum.value}; "
                f"requires one of {sorted(rule.allowed_roles)}"
            )

        # Pick the highest-privilege role for the audit record (deterministic).
        # Order matches the role catalog precedence.
        role_for_audit = self._pick_role_for_audit(intersection)

        now = datetime.now(timezone.utc)
        case.lifecycle_state = to_state_enum.value
        case.state_changed_at = now
        case.state_changed_by = actor

        audit = CaseStateTransition(
            case_id=case.id,
            from_state=from_state.value,
            to_state=to_state_enum.value,
            actor=actor,
            role_at_transition=role_for_audit,
            reason=reason,
            occurred_at=now,
        )
        self._session.add(audit)
        self._session.flush()
        return audit

    def legal_transitions_for_state(
        self, state: CaseLifecycleState
    ) -> List[CaseLifecycleState]:
        """All ``to_state`` values reachable from ``state`` (any role)."""
        return [t.to_state for t in TRANSITIONS if t.from_state == state]

    def legal_transitions_for_role(
        self, state: CaseLifecycleState, role: str
    ) -> List[CaseLifecycleState]:
        """All ``to_state`` values reachable from ``state`` for the given role."""
        return [
            t.to_state
            for t in TRANSITIONS
            if t.from_state == state and role in t.allowed_roles
        ]

    @staticmethod
    def _pick_role_for_audit(roles: Iterable[str]) -> str:
        # Highest-privilege wins, ties broken by the canonical V5 order.
        precedence = {
            "lab_lead": 5,
            "reviewer": 4,
            "senior_analyst": 3,
            "analyst": 2,
            "read_only": 1,
        }
        return max(roles, key=lambda r: (precedence.get(r, 0), r))
