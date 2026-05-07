# V5 Wave 0 — W0b (Case Lifecycle State Machine) Plan

**Goal:** Replace the loose `analysis_cases.status` string with a 6-state lifecycle enum, gated by RBAC, audited via a new `case_state_transitions` table.

**Architecture:** State machine encoded as a frozen tuple of `TransitionRule(from_state, to_state, allowed_roles)`. Service method `transition()` looks up the rule, checks the actor's roles intersect `allowed_roles`, mutates the case row, and inserts a transition audit row in the same DB transaction. Existing `status` column is preserved for one cycle (V6 will drop it) so V4 readers don't break.

**Tech Stack:** SQLAlchemy + Alembic. Reuses W0a's `RbacService` only conceptually (role names match) — the workflow service does not depend on `RbacService` directly because the transition table itself is the authoritative gate.

---

## States

```
triage → analysis → review → ready_to_ship → shipped → archived
```

Plus two off-path edges:
- `review → analysis` (reviewer requests changes)
- `ready_to_ship → review` (re-review before shipping)
- Any non-shipped state can drop to `archived` (false-alarm / dropped-case)
- `archived → triage` (lab_lead-only re-open)

## Transition matrix

| From | To | Allowed roles |
|---|---|---|
| triage | analysis | analyst, senior_analyst, lab_lead |
| triage | archived | analyst, senior_analyst, lab_lead |
| analysis | review | analyst, senior_analyst, lab_lead |
| analysis | archived | analyst, senior_analyst, lab_lead |
| review | analysis | reviewer, lab_lead |
| review | ready_to_ship | reviewer, lab_lead |
| review | archived | reviewer, lab_lead |
| ready_to_ship | shipped | senior_analyst, lab_lead |
| ready_to_ship | review | reviewer, lab_lead |
| ready_to_ship | archived | reviewer, lab_lead |
| shipped | archived | lab_lead |
| archived | triage | lab_lead |

12 legal transitions. Red-team test enumerates 5 roles × 6 states × 5 outbound = 150 (role, from, to) tuples; the ~12 legal cases for any allowed role pass, the rest must raise `RoleNotPermittedError` or `IllegalTransitionError`.

## File structure

| Action | File | Responsibility |
|---|---|---|
| Modify | `app/models/malware_lab.py` | Add `lifecycle_state`, `state_changed_at`, `state_changed_by` to `AnalysisCase`; new `CaseStateTransition` class. Keep `status` column unchanged (deprecation comment only). |
| Modify | `app/models/__init__.py` | Export `CaseStateTransition`. |
| Create | `app/migrations/versions/v5a02_case_lifecycle.py` | Add 3 columns + new transition table; backfill lifecycle_state from status. |
| Create | `app/services/case_workflow.py` | `CaseLifecycleState` enum, `TransitionRule`, `TRANSITIONS` tuple, `CaseWorkflowService.transition()`, `IllegalTransitionError`, `RoleNotPermittedError`, `legal_transitions_for_state()` helper. |
| Create | `tests/unit/test_case_workflow.py` | Service unit tests (happy path + each error class). |
| Create | `tests/red_team/__init__.py` + `tests/red_team/test_lifecycle_escapes.py` | Table-driven kill-criteria test. |

## Service shape

```python
class CaseLifecycleState(str, Enum):
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    REVIEW = "review"
    READY_TO_SHIP = "ready_to_ship"
    SHIPPED = "shipped"
    ARCHIVED = "archived"


@dataclass(frozen=True)
class TransitionRule:
    from_state: CaseLifecycleState
    to_state: CaseLifecycleState
    allowed_roles: frozenset[str]


TRANSITIONS: tuple[TransitionRule, ...] = (...)


class IllegalTransitionError(ValueError):
    """The (from_state, to_state) pair is not a legal transition."""


class RoleNotPermittedError(PermissionError):
    """The caller's role(s) do not include any role allowed for this transition."""


class CaseWorkflowService:
    def __init__(self, session: Session) -> None: ...

    def transition(
        self,
        *,
        case_id: int,
        to_state: CaseLifecycleState,
        actor: str,
        actor_roles: Iterable[str],
        reason: str | None = None,
    ) -> CaseStateTransition:
        ...

    def legal_transitions_for_state(
        self, state: CaseLifecycleState
    ) -> list[CaseLifecycleState]: ...

    def legal_transitions_for_role(
        self, state: CaseLifecycleState, role: str
    ) -> list[CaseLifecycleState]: ...
```

## Migration backfill rules

| Pre-existing `status` value | New `lifecycle_state` |
|---|---|
| `open` | `triage` |
| `triage` | `triage` |
| `analyzing`, `in_progress`, `analysis` | `analysis` |
| `in_review`, `review`, `pending_review` | `review` |
| `ready_to_ship`, `ready` | `ready_to_ship` |
| `shipped`, `published` | `shipped` |
| `closed`, `archived` | `archived` |
| anything else | `triage` (safest default) |

## Acceptance for W0b

- Migration up + down clean on sqlite (verified manually with the same create_all + stamp + upgrade pattern as W0a).
- All red-team test cases produce expected `RoleNotPermittedError` or `IllegalTransitionError`.
- Each successful `transition()` writes a `case_state_transitions` row with `(case_id, from_state, to_state, actor, role_at_transition, reason, occurred_at)`.
- The existing `analysis_cases.status` column is untouched at runtime (V4 readers continue to work).
