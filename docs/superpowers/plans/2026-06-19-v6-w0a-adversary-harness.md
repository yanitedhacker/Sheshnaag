# V6 Wave 0 — W0a (Adversary Harness) Implementation Plan

**Goal:** Establish automated red-team tests that prove the capability-policy chokepoint blocks scope escapes before offensive features ship.

**Architecture:** Pytest red-team suite exercises `CapabilityPolicy.issue()` and `evaluate()` with adversarial issuance requests. No new runtime services — pure policy-layer verification that gates W1–W5 merges.

**Tech Stack:** pytest + SQLAlchemy in-memory sqlite. Reuses existing `CapabilityPolicy` in `app/services/capability_policy.py`.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Create | `tests/red_team/test_capability_escapes.py` | Escape attempts: analyst→offensive, single-reviewer dual caps, self-approval |
| Extend | `app/services/capability_policy.py` | Enforce `requester_role_denied`, `need_2_approvals`, `requester_cannot_review` |
| Reference | `tests/v6/test_auth_issue_enforcement.py` | W1a unit coverage for `permitted_requester_for` at issuance |
| Reference | `tests/unit/test_capability_role_binding.py` | V5 requester_roles registry shape guard |

---

## Escape scenarios

| Scenario | Expected rejection |
|---|---|
| `analyst` issues `offensive_research` | `requester_role_denied` |
| Single reviewer on `exploit_validation` (dual) | `need_2_approvals` |
| Requester listed as reviewer | `requester_cannot_review` |

---

## Acceptance for W0a

- `pytest tests/red_team/test_capability_escapes.py -q` — 0 escapes.
- All three offensive capabilities (`exploit_validation`, `red_team_emulation`, `offensive_research`) covered.
- Pre-existing V5 test suite remains green.

W1a (auth issue enforcement) and W1b (Authorization Center quorum UI) depend on W0a passing.
