# V6 Wave 1a — Auth Issue Enforcement

**Goal:** Wire `permitted_requester_for()` into `CapabilityPolicy.issue()` so requester V5 roles are enforced at authorization issuance, not only at runtime evaluate.

**Architecture:** `IssuanceRequest` carries `requester_roles`; `issue()` rejects when roles ∉ capability `requester_roles`. Offensive capabilities require `senior_analyst` or `lab_lead`; `offensive_research` additionally requires `dual_plus_admin` review kind.

**Tech Stack:** SQLAlchemy + existing capability registry in `app/services/capability_policy.py`.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Modify | `app/services/capability_policy.py` | `permitted_requester_for()`, `issue()` role gate, review-kind quorum checks |
| Modify | `app/api/routes/authorization_routes.py` | Pass caller roles into issuance payload |
| Modify | `app/api/routes/capability_routes.py` | Expose `requester_roles` in registry GET |
| Create | `tests/v6/test_auth_issue_enforcement.py` | Deny analyst for `offensive_research`; permit lab_lead |
| Reference | `tests/red_team/test_capability_escapes.py` | Adversary harness regression |

---

## Capability review kinds (V6)

| Capability | Review kind | Requester roles |
|---|---|---|
| `exploit_validation` | dual | analyst, senior_analyst, lab_lead |
| `red_team_emulation` | dual | senior_analyst, lab_lead |
| `offensive_research` | dual_plus_admin | senior_analyst, lab_lead |

---

## Acceptance for W1a

- `pytest tests/v6/test_auth_issue_enforcement.py -q` passes.
- `CapabilityPolicy.issue()` raises `ValueError("requester_role_denied")` for out-of-role requesters.
- Registry endpoint returns non-null `requester_roles` for all capabilities.

W1b adds the Authorization Center UI for dual-reviewer flows.
