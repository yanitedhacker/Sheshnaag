# V5 Wave 0 — W0c (Capability registry role binding) Plan

**Goal:** Make the V4 capability registry V5-role-aware without changing any runtime gate. Reserve V7 capability names with a comment block.

**Why:** V5 introduces named roles (W0a). The V4 `Capability` dataclass has no role field, so the policy engine can't check "is this requester's role allowed to even ask for this capability?". V5 lays the data binding so V6's AuthorizationCenter UI can use it. We deliberately do NOT change `issue()` flow in V5 (that's V6 work).

**Scope:** small. ~30 lines in `capability_policy.py`. One new test file.

## Concrete changes

1. **Extend `Capability` dataclass** with `requester_roles: Optional[frozenset[str]] = None`. `None` = anyone authenticated may request (V4 default behavior preserved). A populated set means "only these roles may originate an issuance request".

2. **Set `requester_roles` per capability** based on sensitivity tier:
   - **Senior+ tier** (only senior_analyst, lab_lead can request): `external_disclosure`, `specimen_exfil`, `destructive_defang`, `network_egress_open`, `kernel_driver_load`, `offensive_research`, `red_team_emulation`
   - **Analyst+ tier** (analyst, senior_analyst, lab_lead): `dynamic_detonation`, `cloud_ai_provider_use`, `autonomous_agent_run`, `exploit_validation`, `memory_exfil_to_host`

3. **Add `RESERVED_FOR_V7` comment block** at the bottom of `CAPABILITIES`. Documents the four V7 capability slugs (`cve_coordination`, `vendor_disclosure`, `public_intel_publish`, `dataset_publish`) so V7 kickoff knows where to plug them in. Not live entries — adding them now would surface UI elements in the AuthorizationCenter that gate nothing.

4. **Add `CapabilityPolicy.permitted_requester_for(capability, roles)` helper** that returns True if any of `roles` is in `requester_roles` (or `requester_roles is None`). Pure read; no DB write. V6 wires this into the `issue()` flow.

5. **Add unit test** `tests/unit/test_capability_role_binding.py` covering: data correctness per-capability, helper method behavior, that None means everyone passes.

## What this is NOT

- Not a wiring change to `issue()` — V5 keeps the existing reviewer/admin logic untouched.
- Not adding new capabilities — the 12 existing capabilities are the V5 surface.
- Not breaking V4 — `requester_roles` is optional with a `None` default; existing test suite stays green.

## Acceptance

- Capability dataclass has the new field.
- Each existing capability has its tier-appropriate `requester_roles`.
- `RESERVED_FOR_V7` comment present.
- Helper method behaves correctly (test verifies).
- Existing `tests/unit/test_capability_policy.py` semantically unchanged.
