# Sheshnaag P0 Integrity Boundary Implementation Plan

> **For Codex:** Use `superpowers:executing-plans` to implement this plan task by task. Use strict red-green-refactor TDD and `superpowers:systematic-debugging` for each unexpected failure.

**Goal:** Make autonomous execution fail closed, require an independent exact-action approval, and return success only after durable persistence.

**Architecture:** Add pending authorization request and immutable decision rows. Derive an action digest on the server and bind the issued artifact to it. Make the autonomous route evaluate that exact scope before any work, commit the run before it returns, and use durable replay only.

**Tech Stack:** Python 3, FastAPI, Pydantic, SQLAlchemy, Alembic, Pytest, React, TypeScript, Vite

---

## Execution rules

- Work only in `/private/tmp/sheshnaag-p0-to-beta-20260829` on `yanitedhacker/p0-to-beta`.
- Preserve all owner changes copied from the main checkout.
- Do not add a shell, network, detonation, or arbitrary tool capability.
- Run each new test and observe the expected failure before implementation.
- Commit after each green task with only the named files staged.

### Task 1: Establish the P0 baseline

**Files:**
- Test: `tests/unit/test_capability_policy.py`
- Test: `tests/integration/test_autonomous_routes.py`
- Test: `tests/integration/test_v4_phase1_routes.py`

- [ ] **Step 1: Run the focused baseline**

Run:

```bash
PYTHONPATH=. /Users/archishmanpaul/Desktop/Sheshnaag-main/.venv-v2/bin/python -m pytest -vv --maxfail=1 tests/unit/test_capability_policy.py tests/integration/test_autonomous_routes.py tests/integration/test_v4_phase1_routes.py
```

Expected: the current tests pass, or a concrete environment/setup failure is recorded without calling it a product failure.

- [ ] **Step 2: Record the exact baseline count and duration in the implementation log**

Add the command and result to `docs/runbooks/v5/p0_integrity_evidence.md`.

### Task 2: Add server-derived exact-action digests

**Files:**
- Modify: `app/services/capability_policy.py`
- Test: `tests/unit/test_capability_policy.py`

- [ ] **Step 1: Write failing digest tests**

Add tests with literal expected SHA-256 values:

```python
def test_action_digest_is_stable_for_key_order():
    first = exact_action_digest(
        "autonomous_agent_run",
        {"tenant_id": 7, "goal": "Review case", "case_id": 42, "max_steps": 3},
    )
    second = exact_action_digest(
        "autonomous_agent_run",
        {"max_steps": 3, "case_id": 42, "goal": "Review case", "tenant_id": 7},
    )
    assert first == second
    assert first.startswith("sha256:")


def test_changed_action_argument_changes_digest():
    approved = exact_action_digest("autonomous_agent_run", {"tenant_id": 7, "goal": "A", "case_id": 42, "max_steps": 3})
    changed = exact_action_digest("autonomous_agent_run", {"tenant_id": 7, "goal": "B", "case_id": 42, "max_steps": 3})
    assert changed != approved
```

Run the two tests and confirm import or assertion failure.

- [ ] **Step 2: Implement minimal digest helpers**

Add:

```python
EXACT_ACTION_CAPABILITIES = frozenset({"autonomous_agent_run"})


def exact_action_digest(action: str, arguments: dict[str, Any]) -> str:
    body = canonical_json({"action": action, "arguments": arguments})
    return "sha256:" + hashlib.sha256(body).hexdigest()


def exact_action_scope(action: str, arguments: dict[str, Any], *, tenant_id: int, case_id: Optional[int] = None) -> dict[str, Any]:
    scope = {"tenant_id": tenant_id, "action": action, "action_digest": exact_action_digest(action, arguments)}
    if case_id is not None:
        scope["case_id"] = case_id
    return scope
```

- [ ] **Step 3: Run the digest tests and confirm green**

- [ ] **Step 4: Commit**

```bash
git add app/services/capability_policy.py tests/unit/test_capability_policy.py
git commit -m "feat(authz): derive exact action digests"
```

### Task 3: Add the pending request and immutable decision model

**Files:**
- Modify: `app/models/capability.py`
- Modify: `app/models/__init__.py`
- Create: `app/migrations/versions/v5a08_exact_action_authorization.py`
- Test: `tests/unit/test_authorization_workflow.py`

- [ ] **Step 1: Write failing model constraint tests**

Create an in-memory SQLite test that creates only the authorization request and decision tables. Prove that duplicate `(request_id, reviewer)` decisions fail and invalid status or decision values fail.

- [ ] **Step 2: Run the test and confirm missing-model failure**

- [ ] **Step 3: Add the SQLAlchemy models and migration**

`AuthorizationRequestRecord` fields:

- `request_id`, `capability`, `scope`, `action`, `action_digest`
- `requester`, `reason`, `requested_ttl_seconds`, `engagement_ref`
- `status`, `required_approvals`, `requires_admin_approval`
- `artifact_id`, `created_at`, `expires_at`, `resolved_at`

`AuthorizationDecisionRecord` fields:

- integer primary key, `request_id`, `reviewer`, `reviewer_roles`
- `decision`, `note`, `created_at`
- unique `(request_id, reviewer)`

Migration `v5a08` must use `down_revision = "v5a07"` and add the run columns from the design.

- [ ] **Step 4: Run model tests and an Alembic upgrade on a temporary SQLite database**

- [ ] **Step 5: Commit**

### Task 4: Implement the independent authorization workflow

**Files:**
- Modify: `app/services/capability_policy.py`
- Test: `tests/unit/test_authorization_workflow.py`

- [ ] **Step 1: Write failing request and decision behavior tests**

Test these observable outcomes with real SQLite rows:

- Creating a request stores `pending` and writes a `request` audit entry.
- The requester cannot decide their own request.
- One reviewer cannot decide twice.
- A rejection creates no artifact.
- A single independent approval issues one artifact.
- Dual approval needs two distinct reviewers.
- `dual_plus_admin` needs a `lab_lead` reviewer.
- The artifact contains the server-derived action digest.

- [ ] **Step 2: Run the tests and confirm the first expected failure**

- [ ] **Step 3: Implement `create_request` and `record_decision`**

Use one SQLAlchemy transaction controlled by the route dependency. Do not accept reviewer identity, roles, or admin approval from the original request body. Convert stored decision rows to existing `Reviewer` values only when the threshold is met, then call a private artifact issuance function.

- [ ] **Step 4: Run the workflow and existing capability-policy tests**

- [ ] **Step 5: Commit**

### Task 5: Require exact-action artifact matching

**Files:**
- Modify: `app/services/capability_policy.py`
- Test: `tests/unit/test_capability_policy.py`

- [ ] **Step 1: Write failing policy tests**

Issue an `autonomous_agent_run` artifact with one action scope. Assert permit for the exact scope. Assert deny for changed goal digest, changed case, missing digest, and legacy tenant-only artifact.

- [ ] **Step 2: Run and confirm current policy incorrectly permits a changed request**

- [ ] **Step 3: Enforce exact action in `_find_active_artifact` and `evaluate`**

For `EXACT_ACTION_CAPABILITIES`, require `action` and `action_digest` in both request and artifact scopes and require equality. Audit each denial reason.

- [ ] **Step 4: Run all capability-policy tests**

- [ ] **Step 5: Commit**

### Task 6: Replace the unsafe authorization routes

**Files:**
- Modify: `app/api/routes/authorization_routes.py`
- Modify: `tests/integration/test_v4_phase1_routes.py`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/pages/AuthorizationCenterPage.tsx`

- [ ] **Step 1: Write a failing HTTP lifecycle test**

The test must prove:

1. `POST /api/v4/authorization/requests` returns `pending` without an artifact.
2. A separate reviewer decision returns `issued` and an artifact ID.
3. The exact scope passes the capability check.
4. A changed digest fails the capability check.
5. The legacy unsafe route returns 410.

Use authenticated token overrides or direct `TokenData` dependency overrides so the requester and reviewer are distinct. Do not pass reviewer roles in the JSON body.

- [ ] **Step 2: Run the HTTP test and confirm 404 or contract failure**

- [ ] **Step 3: Implement routes and error mapping**

Add list/create request and record-decision routes. Map duplicate or terminal decisions to 409. Return 410 from the unsafe endpoints.

- [ ] **Step 4: Update the Authorization Center**

Show pending requests separately from issued artifacts. Remove reviewer input fields and the admin checkbox from request creation. Add an approve/reject control that calls the decision endpoint using the authenticated identity.

- [ ] **Step 5: Run backend tests, `npm test` if present, and `npm run build`**

- [ ] **Step 6: Commit**

### Task 7: Make autonomous policy evaluation fail closed

**Files:**
- Modify: `app/services/autonomous_agent.py`
- Test: `tests/unit/test_autonomous_agent_fail_closed.py`

- [ ] **Step 1: Write a failing policy-unavailable test**

Use a real SQLite session for run persistence. Replace only `CapabilityPolicy.evaluate` with a function that raises `RuntimeError`. Use test doubles for AI and the event bus. Assert:

```python
assert run.status == "denied"
assert run.disposition["code"] == "denied_policy_unavailable"
assert run.steps == []
assert ai.calls == 0
assert bus.events == []
```

Also query `AutonomousAgentRun` and assert one denied durable row exists after commit.

- [ ] **Step 2: Run and confirm the current code completes instead**

- [ ] **Step 3: Implement fail-closed evaluation and structured disposition**

Calculate the action scope before evaluation. On any policy exception, create a denied run, persist it, and return without calling a tool or provider.

- [ ] **Step 4: Add and pass a no-artifact denial test**

- [ ] **Step 5: Commit**

### Task 8: Make run persistence a required success condition

**Files:**
- Modify: `app/services/autonomous_agent.py`
- Modify: `app/api/routes/autonomous_routes.py`
- Test: `tests/unit/test_autonomous_agent_fail_closed.py`
- Test: `tests/integration/test_autonomous_routes.py`

- [ ] **Step 1: Write a failing flush-error unit test**

Make the real session fail on `flush`. Assert `AgentPersistenceError`, no in-memory replay, and no completion event.

- [ ] **Step 2: Write a failing route commit-error test**

Use a session override whose `commit` raises. Assert HTTP 503 and `autonomous_run_persistence_unavailable`.

- [ ] **Step 3: Implement typed errors and commit-before-response**

Remove best-effort persistence and `_recent` fallback. Let flush errors raise `AgentPersistenceError`. In the route, commit before event publication and before returning. Roll back and return 503 on flush or commit error.

- [ ] **Step 4: Prove a 200 response has a durable row**

After one exact-action-approved run returns 200, open a new database session and query by `run_id`.

- [ ] **Step 5: Commit**

### Task 9: Enforce production signer fail-closed behavior

**Files:**
- Modify: `app/services/capability_policy.py`
- Modify: `app/core/config.py`
- Test: `tests/unit/test_capability_policy.py`

- [ ] **Step 1: Write failing signer-selection tests**

Assert that staging or production with `SHESHNAAG_AUDIT_SIGNER=cosign` raises `ProductionSignerUnavailable` when Sigstore is unavailable. Assert development can explicitly use HMAC.

- [ ] **Step 2: Run and confirm the current fallback**

- [ ] **Step 3: Remove production fallback**

`build_signer` reads the validated environment. `CosignSigner` can use HMAC fallback only in development or test when explicitly allowed. Production and staging raise.

- [ ] **Step 4: Run signer and configuration tests**

- [ ] **Step 5: Commit**

### Task 10: Add evidence and run the P0 gate

**Files:**
- Create: `docs/runbooks/v5/p0_integrity_evidence.md`
- Modify: `scripts/sheshnaag_beta_acceptance.py`

- [ ] **Step 1: Add executable P0 checks to the acceptance script**

The script must read test output or a signed proof receipt. It must not infer a pass from source text. Add checks for exact-action denial, independent approval, fail-closed policy error, committed run, and production signer rejection.

- [ ] **Step 2: Run focused Python tests**

```bash
PYTHONPATH=. /Users/archishmanpaul/Desktop/Sheshnaag-main/.venv-v2/bin/python -m pytest -q tests/unit/test_capability_policy.py tests/unit/test_authorization_workflow.py tests/unit/test_autonomous_agent_fail_closed.py tests/integration/test_v4_phase1_routes.py tests/integration/test_autonomous_routes.py
```

- [ ] **Step 3: Run full backend tests**

```bash
PYTHONPATH=. /Users/archishmanpaul/Desktop/Sheshnaag-main/.venv-v2/bin/python -m pytest -q
```

- [ ] **Step 4: Run frontend build**

```bash
npm run build
```

Run it from `frontend/`.

- [ ] **Step 5: Run migration rehearsal and beta acceptance**

Record exact pass, fail, skip, and unavailable results. Do not convert missing Docker, external IdP, isolated worker, or load infrastructure into passes.

- [ ] **Step 6: Request a code review and fix validated P0 findings**

- [ ] **Step 7: Commit the evidence and acceptance integration**

## Completion boundary

P0 is complete only when all P0 tests pass, the migration rehearsal passes, the production signer rejects fallback, and a successful autonomous HTTP response is proven durable. This plan does not mark isolated-worker, real-detonation, load, IdP, or beta-deployment gates complete.
