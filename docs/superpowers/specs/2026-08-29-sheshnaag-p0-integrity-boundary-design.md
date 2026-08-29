# Sheshnaag P0 Integrity Boundary Design

**Date:** 2026-08-29  
**Status:** Approved for implementation by the P0-to-beta goal  
**Scope:** Authorization request integrity, fail-closed autonomous execution, and durable run results

## 1. Purpose

Sheshnaag must not execute an autonomous action unless an independent reviewer approved the exact action. It must not report a completed action unless its durable run record committed successfully.

This P0 change closes three defects in the current flow:

1. The autonomous agent continues when capability-policy evaluation raises an exception.
2. The agent catches persistence errors and can return a completed result without a durable record.
3. The authorization request endpoint accepts reviewer decisions and an admin-approval flag from the requester. The later approval endpoint does not create an approval.

## 2. Safety boundary

The control plane can read case data, calculate ATT&CK summaries, and request grounded AI text. It cannot run shell commands, open network access, start a detonation worker, or add a new tool through this change.

The control plane and the isolated detonation worker remain separate deployment units. An authorization artifact permits one control-plane action. It does not prove that a worker is isolated or qualified.

## 3. Exact action contract

An exact action is a canonical object:

```json
{
  "action": "autonomous_agent_run",
  "arguments": {
    "case_id": 42,
    "goal": "Summarise the active findings.",
    "max_steps": 3,
    "tenant_id": 7
  }
}
```

The policy service serializes this object with sorted keys and compact UTF-8 JSON. It calculates `sha256:<lowercase hex>` over those bytes. The caller does not supply the digest. The server calculates it from validated request data.

The scope of an exact-action authorization contains:

```json
{
  "tenant_id": 7,
  "case_id": 42,
  "action": "autonomous_agent_run",
  "action_digest": "sha256:..."
}
```

For an exact-action capability, policy evaluation denies these cases:

- The request has no `action` or `action_digest`.
- The artifact has no `action` or `action_digest`.
- The action name differs.
- The digest differs because any argument changed.
- The artifact expired or was revoked.

The first P0 exact-action capability is `autonomous_agent_run`. The same helper is the required integration point for later high-risk actions.

## 4. Independent approval workflow

### 4.1 Request

`POST /api/v4/authorization/requests` creates an `AuthorizationRequestRecord` with status `pending`. The server binds the requester to the authenticated JWT subject. The body contains the capability, validated action arguments, reason, TTL request, and optional engagement reference. It does not contain reviewers, reviewer decisions, or an admin-approval boolean.

The response includes the request ID, canonical action scope, digest, required approval count, admin-approval requirement, and status. It does not include an authorization artifact.

### 4.2 Review

`POST /api/v4/authorization/requests/{request_id}/decisions` records one immutable `AuthorizationDecisionRecord`. The server binds the reviewer to the authenticated JWT subject and roles. The body contains only `decision` (`approve` or `reject`) and an optional note.

The service enforces these rules:

- The requester cannot review the request.
- One reviewer can create only one decision.
- A rejection sets the request status to `rejected` and no artifact is issued.
- Single-review capabilities need one distinct approval.
- Dual-review capabilities need two distinct approvals.
- `dual_plus_admin` also needs an approval from a token with the `lab_lead` role.
- An expired, rejected, or already-issued request cannot receive another decision.

When the threshold is met, the service issues one signed `AuthorizationArtifact` from the server-owned request and decision rows. It sets the request status to `issued` and stores the artifact ID. The request, decisions, artifact, and audit entries commit in one database transaction.

### 4.3 Compatibility

The unsafe `POST /api/v4/authorization/request` endpoint returns HTTP 410 with `unsafe_authorization_flow_removed`. The no-op artifact approval endpoint returns HTTP 410. The operator UI uses the new pending-request and decision endpoints.

## 5. Autonomous execution flow

The autonomous route calculates the exact action object from the resolved tenant ID and the validated `goal`, `case_id`, and effective `max_steps`. It sends the derived scope to `CapabilityPolicy.evaluate`.

The required sequence is:

1. Resolve tenant and authenticated actor.
2. Calculate the exact action digest.
3. Evaluate policy.
4. If evaluation returns a denial, persist a denied run and commit it. Do not call tools or the AI provider.
5. If evaluation raises an exception, persist a denied run with `policy_unavailable:<ExceptionClass>`, commit it, and do not call tools or the AI provider.
6. If evaluation permits the exact action, run the bounded read-only tools.
7. Persist the completed or failed run.
8. Commit the transaction.
9. Publish best-effort events only after the durable commit.
10. Return the committed result.

If run persistence or commit fails, the API returns HTTP 503 with `autonomous_run_persistence_unavailable`. It must not add an in-memory completed result. Event publication failures do not change a committed run result because events are telemetry, not the durable record.

## 6. Run disposition

Each `AgentRun` has a structured disposition:

```json
{
  "code": "completed_read_only",
  "message": "The approved read-only action completed.",
  "retryable": false,
  "policy_reason": "artifact_match"
}
```

P0 codes are:

- `completed_read_only`
- `denied_no_authorization`
- `denied_policy_unavailable`
- `failed_execution`
- `failed_persistence`

The existing `status` field remains `completed`, `denied`, or `failed`. The disposition gives a stable machine contract without relying on free-text `reason` values.

## 7. Persistence model

Migration `v5a08` adds:

- `authorization_request_records`
- `authorization_decision_records`
- `autonomous_agent_runs.disposition`
- `autonomous_agent_runs.action_digest`
- `autonomous_agent_runs.authorization_artifact_id`

Important constraints:

- Unique request ID.
- Unique `(request_id, reviewer)` decision.
- Decision is append-only at the service layer.
- Request status has a database check constraint.
- Decision value has a database check constraint.
- `authorization_artifact_id` is a soft reference so audit history survives administrative cleanup.

The existing signed audit chain records `request`, `approve`, `reject`, `issue`, `exercise`, `deny`, and `revoke`. The action digest is present in the audit scope for all exact-action events.

## 8. Signing policy

Development and tests can use `HmacDevSigner`.

When `ENVIRONMENT` is `staging` or `production`, `SHESHNAAG_AUDIT_SIGNER` must be `cosign`, and `CosignSigner.using_sigstore` must be true. A missing Sigstore package, identity, Fulcio connection, or Rekor connection is a startup or signing error. Production must not fall back to HMAC.

## 9. Replay boundary

P0 removes process-memory replay as a success fallback. `GET /api/v4/autonomous/runs` reads durable rows only and enforces the existing bounded limit. A database read error returns HTTP 503. Later work will add redaction and retention rules, but P0 must not return an uncommitted result from memory.

## 10. Error handling

The service uses typed errors:

- `AuthorizationWorkflowError(code)` for invalid workflow transitions.
- `AgentPersistenceError` for flush or commit failure.
- `AgentReplayError` for durable replay failure.
- `ProductionSignerUnavailable` for an invalid production signer.

Routes map validation and workflow errors to 400 or 409, authorization denial to a committed `denied` run, and infrastructure persistence/read errors to 503.

## 11. Verification

Tests must first fail against the current code and then pass after the implementation. The P0 test set proves:

- A policy exception denies before any tool or AI call.
- No artifact denies and leaves an empty step list.
- A valid exact-action artifact permits only the approved arguments.
- A changed goal, case ID, tenant ID, or step budget denies.
- A requester cannot approve their own request.
- A body cannot claim an admin approval.
- Review decisions are independent and immutable.
- A persistence failure returns 503 and creates no replay entry.
- A successful HTTP response has a committed durable row.
- Production signer selection does not fall back to HMAC.
- Existing non-exact capability artifact tests still pass.

## 12. Non-goals

This P0 slice does not claim:

- Isolated worker qualification.
- Real malware containment.
- External identity-provider qualification.
- Load or soak qualification.
- Beta deployment completion.

Those items remain later gates in the P0-to-beta program.
