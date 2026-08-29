# P0 Integrity Evidence

**Branch:** `yanitedhacker/p0-to-beta`  
**Worktree:** `/private/tmp/sheshnaag-p0-to-beta-20260829`  
**Date:** 2026-08-29

## Baseline

The existing `/Users/archishmanpaul/Desktop/Sheshnaag-main/.venv-v2` environment did not give a test result. Python blocked while it read packages such as `httpx` and `sqlalchemy`. Interrupt traces showed the blocked imports. This is recorded as an unavailable environment, not as a product test failure.

A clean Python 3.11.15 environment was created at `/private/tmp/sheshnaag-p0-venv`. It contains the repository's declared minimal requirements and the control-plane packages needed by eager route imports.

### Capability-policy baseline

Command:

```bash
PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -vv --maxfail=1 tests/unit/test_capability_policy.py
```

Result:

```text
7 passed in 1.34s
```

### In-memory route baseline

Command:

```bash
RUN_INTEGRATION_TESTS=1 PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -vv --maxfail=1 tests/integration/test_autonomous_routes.py tests/integration/test_v4_phase1_routes.py
```

Result:

```text
4 passed, 6 warnings in 1.99s
```

The warnings were Starlette/httpx deprecation, Pydantic class-config deprecation, Python `crypt` deprecation, and Pytest collection warnings for module-level FastAPI objects. They did not change the pass result.

## Evidence boundary

This baseline proves only the current capability-policy unit tests and local in-memory route tests. It does not prove Postgres migration behavior, production signing, external identity providers, isolated worker behavior, real detonation, load performance, or beta deployment.

## P0 authorization schema

The model constraint test result after adding request and decision rows was:

```text
7 passed
```

A controlled SQLite database was stamped at `v5a07` with the legacy `autonomous_agent_runs` columns. `alembic upgrade v5a08` completed. The database reported:

```text
v5a08
authorization_decision_records
authorization_request_records
autonomous_agent_runs.disposition JSON NOT NULL DEFAULT '{}'
autonomous_agent_runs.action_digest VARCHAR(80)
autonomous_agent_runs.authorization_artifact_id VARCHAR(64)
```

### Historical fresh-install blocker

A separate empty-database `alembic upgrade head` did not reach `v5a08`. Migration `20260409_0001` tried to alter `advisory_records` before any migration created that table and raised:

```text
sqlalchemy.exc.NoSuchTableError: advisory_records
```

This is a confirmed pre-existing fresh-install migration blocker. It is not a `v5a08` result. It must be repaired and retested before the deployment gate can pass.

## Independent exact-action HTTP lifecycle

The safe route lifecycle now creates a pending request and needs a decision from a different token subject. The route test also submitted requester-controlled `reviewers` and `is_admin_approved` fields. The response remained pending with no artifact. A separate reviewer then issued the artifact. The exact scope passed policy evaluation, a changed digest failed, and the unsafe legacy endpoint returned HTTP 410.

Focused backend result:

```text
34 passed
```

The focused set was:

- capability policy
- authorization workflow
- audit chain
- V4 foundation routes
- autonomous routes

Frontend production build result:

```text
TypeScript no-emit check passed
Vite transformed 100 modules
Production build completed in 732ms
```

`npm ci` reported 6 dependency audit findings: 3 moderate and 3 high. This is not treated as a pass. The dependency findings need a separate validated update because an automatic audit fix can make breaking dependency changes.

## Fail-closed autonomous policy boundary

The agent tests replace only policy evaluation for the infrastructure-error case and use real SQLite persistence. A policy exception now creates a denied durable run before any agent tool, AI call, or event publication. A normal no-artifact decision has the same stop-before-work property.

The stored run includes:

- structured denial disposition
- server-derived action digest
- authorization artifact ID when permitted

Focused P0 result after this change:

```text
36 passed
```

## Durable response boundary

The persistence-error unit test raises only when SQLAlchemy flushes an `AutonomousAgentRun`. The agent now raises `AgentPersistenceError`, creates no replay item, and publishes no event.

The route commit-error test injects a failing session commit. The route returns:

```text
HTTP 503 autonomous_run_persistence_unavailable
```

The positive route test issues an exact-action artifact, receives HTTP 200 with `status=completed`, and then opens a new database session. The new session finds the committed run with the same action digest and authorization artifact ID.

Focused P0 result after this change:

```text
38 passed
```

## Production signer fail-closed boundary

Signer selection now rejects these states:

- staging or production with a non-cosign signer
- beta or release profile with a non-cosign signer
- secure runtime with `cosign` selected but Sigstore unavailable
- unknown signer names

Development can still select HMAC explicitly. The production-missing-Sigstore test uses a controlled dummy module so it does not depend on the host package set.

Focused P0 result after this change:

```text
41 passed
```

## Executable acceptance gate

The beta acceptance script now runs eight named P0 behavior tests. It does not use file-presence checks as proof for the P0 integrity boundary. The tests cover exact-action scope, production signer failure, independent approval, policy failure, durable persistence failure, route commit failure, and committed success replay.

Gate result:

```text
8 passed
p0_integrity.status=ok
docker_compose.status=ok
duplicate_artifacts=[]
overall status=blocked
```

The overall result is correctly blocked. The local health endpoint was not available in this execution environment, and these proof receipts do not exist yet:

- real detonation
- AI provider matrix
- capability audit
- STIX/TAXII
- autonomous agent
- load rehearsal

The health request returned `Operation not permitted`. This result is an environment-access blocker until the same check runs in a permitted runtime. It is not a product health pass or failure.

## Migration rehearsal

The repository migration rehearsal completed with exit code 0. It validated all four declared checks:

```text
fresh_bootstrap_creates_maintainer_assessments=true
maintainer_assessments_has_report_id=true
v4a03_to_v4a04_creates_maintainer_assessments=true
v4a04_downgrade_removes_maintainer_assessments=true
```

The stamped `v4a03` upgrade path reached `v5a08`, and the downgrade returned to `v4a03`. This does not remove the separate empty-database Alembic blocker recorded above.

## Full local regression

The full backend test run completed:

```text
728 passed, 134 skipped, 14 warnings in 38.83s
```

The skipped tests are external integration tests controlled by repository policy. They are not passes. The warnings are deprecation and test-collection warnings. The frontend production build result remains the successful result recorded above because no frontend source changed after that build.

## Evidence-gated claim ledger

The beta gate no longer accepts file presence or marker text as proof. Each proof class now needs an Ed25519-signed receipt with a pinned trust fingerprint. The verifier checks:

- proof schema and class
- exact Git commit
- receipt pass state
- pinned signer fingerprint
- canonical payload digest and Ed25519 signature
- relative artifact path, byte size, and SHA-256

Focused proof and P0 result:

```text
51 passed
```

The focused run included capability policy, authorization workflow, autonomous fail-closed behavior, proof receipts, the proof CLI, beta acceptance, and the V4 authorization and autonomous HTTP routes.

The current live acceptance report remains blocked:

```text
p0_integrity=ok
docker_compose=ok
ops_health_unreachable
proof_trust_root_missing
missing_proof.real_detonation
missing_proof.ai_provider_matrix
missing_proof.capability_audit
missing_proof.stix_taxii
missing_proof.autonomous_agent
missing_proof.load_rehearsal
```

This is the correct release state. No proof receipt was generated from missing evidence.
