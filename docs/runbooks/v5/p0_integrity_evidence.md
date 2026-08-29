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
