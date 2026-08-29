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
