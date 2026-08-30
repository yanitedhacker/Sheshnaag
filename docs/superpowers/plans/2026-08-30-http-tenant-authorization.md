# HTTP Tenant Authorization Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind all HTTP tenant resolution to the caller's current database membership without breaking public demo reads or direct service workflows.

**Architecture:** Middleware validates an optional Bearer token and binds a request-local `TokenData`. The shared tenancy helpers apply `AuthService.assert_tenant_access` only inside that HTTP context, so every legacy route inherits the same read/write check.

**Tech Stack:** FastAPI, Starlette middleware, Python `ContextVar`, SQLAlchemy, Pytest.

**Spec:** `docs/superpowers/specs/2026-08-30-http-tenant-authorization-design.md`

## Global Constraints

- Public `demo-public` reads remain available without authentication.
- Private tenant access uses current database membership, not JWT membership claims alone.
- Direct non-HTTP service calls keep their current behavior.
- Production code is written only after the focused test fails for the expected reason.

---

### Task 1: Request Authentication Context

**Files:**
- Modify: `app/core/security.py`
- Create: `app/core/tenant_auth.py`
- Test: `tests/unit/test_http_tenant_authorization.py`

**Interfaces:**
- Produces: `token_data_from_payload(payload: dict) -> TokenData`
- Produces: `bind_request_token(token_data: TokenData | None)` context manager
- Produces: `current_request_token() -> tuple[bool, TokenData | None]`
- Produces: `TenantAuthorizationContextMiddleware`

- [ ] **Step 1: Write the failing middleware tests**

Add tests that send no token, an invalid token, and a valid token through a
FastAPI application with `TenantAuthorizationContextMiddleware`. Assert that
the route observes `(True, None)`, invalid JWT returns 401, and the valid JWT
exposes the literal subject and user id.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_http_tenant_authorization.py`

Expected: collection fails because `app.core.tenant_auth` and the request-token
context functions do not exist.

- [ ] **Step 3: Implement the minimal context and middleware**

Refactor JWT payload conversion from `verify_token` into
`token_data_from_payload`. Use a `ContextVar` with an unbound sentinel and a
context manager that resets its token in `finally`. Middleware must reject a
malformed authorization scheme, an empty Bearer value, and an invalid token
with HTTP 401 without logging or storing the token.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run the command from Step 2. Expected: middleware tests pass.

### Task 2: Shared Tenant Enforcement

**Files:**
- Modify: `app/core/tenancy.py`
- Modify: `app/main.py`
- Test: `tests/unit/test_http_tenant_authorization.py`

**Interfaces:**
- Consumes: `current_request_token() -> tuple[bool, TokenData | None]`
- Produces: `resolve_tenant(..., access: str = "read") -> Tenant`
- Preserves: `require_writable_tenant(...) -> Tenant`

- [ ] **Step 1: Add failing behavior tests**

Create two private tenants with real memberships. Add GET and POST test routes
that call `resolve_tenant` and `require_writable_tenant`. Prove: missing token
cannot read private data, tenant A cannot select tenant B, a read-only member
cannot write, the matching lab lead can write, and anonymous demo read works.

- [ ] **Step 2: Run the focused tests and verify RED**

Run the focused command. Expected: private access tests return 200 where 401 or
403 is required.

- [ ] **Step 3: Enforce access in the shared helpers**

When the request context is bound, call
`AuthService(session).assert_tenant_access(tenant, token_data, access=access)`.
Pass `access="write"` from `require_writable_tenant`. Register
`TenantAuthorizationContextMiddleware` in `app/main.py`.

- [ ] **Step 4: Run focused and security tests**

Run:
`env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_http_tenant_authorization.py tests/unit/test_security_jwt.py tests/unit/test_security_rbac_deps.py`

Expected: all pass.

- [ ] **Step 5: Commit**

Commit the middleware, tenancy helper, main registration, and tests with:
`git commit -m "fix: enforce HTTP tenant membership centrally"`.

