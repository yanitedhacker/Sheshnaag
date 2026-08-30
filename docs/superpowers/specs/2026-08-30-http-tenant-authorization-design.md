# HTTP Tenant Authorization Boundary Design

**Status:** Approved for implementation by the repository owner on 2026-08-30.

## Objective

Bind every tenant resolved through the HTTP API to the authenticated actor's
current database membership. Keep public demo reads available. Deny all writes
to the demo tenant and deny private tenant access when the actor has no current
membership or role.

## Current failure

Legacy route modules call `resolve_tenant` and `require_writable_tenant`
directly. Those helpers trust a request-supplied tenant id or slug. They do not
know the JWT actor. A caller can therefore select another private tenant on
routes that do not add their own authorization dependency.

The vulnerable control is shared by many routes. Fixing only `/api/specimens`
or `/api/runs` would leave equivalent paths open.

## Design

Add a request-local authentication context in `app/core/security.py`. A small
HTTP middleware parses an optional Bearer token once, validates it with the
existing JWT rules, stores the resulting `TokenData` in a `ContextVar`, and
always clears the value after the response.

The context has three states:

- unbound: code is running outside the HTTP request boundary;
- bound with no token: the HTTP request did not supply credentials;
- bound with token: the HTTP request supplied a valid JWT.

`resolve_tenant` will enforce read membership only when the context is bound.
`require_writable_tenant` will enforce write membership through the same shared
boundary. Service and migration code that calls these helpers outside an HTTP
request keeps its current behavior.

The existing `AuthService.assert_tenant_access` remains the authority for live
database membership and role checks. JWT membership claims are not enough.

## Security rules

- An invalid Bearer token returns HTTP 401 before a tenant route runs.
- A missing token can read `demo-public` only.
- A missing token cannot read or write a private tenant when auth is enabled.
- A valid token cannot read a private tenant without a current membership.
- A `read_only` or `reviewer` member can read its private tenant but cannot
  write it.
- An `analyst`, `senior_analyst`, or `lab_lead` member can write its private
  tenant.
- No role can write the read-only demo tenant.
- The membership check uses the tenant row selected by the request, not a
  tenant claim chosen by the client.

## Compatibility

- Development with `AUTH_ENABLED=false` keeps anonymous read and write access
  to private development data.
- Public demo reads stay anonymous when auth is enabled.
- Direct service calls, migration scripts, and test fixtures stay outside the
  HTTP boundary unless they explicitly bind a request token.
- Routes that already call `verify_token` or `assert_tenant_access` continue to
  work. The shared check is defense in depth.

## Verification

Integration tests will use a small FastAPI application with the middleware and
real SQLAlchemy rows. They will prove missing-token denial, cross-tenant denial,
read-only-role denial on write, authorized write success, and public demo read
compatibility.

