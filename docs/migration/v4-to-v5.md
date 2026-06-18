# Migration Guide: V4 → V5

## Overview

V5 adds RBAC, case lifecycle, worker pool, OIDC, team workflow integrations, and team analytics. V4 API paths remain under `/api/v4/`; new surfaces use `/api/v5/`.

**Kickoff record:** [docs/runbooks/v5/kickoff_decision_record.md](../runbooks/v5/kickoff_decision_record.md)

## Database migrations

Run Alembic through V5 head:

```bash
alembic upgrade head
```

New revisions (in order): `v5a01` roles/permissions → `v5a02` case lifecycle → `v5a03` custom case fields → `v5a04` worker registry → `v5a05` OIDC → `v5a06` integration links → `v5a07` analytics permission.

## Breaking changes

| Area | V4 | V5 |
|------|----|----|
| Roles | Implicit / tenant membership string | 5 seeded roles with permission matrix |
| Case status | `analysis_cases.status` string | `lifecycle_state` enum + transition audit |
| Workers | Single-host sandbox | mTLS worker fleet over Redis Streams |
| Auth | JWT only | OIDC JIT + JWT for service accounts |
| Frontend | Ungated nav | RoleGate on all 24 routes |

## Operator steps

1. **Seed RBAC** — migration `v5a01` seeds roles; assign `lab_lead` to at least one user per tenant.
2. **Register OIDC providers** — Keycloak/Authentik per kickoff decision #1.
3. **Provision worker CA** — first bootstrap call auto-generates CA if `worker_ca_keys` empty.
4. **Enroll workers** — mint tokens, run `sandbox_agent` on each worker node.
5. **Verify gate** — follow [V5 smoke runbook](../runbooks/v5/smoke.md).

## Rollback

V5 migrations are forward-only. Rollback requires restore from pre-V5 DB snapshot. Worker certs become invalid if CA row is restored to an earlier state — re-enroll all workers after rollback.

## Deferred to V6

- Drop legacy `analysis_cases.status` column
- `assignee_role` filter on review queues
- Wire `permitted_requester_for` into authorization issuance (V6 W1)
