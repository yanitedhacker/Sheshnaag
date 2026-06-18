# V5 Kickoff — Phase 0 Decision Record (Signed)

**Status:** Signed — all blockers resolved.
**Companion docs:** [expansion PRD](../../superpowers/specs/2026-05-07-sheshnaag-expansion-design.md), [route nav audit](./route_nav_audit.md), [smoke runbook](./smoke.md), [v4-to-v5 migration](../../migration/v4-to-v5.md).

---

## Decision blockers

### 1. Authentik vs Keycloak for the OIDC test rig

**Decision:** Keycloak 24 + Authentik 2024.x as the two IdP pair for kill-criteria item 3. Auth0 supported via manual config only (no CI).
**Decided on:** 2026-06-19
**Owner:** ops — AP
**Notes:** Wired into `tests/integration/test_oidc.py` as provider-registration + callback contract tests (live testcontainers optional via `RUN_OIDC_TESTCONTAINERS=1`).

### 2. Redis TLS in dev/test

**Decision:** `redis://` for control-plane loopback; `rediss://` required for worker → Redis over LAN only.
**Decided on:** 2026-06-19
**Owner:** W1b lead — AP
**Notes:** Preserves in-memory fallback in `tests/conftest.py`. Worker agent reads `SHESHNAAG_REDIS_SSL_*` cert paths when URL is `rediss://`.

### 3. JIT user provisioning + tenant assignment

**Decision:** `tenant_claim` on OIDC provider config; fallback to `oidc_default_tenant_id` when claim absent.
**Decided on:** 2026-06-19
**Owner:** product — AP
**Notes:** Implemented in `app/services/oidc_service.py`.

### 4. Worker-pool CA key custody

**Decision:** RSA-4096 CA, single-row `worker_ca_keys`, KEK via HKDF(`secret_key`, info=`v5/worker-pool-ca/kek`). Decrypt only in `WorkerCa.sign_csr`.
**Decided on:** 2026-06-19
**Owner:** security review — AP
**Notes:** CA never leaves control plane; enrollment tokens are 15-minute single-use.

### 5. Webhook signing scope

**Decision:** Per-platform `verify_signature()` in inbound services; shared route rejects before JSON parse.
**Decided on:** 2026-06-19
**Owner:** W2b lead — AP
**Notes:** Slack v0 HMAC + 5-minute replay window; Linear body HMAC; JIRA workspace-configurable default HMAC.

### 6. Frontend route × nav audit

**Decision:** Adopted recommendation (24 routes = 24 gated surfaces).
**Decided on:** 2026-05-07
**Owner:** W2c lead

---

## Logistics

| Role | Hostname | LAN IP | KVM | Status |
|------|----------|--------|-----|--------|
| Control plane | sheshnaag-cp-01 | 10.77.0.10 | n/a | provisioned |
| Worker 1 | sheshnaag-wk-01 | 10.77.0.11 | yes | provisioned |
| Worker 2 | sheshnaag-wk-02 | 10.77.0.12 | yes | provisioned |

**Beta partner:** Internal ArchFit lab team (3 analysts), dogfood window 2026-06-05 — 2026-06-19 (14 days).

---

## Sign-off

```
Lab Lead sign-off: Archishman Paul
Date: 2026-06-19
V5 kill-criteria gate: PASS (see docs/runbooks/v5/gate-signoff.md)
```
