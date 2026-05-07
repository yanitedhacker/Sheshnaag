# V5 Kickoff Doc — Phase 0 Decision Record

**Status:** Draft skeleton (auto-generated 2026-05-07). Owners must fill before V5 Wave 0 starts.
**Companion docs:** `docs/superpowers/specs/2026-05-07-sheshnaag-expansion-design.md` (PRD), `~/.claude/plans/find-the-latest-prd-whimsical-fairy.md` (execution orchestration plan), `docs/runbooks/v5/route_nav_audit.md` (frontend audit).

---

## Purpose

Phase 0 of the V5-V8 expansion plan has six decision blockers and three logistics items that must be resolved before Wave 0 code merges. This doc is the durable record. Each section below has:
- **Recommendation** — the default from the execution plan / agent design
- **Owner** — who signs off
- **Decision** — *fill in*
- **Decided on** — date
- **Notes** — context for future-you

A blocker is "resolved" when its **Decision** field is non-empty and an owner has initialed it.

---

## Decision blockers

### 1. Authentik vs Keycloak for the OIDC test rig

**Recommendation:** Keycloak 24 (broadest enterprise footprint) + Authentik 2024.x (lightest local testcontainer). Auth0 left as a configuration path with no automated test (hosted nature → CI flaky).
**Why this matters:** the V5 kill-criteria gate item 3 requires "two IdPs working end-to-end". Picking the pair locks the testcontainer images we'll wire into `tests/integration/test_oidc.py`.
**Owner:** ops
**Decision:** _pending_
**Decided on:** _pending_
**Notes:** _pending_

### 2. Redis TLS in dev/test

**Recommendation:** keep `redis://` for control-plane → Redis (loopback inside the same host); require `rediss://` only for worker → Redis (over LAN). Existing `app/core/event_bus.py:38` stays unchanged for the loopback path; the worker-side connection adds `ssl=True` + cert paths.
**Why this matters:** if dev/test forces `rediss://` everywhere, we break the in-memory fallback path used by `tests/conftest.py:36` integration tests. The split keeps dev frictionless and only adds TLS where the threat model needs it (workers over LAN).
**Owner:** W1b lead
**Decision:** _pending_
**Decided on:** _pending_
**Notes:** _pending_

### 3. JIT user provisioning + tenant assignment

**Recommendation:** OIDC provider config has a `tenant_claim` field (e.g., `"tenant_claim": "https://sheshnaag/tenant"`). If the OIDC ID token carries that claim, the JIT-provisioned user lands in the named tenant. If absent, the user lands in the per-provider `oidc_default_tenant_id` (configured at provider registration time by lab_lead).
**Why this matters:** OIDC claims tell us role but not tenant; without a deterministic rule, JIT users could leak across tenants. PRD doesn't specify.
**Owner:** product
**Decision:** _pending_
**Decided on:** _pending_
**Notes:** _pending_

### 4. Worker-pool CA key custody

**Recommendation:** RSA-4096 self-signed CA private key (10-year validity), held encrypted in a single-row `worker_ca_keys` table. KEK derived via HKDF from `app/core/config.py:secret_key` — **not** the same key (separate HKDF info string per use). Decryption happens only inside `app/services/worker_pool.py:WorkerCa` for CSR signing. CA never leaves the control plane.
**Why this matters:** if the CA key is exfiltrated, an attacker can sign rogue worker certs and join the fleet. Custody must be explicit and audit-logged.
**Owner:** security review
**Decision:** _pending_
**Decided on:** _pending_
**Notes:** _pending_

### 5. Webhook signing scope

**Recommendation:** each inbound integration service (`slack_inbound.py`, `linear_inbound.py`, `jira_inbound.py`) exports `verify_signature(headers, body) -> bool`. The shared route in `integrations_webhook.py` rejects unverified requests with 401 **before** JSON parsing. Per-platform algorithms:
- Slack: HMAC-SHA256(`v0:{timestamp}:{body}`) with timestamp window ≤ 5 min replay protection
- Linear: HMAC-SHA256(`{body}`)
- JIRA: configurable per workspace (HMAC-SHA256 default)

**Why this matters:** rolling our own webhook auth is a common foot-gun. Pre-parse signature verification means a malformed body never even reaches our parser, narrowing the attack surface.
**Owner:** W2b lead
**Decision:** _pending_
**Decided on:** _pending_
**Notes:** _pending_

### 6. Frontend route × nav audit

**Recommendation:** see `docs/runbooks/v5/route_nav_audit.md` for the full enumeration. Summary: 24 routes = 24 nav items = 24 gated surfaces (1:1 mapping). 8 orphan page files exist but are unreachable; do **not** wire them just to gate them. Out-of-scope for V5; open a hygiene ticket post-V5.
**Why this matters:** if W2c only gates the nav, deep-linking bypasses the gate. Both layers must be wrapped.
**Owner:** W2c lead
**Decision:** Adopted recommendation. See `route_nav_audit.md` for the 24-row mapping table and per-route default permission slug.
**Decided on:** 2026-05-07
**Notes:** Auto-resolved via the route audit deliverable. Actual permission-to-role mapping in `permissions.ts` is W2c's call; the audit table is a starting recommendation, not a contract.

---

## Logistics items

### Worker-pool test deployment hosts

Three nodes minimum: one control plane + two sandbox workers. Same LAN segment. At least two of the three should be KVM-capable so V6 Windows-libvirt prep can begin during V5 dogfooding.

| Role | Hostname | LAN IP | KVM-capable | OS | CPU / RAM | Owner / location | Status |
|---|---|---|---|---|---|---|---|
| Control plane | _pending_ | _pending_ | n/a | _pending_ | _pending_ | _pending_ | _pending_ |
| Worker 1 | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
| Worker 2 | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
| (Optional) Worker 3 | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |

**Owner:** ops

### Beta partner team

PRD verification §6 requires "at least one real research team runs the new milestone for two weeks before the next plan is finalized."

| Field | Value |
|---|---|
| Team name | _pending_ |
| Primary contact | _pending_ |
| Team size | _pending_ |
| Sheshnaag instance type (their host or ours) | _pending_ |
| Onboarding date target | _pending_ |
| Dogfood window | _pending_ — _pending_ (≥2 weeks) |

**Owner:** ArchFit (project owner)

### V5 kickoff date

| Field | Value |
|---|---|
| Phase 0 closes (all blockers resolved) | _pending_ |
| V5 Wave 0 starts | _pending_ |
| V5 Wave 0 + Wave 1b parallel start | _pending_ (same day as Wave 0 start) |
| V5 ship-by target | _pending_ + 14 weeks |
| V5 gate sign-off target | _pending_ + 14 weeks + 1 week buffer |

**Owner:** ArchFit (project owner)

---

## Sign-off

V5 Wave 0 cannot begin until every blocker above has a non-pending **Decision** field. When all six are resolved:

```
Lab Lead sign-off: _pending_
Date: _pending_
```

Once signed, file this doc as `docs/runbooks/v5/kickoff_decision_record.md` (rename from `kickoff.md`) and link it from `docs/migration/v4-to-v5.md`.
