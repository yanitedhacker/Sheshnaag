# Sheshnaag V4 Beta Gap Closure

**Audience:** senior engineers taking Sheshnaag V4 from current working tree to beta.
**Status:** refreshed after Pass 1 foundation spine and Pass 2 core implementation work.
**Last refreshed:** 2026-04-25
**Companion docs:** `SHESHNAAG_V4_PRD.md`, `SHESHNAAG_V4_ARCHITECTURE.md`, `SHESHNAAG_V4_ROADMAP.md`, `SHESHNAAG_V4_CAPABILITY_POLICY.md`, `SHESHNAAG_V4_DEPLOYMENT.md`.

---

## 0. How to read this document

This file is now a live gap ledger. Items marked done are already represented in the working tree. Items marked partial have a usable contract but still need beta-hardening or a full analyst surface. Open items are the next implementation queue.

Ground rule: do not rewrite green behavior. Existing tests are the canary. If a change makes a previously green lane fail, treat it as a regression unless this document explicitly calls out the failure.

---

## 1. Beta-Ready Definition

| Gate | Status | Check |
|---|---:|---|
| **G1. Feature completeness** | Open | PRD §5 success criteria items 1-10 need final closure. Autonomous agent and real detonation remain the largest gaps. |
| **G2. Analyst can drive the system without a Python REPL** | Partial | Backend authorization/capability APIs now exist. Authorization Center, Run Console SSE, ATT&CK Coverage, and CapabilityGate are in Pass 2 core. Case graph and AI sidebar remain open. |
| **G3. One real end-to-end detonation has succeeded** | Open | EICAR-class benign detonation on a Linux host with real telemetry is still pending. |
| **G4. V3 to V4 upgrade is documented and scripted** | Open | Upgrade runbook and migration script remain open. |
| **G5. Ops hardening minimum met** | Partial | Worker queue, Redis EventBus, lifecycle event publishing, and ops health endpoint exist. MinIO quarantine, real Sigstore, structured logs, OTel, and production process supervision/load validation remain open. |
| **G6. Known V3 regression fixed** | Done | `tests/integration/test_malware_lab_routes.py` setup now commits seeded recipe data. |
| **G7. Autonomous Analyst Agent ships** | Open | V4 autonomous routes/service/page are not implemented yet. |

Deferred to GA: behavior-embedding similarity, detection copilot, NL hunt and scheduled briefs, multi-host orchestration.

---

## 2. Current Status

### Done

- V3 integration regression fixed by committing setup data in `tests/integration/test_malware_lab_routes.py`.
- V4 authorization routes:
  - `GET /api/v4/authorization`
  - `POST /api/v4/authorization/request`
  - `POST /api/v4/authorization/{artifact_id}/approve`
  - `POST /api/v4/authorization/{artifact_id}/revoke`
  - `GET /api/v4/authorization/chain/root`
  - `GET /api/v4/authorization/chain/verify`
- Capability check route: `GET /api/v4/capability/check`.
- Live run SSE route: `GET /api/v4/runs/{run_id}/events`.
- Redis/EventBus foundation with development/test fallback.
- Sandbox worker and queued execute-mode handoff.
- Worker compose service.
- Ops health endpoint: `GET /api/v4/ops/health`.
- Focused backend tests for Phase 1.
- Pass 2 core backend ATT&CK mapper and routes.
- Pass 2 core frontend routes/pages for Authorization Center and ATT&CK Coverage.
- Pass 2 core Run Console SSE event panel.
- Pass 2 core CapabilityGate exercised on disclosure export.

### Partially Done

- UI authorization flow exists and can issue/revoke/check chain state, but a true persistent reviewer inbox is still deferred.
- RunConsole SSE backend and frontend event panel exist, but richer telemetry events beyond lifecycle remain a follow-up.
- Worker exists, but real host/process-pool supervision and load validation remain.
- Ops health exists, but MinIO health is deferred to the MinIO pass.

### Open

- CaseGraph page and route.
- AISidebar and GroundingInspector.
- MinIO quarantine/object store.
- Real Sigstore/Rekor hardening.
- Structured JSON logs.
- OpenTelemetry.
- Autonomous agent service/routes/page.
- V3 to V4 upgrade scripts and runbook.
- Host dependency installer.
- Real detonation E2E harness.
- Beta operator, troubleshooting, and log schema runbooks.

---

## 3. Gap Inventory

### 3.1 Analyst UI Surfaces

#### 3.1.1 AuthorizationCenterPage

**Status:** Done for Pass 2 core; beta reviewer-inbox fidelity remains partial.

Backend dependency is done in `app/api/routes/authorization_routes.py`. `frontend/src/pages/AuthorizationCenterPage.tsx` now supports listing artifacts, issuing authorization artifacts with reviewers, revoking artifacts, and checking chain root/verify state. Backend approval is currently idempotent for already issued artifacts, so the UI presents this as already issued rather than a durable pending queue.

**Remaining:** persistent pending approval queue and reviewer inbox semantics if beta testers need delegated review rather than immediate backend-issued artifacts.

#### 3.1.2 RunConsolePage Live SSE

**Status:** Done for lifecycle events; richer telemetry remains open.

Backend SSE dependency is done in `app/api/routes/live_run_routes.py`. `frontend/src/pages/RunConsolePage.tsx` keeps the current run list/detail behavior and adds a live EventSource panel with type, severity, and source filters plus disconnected/error state.

**Remaining:** publish detailed `process_exec`, `network_conn`, `dns_query`, `syscall`, `yara_hit`, `memory_finding`, `egress_blocked`, and `snapshot_reverted` telemetry into the run stream.

#### 3.1.3 AttackCoveragePage

**Status:** Done for Pass 2 core.

`frontend/src/pages/AttackCoveragePage.tsx` reads `GET /api/v4/attack/coverage` and opens `GET /api/v4/attack/technique/{id}` findings for selected techniques.

**Remaining:** MITRE Navigator export and richer case links can be added after core beta flows are green.

#### 3.1.4 CaseGraphPage

**Status:** Open.

Build `frontend/src/pages/CaseGraphPage.tsx` and `GET /api/v4/cases/{case_id}/graph` around the existing IOC/exposure graph service.

#### 3.1.5 AISidebar and GroundingInspector

**Status:** Open.

Add reusable AI session streaming and grounding inspection components after ATT&CK/Auth/Run Console are stable.

#### 3.1.6 CapabilityGate

**Status:** Done for Pass 2 core.

Backend capability-check dependency is done. `frontend/src/components/CapabilityGate.tsx` wraps the disclosure export button and links users to Authorization Center when the capability is missing.

**Remaining:** wrap additional export/disclosure/offensive actions once those surfaces are added.

#### 3.1.7 Navigation and typed frontend APIs

**Status:** Done for Pass 2 core.

`frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`, `frontend/src/api.ts`, `frontend/src/types.ts`, and the route smoke script include Authorization Center, ATT&CK Coverage, run-event SSE, authorization, capability-check, and ATT&CK response contracts.

### 3.2 ATT&CK Mapping And Detection Engineering

#### 3.2.1 AttackMapper

**Status:** Done for deterministic beta mapping.

`app/services/attack_mapper.py` maps behavior findings into `BehaviorFinding.payload.attack_techniques` using deterministic rules. LLM fallback remains disabled by default for beta tests. `MalwareLabService.materialize_run_outputs` calls `AttackMapper.map_run(run)` after output materialization.

**Remaining:** optional LLM fallback and official ATT&CK data bundle/fetch script are post-core hardening tasks.

#### 3.2.2 ATT&CK routes

**Status:** Done.

`app/api/routes/attack_routes.py` exposes:

- `GET /api/v4/attack/coverage`
- `GET /api/v4/attack/technique/{id}`

Routes are exported and registered in `app.main`.

#### 3.2.3 Detection validator

**Status:** Open, post-beta unless requested.

#### 3.2.4 YARA live scanner

**Status:** Open, post-beta unless requested.

### 3.3 Ops Hardening

#### 3.3.1 MinIO quarantine wiring

**Status:** Open.

MinIO/object-store work is intentionally deferred to a later ops-hardening pass.

#### 3.3.2 Redis Streams for live events

**Status:** Partial/Done for foundation.

`app/core/event_bus.py` exists, Redis Streams are the canonical backbone, and lifecycle event publishing is done for `run_queued`, `run_started`, `run_completed`, and `run_failed`. SSE streams from `sheshnaag:run:{run_id}:events`.

**Remaining:** detailed telemetry fanout from launchers/collectors.

#### 3.3.3 Real Sigstore signing

**Status:** Open.

HMAC development signing remains allowed in this phase. Sigstore/Rekor hardening moves to a later pass.

#### 3.3.4 Structured JSON logging

**Status:** Open.

#### 3.3.5 OpenTelemetry instrumentation

**Status:** Open.

#### 3.3.6 Sandbox-worker process pool

**Status:** Partial.

Worker service and queued execute handoff are done. `docker-compose.yml` includes a worker service, and execute-mode launch returns quickly with state `queued`.

**Remaining:** production supervision/process-pool hardening and parallel load validation.

#### 3.3.7 Lab dependencies health endpoint

**Status:** Partial/Done for Phase 1.

`GET /api/v4/ops/health` returns API, DB, Redis, lab dependency, and AI provider config status without exposing secrets.

**Remaining:** MinIO status field once object-store work lands.

### 3.4 Autonomous Analyst Agent

**Status:** Open.

Implement `app/services/autonomous_agent.py`, `app/api/routes/autonomous_routes.py`, and `frontend/src/pages/AutonomousAgentPage.tsx` in a later pass.

### 3.5 V3 to V4 Migration Path

**Status:** Open.

Add `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md` and `scripts/v4/upgrade_from_v3.sh`, including MinIO migration once object-store work lands.

### 3.6 Production Sandbox Execution

**Status:** Open.

Host dependency installer, default enforcement posture, and real detonation E2E remain open.

### 3.7 Pre-Existing V3 Test Regression

**Status:** Done.

Root cause was uncommitted setup data in `tests/integration/test_malware_lab_routes.py`. The setup now commits before closing the session.

Passing command:

```bash
RUN_INTEGRATION_TESTS=1 .venv-v2/bin/python -m pytest -q tests/unit tests/integration/test_malware_lab_routes.py tests/integration/test_taxii_routes.py tests/integration/test_v4_phase1_routes.py
```

### 3.8 Documentation And Runbooks

**Status:** Open except this refreshed gap ledger.

Still needed:

- `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md`
- `docs/SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`
- `docs/SHESHNAAG_V4_TROUBLESHOOTING.md`
- `docs/LOG_SCHEMA.md`
- README beta operator links

---

## 4. Public Interface Ledger

### Authorization

- `GET /api/v4/authorization`
- `POST /api/v4/authorization/request`
- `POST /api/v4/authorization/{artifact_id}/approve`
- `POST /api/v4/authorization/{artifact_id}/revoke`
- `GET /api/v4/authorization/chain/root`
- `GET /api/v4/authorization/chain/verify`

### Capability

- `GET /api/v4/capability/check?capability=...&scope=...&actor=...`
- Response: `{ "permitted": boolean, "reason": string, "artifact_id": string | null }`

### Live Runs

- `GET /api/v4/runs/{run_id}/events`
- Response: `text/event-stream`
- Event payload: `{id, run_id, type, timestamp, severity, source, payload}`

### ATT&CK

- `GET /api/v4/attack/coverage?tenant_slug=...&since=...`
- `GET /api/v4/attack/technique/{id}?tenant_slug=...`

### Ops

- `GET /api/v4/ops/health`
- Response includes dependency/config status only; no secret values.

---

## 5. Risk Inventory

| Risk | Probability | Impact | Mitigation |
|---|---:|---:|---|
| Real detonation on beta host reveals host-specific bugs | High | Medium | Add host dependency installer and E2E detonation harness before beta. |
| Sigstore wiring delays beta | Medium | Low | Keep HMAC development fallback explicit until Sigstore pass lands; do not imply transparency-log guarantees. |
| Worker queue appears done but lacks production supervision | Medium | Medium | Add process-pool supervision and load validation before beta cohort. |
| Capability artifacts are issued too easily in UI | Medium | Medium | Current UI is explicit that issued artifacts are already issued; persistent review queue remains a follow-up. |
| Detailed run telemetry absent from SSE | Medium | Medium | Lifecycle SSE is green; collector fanout is tracked as the next telemetry gap. |
| Beta tester uploads real malware to a cloud provider | Medium | High | Keep capability policy strict; require explicit cloud AI authorization and document the default denial. |

---

## 6. File-Level Checklist

### Backend new files

- [x] `app/api/routes/authorization_routes.py`
- [x] `app/api/routes/attack_routes.py`
- [x] `app/api/routes/live_run_routes.py`
- [ ] `app/api/routes/autonomous_routes.py`
- [ ] `app/core/object_store.py`
- [x] `app/core/event_bus.py`
- [x] `app/services/attack_mapper.py`
- [ ] `app/services/autonomous_agent.py`
- [x] `app/workers/__init__.py`
- [x] `app/workers/sandbox_worker.py`
- [ ] `app/data/attack/enterprise-attack.json`

### Backend modifications

- [x] `app/api/routes/__init__.py` - register V4 authorization, capability, live-run, ops, and attack routers
- [ ] `app/services/ai_provider_harness.py` - streaming AI session route remains open
- [ ] `app/services/ai_tools_registry.py` - real autonomous tool implementations remain open
- [x] `app/services/malware_lab_service.py` - queued execute handoff and `AttackMapper` call
- [ ] `app/services/malware_lab_service.py` - ObjectStore quarantine replacement remains open
- [ ] `app/services/capability_policy.py` - Sigstore/Rekor hardening remains open
- [ ] `app/core/security.py` - non-request capability helper remains open
- [x] `app/main.py` - V4 route registration
- [ ] `app/main.py` - OpenTelemetry and structured logging remain open
- [ ] `app/core/config.py` - MinIO/Rekor/OTel env expansion remains open
- [x] `docker-compose.yml` - worker service
- [ ] `docker-compose.yml` - minio, otel-collector, production process supervision remain open
- [ ] `Dockerfile` - bundled lab binaries remain open
- [x] `tests/integration/test_malware_lab_routes.py` - missing commit fix
- [ ] `requirements.txt` - minio, sigstore, OTel, structlog, yara-python remain open

### Frontend new files

- [x] `frontend/src/pages/AuthorizationCenterPage.tsx`
- [x] `frontend/src/pages/AttackCoveragePage.tsx`
- [ ] `frontend/src/pages/CaseGraphPage.tsx`
- [ ] `frontend/src/pages/AutonomousAgentPage.tsx`
- [ ] `frontend/src/components/AISidebar.tsx`
- [ ] `frontend/src/components/GroundingInspector.tsx`
- [ ] `frontend/src/components/LiveConsole.tsx`
- [x] `frontend/src/components/CapabilityGate.tsx`

### Frontend modifications

- [x] `frontend/src/pages/RunConsolePage.tsx` - SSE lifecycle event panel
- [x] `frontend/src/components/Layout.tsx` - Authorization and ATT&CK nav entries
- [x] `frontend/src/App.tsx` - Authorization and ATT&CK routes
- [x] `frontend/src/api.ts` - typed V4 methods and SSE helper
- [x] `frontend/src/types.ts` - V4 response types
- [x] `frontend/src/pages/DisclosureBundlesPage.tsx` - CapabilityGate on export action
- [x] `frontend/src/styles.css` - CapabilityGate and ATT&CK layout styles
- [x] `scripts/sheshnaag_frontend_smoke.py` - new route smoke coverage

### Tests

- [x] `tests/unit/test_event_bus_and_worker.py`
- [x] `tests/integration/test_v4_phase1_routes.py`
- [x] `tests/unit/test_attack_mapper.py`
- [x] `tests/integration/test_attack_routes.py`
- [ ] `tests/e2e/test_real_detonation.sh`

### Scripts / ops

- [ ] `scripts/v4/install_host_deps.sh`
- [ ] `scripts/v4/minio_provision.py`
- [ ] `scripts/v4/migrate_quarantine_to_minio.py`
- [ ] `scripts/v4/upgrade_from_v3.sh`
- [ ] `scripts/v4/generate_audit_signing_key.sh` real implementation

### Docs

- [ ] `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md`
- [ ] `docs/SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`
- [ ] `docs/SHESHNAAG_V4_TROUBLESHOOTING.md`
- [ ] `docs/LOG_SCHEMA.md`
- [ ] README beta operator links

---

## 7. Verification Ledger

### Pass 1 commands already run

```bash
RUN_INTEGRATION_TESTS=1 .venv-v2/bin/python -m pytest -q tests/unit tests/integration/test_malware_lab_routes.py tests/integration/test_taxii_routes.py tests/integration/test_v4_phase1_routes.py
npm --prefix frontend run build
npm --prefix frontend run smoke:routes
```

The route smoke command required a temporary `python -> python3` PATH shim because this shell did not provide `python`.

### Pass 2 commands passed

```bash
RUN_INTEGRATION_TESTS=1 .venv-v2/bin/python -m pytest -q tests/unit tests/integration/test_malware_lab_routes.py tests/integration/test_taxii_routes.py tests/integration/test_v4_phase1_routes.py tests/integration/test_attack_routes.py
npm --prefix frontend run build
npm --prefix frontend run smoke:routes
```

The route smoke command was run with the same temporary `python -> python3` PATH shim because this shell did not provide `python`.

---

## 8. Next Pass

The next implementation pass should focus on ops hardening and beta closeout prerequisites:

1. MinIO/object-store quarantine and migration.
2. Production worker supervision/load validation.
3. Structured logs and OTel.
4. Sigstore/Rekor hardening.
5. Host dependency installer.
6. Real detonation E2E harness.
7. Beta runbooks.

Autonomous Agent should start after the above contracts are stable unless the beta narrative requires it sooner.
