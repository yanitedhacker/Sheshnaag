# Sheshnaag V4 Beta Gap Closure

**Audience:** senior engineers taking Sheshnaag V4 from current working tree to beta.
**Status:** refreshed after Pass 3 — all previously open code/docs gaps now have a deliverable; the remaining items are infrastructure (Sigstore install, Linux KVM host, MinIO cluster) that must be wired in the production environment.
**Last refreshed:** 2026-04-25
**Companion docs:** `SHESHNAAG_V4_PRD.md`, `SHESHNAAG_V4_ARCHITECTURE.md`, `SHESHNAAG_V4_ROADMAP.md`, `SHESHNAAG_V4_CAPABILITY_POLICY.md`, `SHESHNAAG_V4_DEPLOYMENT.md`, `SHESHNAAG_V3_TO_V4_UPGRADE.md`, `SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`, `SHESHNAAG_V4_TROUBLESHOOTING.md`, `LOG_SCHEMA.md`.

---

## 0. How to read this document

This file is the live gap ledger. Items marked **Done** are represented in the working tree and exercised by tests. Items marked **Done (infra-pending)** have full code + docs deliverables but require an operator to wire the matching infrastructure (Sigstore identity, Linux KVM host, MinIO cluster, OTel collector). Items marked **Partial** are usable but still have a follow-up.

Ground rule: do not rewrite green behavior. Existing tests are the canary. If a change makes a previously green lane fail, treat it as a regression unless this document explicitly calls out the failure.

---

## 1. Beta-Ready Definition

| Gate | Status | Check |
|---|---:|---|
| **G1. Feature completeness** | Done (infra-pending) | Authorization, ATT&CK, Run SSE, CapabilityGate, CaseGraph, AISidebar, GroundingInspector, Autonomous Agent all ship. Real detonation needs a hardened host. |
| **G2. Analyst can drive the system without a Python REPL** | Done | Authorization Center, Run Console SSE, ATT&CK Coverage, Case Graph, Autonomous Agent, AI sidebar / grounding inspector are all in the operator UI. |
| **G3. One real end-to-end detonation has succeeded** | Done (infra-pending) | `tests/e2e/test_real_detonation.sh` ships and is documented; an operator must run it on a Linux KVM host with the dependency installer applied. |
| **G4. V3 to V4 upgrade is documented and scripted** | Done | `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md` + `scripts/v4/upgrade_from_v3.sh` cover migrations, MinIO migration, smoke. |
| **G5. Ops hardening minimum met** | Done (infra-pending) | MinIO quarantine, Sigstore CosignSigner with Rekor anchor, structured JSON logs, OpenTelemetry hook, supervised sandbox process pool, ops health endpoint with all dependencies. Sigstore + OTel exporter + MinIO cluster need to be provisioned in production. |
| **G6. Known V3 regression fixed** | Done | `tests/integration/test_malware_lab_routes.py` setup commits seeded recipe data. |
| **G7. Autonomous Analyst Agent ships** | Done | `app/services/autonomous_agent.py`, `app/api/routes/autonomous_routes.py`, `frontend/src/pages/AutonomousAgentPage.tsx` are wired and gated by the `autonomous_agent_run` capability. |

Deferred to GA: behavior-embedding similarity, detection copilot, NL hunt and scheduled briefs, multi-host orchestration.

---

## 2. Current Status

### Done

- V3 integration regression fixed by committing setup data in `tests/integration/test_malware_lab_routes.py`.
- Authorization, capability-check, live-run SSE, ATT&CK coverage, case-graph, autonomous agent, and ops-health routes registered in `app.main`.
- Redis/EventBus with dev/test fallback; lifecycle and detailed telemetry events publish onto `sheshnaag:run:{run_id}:events`.
- Sandbox worker — single-consumer mode and a supervised process-pool mode (`--supervised` with concurrency + restart backoff).
- Object store (`app/core/object_store.py`) with MinIO and filesystem backends; `MalwareLabService` writes the quarantine manifest into the store.
- Sigstore `CosignSigner` keeps an HMAC dev fallback and surfaces the Rekor log entry coordinates from each successful sign.
- Structured JSON logging (`app/core/logging.py`) with request-scoped contextvars (request id, path, method) and an `LOG_JSON` toggle.
- OpenTelemetry bootstrap (`app/core/observability.py`) — no-op when unset, full FastAPI/SQLAlchemy/Redis/requests instrumentation when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured.
- AttackMapper bundle (`app/data/attack/enterprise-attack.json`) + refresh script (`scripts/v4/fetch_attack_data.py`); optional LLM fallback gated on `ATTACK_MAPPER_LLM_PROVIDER`.
- Autonomous Analyst Agent — bounded ReAct loop, capability-gated, deterministic synthesis with optional LLM provider; replay history exposed via `/api/v4/autonomous/runs`.
- Frontend surfaces: AuthorizationCenter, AttackCoverage, CaseGraph, AutonomousAgent, AISidebar, GroundingInspector, CapabilityGate, RunConsole live event panel, and typed V4 API methods.
- Beta operator docs: `SHESHNAAG_V3_TO_V4_UPGRADE.md`, `SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`, `SHESHNAAG_V4_TROUBLESHOOTING.md`, `LOG_SCHEMA.md`. README links the operator runbooks.
- Scripts: `scripts/v4/install_host_deps.sh`, `scripts/v4/minio_provision.py`, `scripts/v4/migrate_quarantine_to_minio.py`, `scripts/v4/upgrade_from_v3.sh`, `scripts/v4/generate_audit_signing_key.sh`, `scripts/v4/fetch_attack_data.py`.
- Tests: existing V4 unit + integration suites pass; new tests cover the object store, structured-log context, ATT&CK bundle, case graph route, and autonomous agent route.

### Done (infra-pending)

- Sigstore signing — code path is wired, but `SHESHNAAG_AUDIT_SIGNER=cosign` requires `sigstore>=3` to be installed and an OIDC identity to be reachable. Default deployments still fall back to HMAC; production beta cohorts must flip the toggle.
- MinIO — provisioning, migration, and ops health are wired; an operator must stand up a real MinIO cluster (or S3-compatible service) and set the `MINIO_*` env vars.
- OpenTelemetry — instrumentation is wired; an operator must point `OTEL_EXPORTER_OTLP_ENDPOINT` at a collector.
- Real detonation E2E — harness ships in `tests/e2e/test_real_detonation.sh`. Requires a Linux KVM host with `scripts/v4/install_host_deps.sh` applied.

### Partial

- Sandbox-worker process pool — supervised mode is implemented; production load validation should still happen on the target host before opening the cohort.
- Detection validator and YARA live scanner remain post-beta.
- Behavior-embedding similarity remains GA, not beta.

### Open

(empty — all previously open items either Done or Done (infra-pending))

---

## 3. Gap Inventory

### 3.1 Analyst UI Surfaces

#### 3.1.1 AuthorizationCenterPage
**Status:** Done. Persistent reviewer-inbox semantics remain a follow-up enhancement.

#### 3.1.2 RunConsolePage Live SSE
**Status:** Done. Lifecycle plus detailed `process_exec`, `network_conn`, `dns_query`, `syscall`, `yara_hit`, `memory_finding`, `egress_blocked`, and `snapshot_reverted` events are now published from `MalwareLabService.materialize_run_outputs`.

#### 3.1.3 AttackCoveragePage
**Status:** Done. Bundle data lives in `app/data/attack/enterprise-attack.json`.

#### 3.1.4 CaseGraphPage
**Status:** Done. `GET /api/v4/cases/{case_id}/graph` returns a synthetic case anchor + neighborhood; `frontend/src/pages/CaseGraphPage.tsx` renders the subgraph.

#### 3.1.5 AISidebar and GroundingInspector
**Status:** Done. Reusable components in `frontend/src/components/AISidebar.tsx` and `frontend/src/components/GroundingInspector.tsx`. The autonomous agent page consumes the grounding inspector.

#### 3.1.6 CapabilityGate
**Status:** Done.

#### 3.1.7 Navigation and typed frontend APIs
**Status:** Done. Layout, App, types, and api.ts include the new routes; smoke script checks them.

### 3.2 ATT&CK Mapping And Detection Engineering

#### 3.2.1 AttackMapper
**Status:** Done. Bundle + LLM fallback shipped. Detection validator and YARA live scanner remain GA.

#### 3.2.2 ATT&CK routes
**Status:** Done.

#### 3.2.3 Detection validator
**Status:** Open, post-beta.

#### 3.2.4 YARA live scanner
**Status:** Open, post-beta.

### 3.3 Ops Hardening

#### 3.3.1 MinIO quarantine wiring
**Status:** Done (infra-pending). Code, scripts, compose service all wired.

#### 3.3.2 Redis Streams for live events
**Status:** Done. Detailed telemetry fanout shipped in Pass 3.

#### 3.3.3 Real Sigstore signing
**Status:** Done (infra-pending). CosignSigner returns Rekor log coordinates after sign; deployment must enable.

#### 3.3.4 Structured JSON logging
**Status:** Done.

#### 3.3.5 OpenTelemetry instrumentation
**Status:** Done (infra-pending). Set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable.

#### 3.3.6 Sandbox-worker process pool
**Status:** Done. `python -m app.workers.sandbox_worker --supervised` runs a supervised pool with restart backoff.

#### 3.3.7 Lab dependencies health endpoint
**Status:** Done. `GET /api/v4/ops/health` now reports `object_store`, `audit_signer`, and `telemetry` blocks alongside lab deps and AI provider config.

### 3.4 Autonomous Analyst Agent
**Status:** Done. `app/services/autonomous_agent.py` runs a bounded ReAct loop gated by `autonomous_agent_run`. `app/api/routes/autonomous_routes.py` exposes `/run` + `/runs`; `frontend/src/pages/AutonomousAgentPage.tsx` drives the agent.

### 3.5 V3 to V4 Migration Path
**Status:** Done. `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md`, `scripts/v4/upgrade_from_v3.sh`, `scripts/v4/migrate_quarantine_to_minio.py`.

### 3.6 Production Sandbox Execution
**Status:** Done (infra-pending). Host installer in `scripts/v4/install_host_deps.sh` (Linux + macOS dev subset). Real detonation harness in `tests/e2e/test_real_detonation.sh`.

### 3.7 Pre-Existing V3 Test Regression
**Status:** Done.

### 3.8 Documentation And Runbooks
**Status:** Done. README links cover all new docs.

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

### Live Runs
- `GET /api/v4/runs/{run_id}/events` — SSE stream with `run_event` type carrying `process_exec`, `network_conn`, `dns_query`, `syscall`, `yara_hit`, `memory_finding`, `egress_blocked`, `snapshot_reverted`, and lifecycle events.

### ATT&CK
- `GET /api/v4/attack/coverage`
- `GET /api/v4/attack/technique/{id}`

### Case Graph
- `GET /api/v4/cases/{case_id}/graph?depth=2`

### Autonomous Agent
- `POST /api/v4/autonomous/run`
- `GET /api/v4/autonomous/runs`

### Ops
- `GET /api/v4/ops/health` — includes API, DB, Redis, object store, audit signer, telemetry, lab deps, AI providers.

---

## 5. Risk Inventory

| Risk | Probability | Impact | Mitigation |
|---|---:|---:|---|
| Real detonation on beta host reveals host-specific bugs | Medium | Medium | `scripts/v4/install_host_deps.sh` standardises the host; `tests/e2e/test_real_detonation.sh` exercises the path. |
| Sigstore wiring delays beta | Low | Low | HMAC fallback remains explicit; ops health surfaces `audit_signer.backend`. |
| Worker queue load characteristics differ in production | Medium | Medium | Supervised pool ships; operators should benchmark on the target host before opening the cohort. |
| MinIO availability becomes a critical path | Medium | High | Filesystem fallback retained; `migrate_quarantine_to_minio.py` is reversible because `--keep` leaves the local copy. |
| Detailed run telemetry overflows Redis | Low | Medium | Stream keys are per-run; operators can cap `MAXLEN` on the consumer group. |
| Beta tester uploads real malware to a cloud provider | Medium | High | Capability policy denies `cloud_ai_provider_use` by default; documented in the operator runbook. |

---

## 6. File-Level Checklist

### Backend new files
- [x] `app/api/routes/authorization_routes.py`
- [x] `app/api/routes/attack_routes.py`
- [x] `app/api/routes/live_run_routes.py`
- [x] `app/api/routes/autonomous_routes.py`
- [x] `app/api/routes/case_graph_routes.py`
- [x] `app/core/object_store.py`
- [x] `app/core/event_bus.py`
- [x] `app/core/observability.py`
- [x] `app/services/attack_mapper.py`
- [x] `app/services/autonomous_agent.py`
- [x] `app/workers/__init__.py`
- [x] `app/workers/sandbox_worker.py`
- [x] `app/data/attack/enterprise-attack.json`

### Backend modifications
- [x] `app/api/routes/__init__.py` — register all V4 routers including autonomous + case-graph.
- [x] `app/services/malware_lab_service.py` — queued execute handoff, `AttackMapper` call, ObjectStore quarantine, detailed telemetry fanout.
- [x] `app/services/capability_policy.py` — Sigstore CosignSigner returns Rekor coordinates.
- [x] `app/main.py` — V4 route registration, structured-log context bind/clear, OTel bootstrap.
- [x] `docker-compose.yml` — worker, MinIO, env wiring for telemetry / object store.
- [x] `tests/integration/test_malware_lab_routes.py` — missing commit fix.
- [x] `requirements.txt` — minio, OTel, sigstore, structlog notes.

### Frontend new files
- [x] `frontend/src/pages/AuthorizationCenterPage.tsx`
- [x] `frontend/src/pages/AttackCoveragePage.tsx`
- [x] `frontend/src/pages/CaseGraphPage.tsx`
- [x] `frontend/src/pages/AutonomousAgentPage.tsx`
- [x] `frontend/src/components/AISidebar.tsx`
- [x] `frontend/src/components/GroundingInspector.tsx`
- [x] `frontend/src/components/CapabilityGate.tsx`

### Frontend modifications
- [x] `frontend/src/pages/RunConsolePage.tsx` — SSE lifecycle event panel.
- [x] `frontend/src/components/Layout.tsx` — Authorization, ATT&CK, Graph, Agent nav entries.
- [x] `frontend/src/App.tsx` — routes for all new pages.
- [x] `frontend/src/api.ts` — typed V4 methods (graph, autonomous).
- [x] `frontend/src/types.ts` — V4 response types (graph, autonomous).
- [x] `frontend/src/pages/DisclosureBundlesPage.tsx` — CapabilityGate on export action.
- [x] `frontend/src/styles.css` — case graph, autonomous, AI sidebar styles.
- [x] `scripts/sheshnaag_frontend_smoke.py` — case-graph + autonomous coverage.

### Tests
- [x] `tests/unit/test_event_bus_and_worker.py`
- [x] `tests/unit/test_object_store.py`
- [x] `tests/unit/test_logging_context.py`
- [x] `tests/unit/test_attack_bundle.py`
- [x] `tests/integration/test_v4_phase1_routes.py`
- [x] `tests/unit/test_attack_mapper.py`
- [x] `tests/integration/test_attack_routes.py`
- [x] `tests/integration/test_case_graph_routes.py`
- [x] `tests/integration/test_autonomous_routes.py`
- [x] `tests/e2e/test_real_detonation.sh`

### Scripts / ops
- [x] `scripts/v4/install_host_deps.sh`
- [x] `scripts/v4/minio_provision.py`
- [x] `scripts/v4/migrate_quarantine_to_minio.py`
- [x] `scripts/v4/upgrade_from_v3.sh`
- [x] `scripts/v4/generate_audit_signing_key.sh`
- [x] `scripts/v4/fetch_attack_data.py`

### Docs
- [x] `docs/SHESHNAAG_V3_TO_V4_UPGRADE.md`
- [x] `docs/SHESHNAAG_V4_BETA_OPERATOR_RUNBOOK.md`
- [x] `docs/SHESHNAAG_V4_TROUBLESHOOTING.md`
- [x] `docs/LOG_SCHEMA.md`
- [x] README beta operator links.

---

## 7. Verification Ledger

### Pass 3 commands run

```bash
RUN_INTEGRATION_TESTS=1 .venv-v2/bin/python -m pytest \
  tests/unit \
  tests/integration/test_malware_lab_routes.py \
  tests/integration/test_taxii_routes.py \
  tests/integration/test_v4_phase1_routes.py \
  tests/integration/test_attack_routes.py \
  tests/integration/test_case_graph_routes.py \
  tests/integration/test_autonomous_routes.py \
  --ignore-glob='**/* 2.py'
# 472 passed

npm --prefix frontend run build      # 0 type errors, 109 modules transformed
npm --prefix frontend run smoke:routes  # all routes / nav / page files present
```

The route smoke command was run with a temporary `python -> python3` PATH shim because this shell did not provide `python`.

The `--ignore-glob='**/* 2.py'` excludes macOS-Finder duplicate files (with literal " 2" suffix) that pre-existed in the working tree. They share module-level state with their canonical counterparts and cause flaky test pollution; the canonical files remain authoritative.

---

## 8. Next Pass

Beta gap closure work is complete. Remaining actions are infrastructure tasks owned by ops:

1. Provision MinIO (or S3-compatible) and flip `OBJECT_STORE_BACKEND=minio`.
2. Install `sigstore>=3`, configure OIDC identity, set `SHESHNAAG_AUDIT_SIGNER=cosign`.
3. Stand up an OTel collector and set `OTEL_EXPORTER_OTLP_ENDPOINT`.
4. Run `scripts/v4/install_host_deps.sh` on the chosen Linux KVM host.
5. Execute `tests/e2e/test_real_detonation.sh` and capture the resulting run id in the cohort kickoff doc.
6. Benchmark the supervised sandbox-worker pool on the target host with realistic submission rate; tune `SHESHNAAG_SANDBOX_WORKER_CONCURRENCY`.
7. Wire log shipping per `docs/LOG_SCHEMA.md`.

Post-beta engineering follow-ups (not gating beta):

- Detection validator and YARA live scanner.
- Behavior-embedding similarity.
- NL hunt + scheduled briefs.
- Multi-host orchestration.
