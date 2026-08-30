# Capability-Aware Worker Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dispatch each queued run to one compatible worker class and align risky provider selection with the Linux KVM runtime.

**Architecture:** A pure execution-requirements module derives capabilities from stored run state. A worker-routing module maps capabilities to versioned Redis streams under one consumer group. Both worker entry points use the same functions and reject mismatches before execution.

**Tech Stack:** Python, Redis Streams, SQLAlchemy, Pytest, libvirt/KVM provider registry.

**Spec:** `docs/superpowers/specs/2026-08-30-capability-worker-routing-design.md`

## Global Constraints

- The control plane derives job requirements from persisted run fields.
- One Redis entry is delivered through one consumer group only.
- Missing worker capabilities fail before provider or specimen execution.
- Hardware and external service availability remain explicit deployment gates.

---

### Task 1: Pure Execution and Routing Contract

**Files:**
- Create: `app/lab/execution_requirements.py`
- Create: `app/workers/routing.py`
- Modify: `app/core/event_bus.py`
- Test: `tests/unit/test_worker_routing.py`

**Interfaces:**
- Produces: `required_worker_capabilities(provider: str, launch_mode: str, analysis_mode: str) -> frozenset[str]`
- Produces: `stream_for_requirements(required: Collection[str]) -> str`
- Produces: `streams_for_worker(capabilities: Collection[str]) -> dict[str, str]`
- Produces: `assert_worker_can_process(message: Mapping[str, Any], capabilities: Collection[str]) -> None`
- Produces: `SANDBOX_CONSUMER_GROUP`, `SANDBOX_STANDARD_WORK_STREAM`, and `SANDBOX_DETONATION_WORK_STREAM`

- [ ] **Step 1: Write failing pure-function tests**

Use literal expected sets and stream names. Cover standard Docker execution,
risky libvirt execution, risky Lima execution, a non-execute risky plan, stream
selection, and rejection that lists the missing capabilities.

- [ ] **Step 2: Run and verify RED**

Run: `env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_worker_routing.py`

Expected: collection fails because the two new modules do not exist.

- [ ] **Step 3: Implement the pure contract**

Define risky modes as `malware_detonation`, `url_analysis`, and
`email_analysis`. Define secure providers as `lima` and `libvirt`. Require
`pcap`, `zeek`, and `secure-mode` for all risky execute work. Add `linux`,
`kvm`, and `libvirt` for libvirt jobs, or add `lima` for Lima jobs. Require
`docker` for other execute work. Keep `SANDBOX_WORK_STREAM` as the
standard-stream alias.

- [ ] **Step 4: Run and verify GREEN**

Run the command from Step 2. Expected: all routing tests pass.

### Task 2: Server-Owned Enqueue and Worker Consumption

**Files:**
- Modify: `app/services/sheshnaag_service.py`
- Modify: `app/workers/sandbox_worker.py`
- Modify: `app/workers/sandbox_agent.py`
- Modify: `tests/unit/test_event_bus_and_worker.py`
- Modify: `tests/unit/test_worker_routing.py`

**Interfaces:**
- Consumes: routing functions from Task 1
- Produces queue payload fields: `required_capabilities` and `routing_version`
- Produces: `process_sandbox_work(..., worker_capabilities=...)`

- [ ] **Step 1: Add failing enqueue and consumer tests**

Prove that a risky stored run publishes to the detonation stream with the full
literal capability list, both worker entry points use the canonical group, an
incompatible worker raises before `SessionLocal` is called, and a compatible
worker reaches the handler.

- [ ] **Step 2: Run focused tests and verify RED**

Run:
`env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_worker_routing.py tests/unit/test_event_bus_and_worker.py`

Expected: new enqueue payload and mismatch assertions fail.

- [ ] **Step 3: Implement stream-aware publishing and consumption**

Derive requirements in `_enqueue_sandbox_work`. Publish to the selected stream.
Parse `SHESHNAAG_WORKER_CAPABILITIES` for the Compose worker, defaulting to
`docker`. Make both loops create the same group on each eligible stream and
pass the declared capabilities into the handler.

- [ ] **Step 4: Make completed-run retries idempotent**

Before changing a run, return its completed evidence summary when its state is
already `completed`. Do not publish a second `run_started` or `run_completed`
event for this replay.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run the command from Step 2. Expected: all pass.

### Task 3: Secure Provider Selection

**Files:**
- Modify: `app/services/malware_lab_service.py`
- Modify: `app/services/sheshnaag_service.py`
- Modify: `tests/unit/test_sheshnaag_service.py`
- Modify: `tests/integration/test_malware_lab_routes.py`

**Interfaces:**
- Consumes: `RISKY_ANALYSIS_MODES` and `SECURE_PROVIDER_NAMES`
- Preserves: `MalwareLabService.resolve_run_contract(...) -> dict[str, Any]`

- [ ] **Step 1: Add failing provider tests**

Prove that the default secure file profile resolves risky analysis to
`libvirt`, an explicit valid Lima secure profile stays Lima, and execute policy
accepts both secure providers but rejects Docker when secure mode is required.

- [ ] **Step 2: Run focused tests and verify RED**

Run:
`env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_sheshnaag_service.py tests/integration/test_malware_lab_routes.py`

Expected: at least the libvirt default assertion fails because the current code
forces Lima.

- [ ] **Step 3: Implement profile-owned secure selection**

Change secure default profile hints to `libvirt`. For risky modes, require the
selected profile hint to be in the secure-provider set and keep that provider.
Allow both secure providers in `_enforce_execution_policy`.

- [ ] **Step 4: Run worker and provider tests**

Run:
`env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_worker_routing.py tests/unit/test_event_bus_and_worker.py tests/unit/test_worker_pool.py tests/unit/test_sheshnaag_service.py tests/integration/test_malware_lab_routes.py tests/v6/test_libvirt_provider.py`

Expected: all pass.

- [ ] **Step 5: Commit**

Commit with: `git commit -m "fix: route queued work by worker capability"`.
