# Real Detonation Proof Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Linux/KVM real-detonation harness use the current authenticated API and fail on every missing proof condition.

**Architecture:** The Bash harness performs immutable preflight checks, uploads real bytes, uses current request schemas, polls a bounded run, validates stored evidence and SSE replay, then writes a checksum manifest. Pytest drives it with controlled command binaries and HTTP responses.

**Tech Stack:** Bash, curl, jq, virsh, Zeek, Pytest.

**Spec:** `docs/superpowers/specs/2026-08-30-real-detonation-proof-harness-design.md`

## Global Constraints

- Never print or persist the Bearer token.
- Never use `demo-public` or another read-only tenant.
- No warning-only proof checks are permitted.
- A real run can pass only on a Linux KVM host with live telemetry.

---

### Task 1: Fail-Closed Preflight

**Files:**
- Modify: `tests/e2e/test_real_detonation.sh`
- Create: `tests/unit/test_real_detonation_harness.py`

**Interfaces:**
- Consumes required environment: `SHESHNAAG_ACCESS_TOKEN`, `SHESHNAAG_TENANT`, `SHESHNAAG_RECIPE_ID`
- Consumes optional environment: `SHESHNAAG_API`, `SHESHNAAG_TIMEOUT`, `SHESHNAAG_E2E_OUTPUT_DIR`, `SHESHNAAG_KVM_DEVICE`, `SHESHNAAG_LIBVIRT_URI`

- [ ] **Step 1: Write failing subprocess tests**

Run the script with an isolated `PATH` containing controlled `uname`, `curl`,
`jq`, `virsh`, and `zeek` commands. Assert exit code 2 for a missing token,
`demo-public`, and an unreadable KVM device. Assert that output never contains
the token literal.

- [ ] **Step 2: Run and verify RED**

Run: `env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_real_detonation_harness.py`

Expected: the old script reaches API polling or accepts the demo tenant instead
of returning the required preflight errors.

- [ ] **Step 3: Implement the preflight**

Validate required environment before API mutation. Require Linux, the KVM
device, tools, and successful `virsh list --all`. Fetch ops health with the
Bearer header and use jq to require `lab_deps.kvm`, `lab_deps.virsh`, and
`lab_deps.zeek` equal `ok`, plus egress and PCAP flags equal `on`.

- [ ] **Step 4: Run and verify GREEN for preflight tests**

Run the command from Step 2. Expected: the three preflight tests pass.

### Task 2: Current API Flow and Evidence Contract

**Files:**
- Modify: `tests/e2e/test_real_detonation.sh`
- Modify: `tests/unit/test_real_detonation_harness.py`

**Interfaces:**
- Uploads: multipart `POST /api/specimens/upload`
- Creates: current `POST /api/analysis-cases` body with `title` and `analyst_name`
- Launches: current `POST /api/runs` body with `recipe_id`, `analyst_name`, `launch_mode`, `analysis_mode`, and `specimen_ids`

- [ ] **Step 1: Add failing complete-flow tests**

Make fake curl return current-schema success bodies. Prove a missing SSE
completion event exits non-zero. Prove the complete response set exits zero and
writes `manifest.sha256` when `SHESHNAAG_E2E_OUTPUT_DIR` is set.

- [ ] **Step 2: Run and verify RED**

Run the focused harness test. Expected: the old warning-only SSE path returns
zero or does not write the checksum manifest.

- [ ] **Step 3: Implement current requests and strict assertions**

Use `curl --form file=@...` for upload. Store every response in the evidence
directory. Validate numeric ids and SHA-256. Poll terminal state with a hard
deadline. Require provider, preflight status, worker completion, live evidence,
timeline events, evidence count, and SSE completion by jq queries or exact
event matching.

- [ ] **Step 4: Write the commit-bound checksum manifest**

Write `git-commit.txt`, then use `shasum -a 256` or `sha256sum` over the sorted
evidence filenames. Do not include environment data or request headers.

- [ ] **Step 5: Run focused and shell syntax checks**

Run:
`bash -n tests/e2e/test_real_detonation.sh`

Run:
`env PYTHONPATH=. /private/tmp/sheshnaag-p0-venv/bin/python -m pytest -q tests/unit/test_real_detonation_harness.py`

Expected: syntax check and all harness tests pass.

- [ ] **Step 6: Commit**

Commit with: `git commit -m "fix: make real detonation proof fail closed"`.
