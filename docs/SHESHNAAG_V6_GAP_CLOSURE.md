# Sheshnaag V6 Gap Closure

**Audience:** senior engineers closing the V6 "Full-Spectrum + Windows" milestone.
**Status:** All kill-criteria **PASS** — V7 may proceed.
**Last refreshed:** 2026-06-19
**Companion docs:** [expansion PRD](superpowers/specs/2026-05-07-sheshnaag-expansion-design.md), [V6 kickoff](runbooks/v6/kickoff.md), [V6 smoke](runbooks/v6/smoke.md), [V6 gate sign-off](runbooks/v6/gate-signoff.md), [v5-to-v6 migration](migration/v5-to-v6.md).

---

## 0. How to read this document

Live gap ledger for V6. Items marked **Done** are in the working tree with passing tests. Kill-criteria rows must remain **PASS** before V7 Phase 0 opens.

Ground rule: do not weaken W0a adversary harness to green failing policy checks.

---

## 1. Kill-criteria gate

| # | Criterion | Status | Evidence |
|---|---|:---:|---|
| 1 | All three offensive capabilities pass external pentest of policy chokepoint | **PASS** | `tests/red_team/test_capability_escapes.py`; ArchFit Red Team manual notes in `data/release_metadata/v6-gate/adversary-harness.log` |
| 2 | Windows VM detonation E2E with parity-of-evidence to Linux Docker | **PASS** | `tests/v6/test_libvirt_provider.py`; staging manifest `data/release_metadata/v6-gate/windows-detonation-manifest.json` |
| 3 | Atomic Red Team replay ≥80 ATT&CK techniques vs detection corpus | **PASS** | `tests/v6/test_purple_team.py` — `meets_gate_80: true`; `data/v6/attack_techniques.json` |
| 4 | Exploit validator attestation for real CVE + vulnerable/patched pair | **PASS** | `tests/v6/test_exploit_validator.py`; API manifest in `data/release_metadata/v6-gate/exploit-validation-manifest.json` |
| 5 | Multi-reviewer authorization — zero single-reviewer escape paths | **PASS** | W0a harness + `frontend/src/pages/AuthorizationCenterPage.tsx` quorum UI; manual walkthrough archived |

---

## 2. Wave completion

| Wave | Deliverable | Status | Key paths |
|---|---|:---:|---|
| W0a | Adversary harness | **Done** | `tests/red_team/test_capability_escapes.py` |
| W1a | Auth issue enforcement | **Done** | `app/services/capability_policy.py`, `tests/v6/test_auth_issue_enforcement.py` |
| W1b | Authorization Center quorum UI | **Done** | `frontend/src/pages/AuthorizationCenterPage.tsx` |
| W2a | Libvirt Windows provider | **Done** | `app/lab/providers/libvirt_provider.py`, `app/lab/collectors/sysmon.py`, `app/lab/collectors/etw.py` |
| W2b | Packer BYOL pipeline | **Done** | `infra/packer/windows/README.md` |
| W3 | Exploit validation | **Done** | `app/services/exploit_validator.py`, `app/migrations/versions/v6a01_exploit_validation.py` |
| W4 | Purple team | **Done** | `app/services/purple_team_service.py`, `app/lab/redteam/atomic_runner.py` |
| W5 | Offensive research | **Done** | `app/lab/research/fuzzing.py`, `frontend/src/pages/ResearchWorkbenchPage.tsx` |
| W6 | Gate closure | **Done** | This doc + `docs/runbooks/v6/gate-signoff.md` |

---

## 3. Open items

None. All V6 scope items closed.

---

## 4. Hygiene (post-V6, non-blocking)

- Add live Caldera integration test behind `RUN_CALDERA=1` flag.
- Ship `infra/packer/windows/windows-server.pkr.hcl` hardened provisioning scripts for Server 2022.
- Volatility 3 / MemProcFS memory analysis collectors — deferred V7+.

---

## 5. Sign-off linkage

V6 gate signed 2026-06-19 by Lab Lead. See [gate-signoff.md](runbooks/v6/gate-signoff.md).
