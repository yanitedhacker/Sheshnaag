# V6 Kickoff — Phase 0 Decision Record (Signed)

**Status:** Signed — all blockers resolved.
**Companion docs:** [expansion PRD](../../superpowers/specs/2026-05-07-sheshnaag-expansion-design.md), [V5 gate sign-off](../v5/gate-signoff.md), [smoke runbook](./smoke.md), [v5-to-v6 migration](../../migration/v5-to-v6.md).

---

## Decision blockers

### 1. Windows BYOL + Packer golden images

**Decision:** Operators supply their own Windows ISO (BYOL). Packer templates live under `infra/packer/windows/`; no redistributable images ship in the repo. Golden volume name `sheshnaag-windows-golden`; Sysmon + optional Velociraptor pre-installed per README.
**Decided on:** 2026-06-19
**Owner:** ops — AP
**Notes:** Workers advertise `windows-vm` in capability flags when KVM + libvirt are present (`app/workers/sandbox_agent.py`). Detonation uses `app/lab/providers/libvirt_provider.py`.

### 2. Atomic Red Team MIT attribution

**Decision:** ART test content is referenced, not vendored. `app/lab/redteam/atomic_runner.py` replays technique IDs from `data/v6/attack_techniques.json`; live ART install is optional and operator-supplied. UI and docs carry MIT license attribution for Atomic Red Team.
**Decided on:** 2026-06-19
**Owner:** legal / product — AP
**Notes:** Simulated replay satisfies CI; production purple-team runs require operator-installed ART under signed `red_team_emulation` authorization.

### 3. KVM-capable worker hosts

**Decision:** Reuse V5 three-node LAN (`sheshnaag-cp-01`, `sheshnaag-wk-01`, `sheshnaag-wk-02`). Both workers remain KVM-capable; `sheshnaag-wk-01` is primary Windows detonation host, `sheshnaag-wk-02` failover.
**Decided on:** 2026-06-19
**Owner:** ops — AP
**Notes:** `SHESHNAAG_LIBVIRT_URI=qemu:///system` on workers; control plane stays non-KVM.

### 4. External pentest vendor for policy chokepoint

**Decision:** ArchFit Red Team (internal) performs V6 kill-criteria adversary harness + manual scope-escape attempts; findings filed as GitHub issues before gate sign-off.
**Decided on:** 2026-06-19
**Owner:** security review — AP
**Notes:** Automated baseline in `tests/red_team/test_capability_escapes.py`; manual pentest covers Authorization Center quorum UI and worker egress boundaries.

---

## Logistics

| Role | Hostname | LAN IP | KVM | Status |
|------|----------|--------|-----|--------|
| Control plane | sheshnaag-cp-01 | 10.77.0.10 | n/a | provisioned |
| Worker 1 (Windows primary) | sheshnaag-wk-01 | 10.77.0.11 | yes | provisioned |
| Worker 2 (Windows failover) | sheshnaag-wk-02 | 10.77.0.12 | yes | provisioned |

**Dogfood window:** 2026-06-05 — 2026-06-19 (continues from V5 internal ArchFit lab team).

---

## Sign-off

```
Lab Lead sign-off: Archishman Paul
Date: 2026-06-19
V6 kill-criteria gate: PASS (see docs/runbooks/v6/gate-signoff.md)
```
