# V6 Kill-Criteria Gate Sign-Off

**Milestone:** V6 — Full-Spectrum + Windows
**Date:** 2026-06-19
**Signer:** Archishman Paul (Lab Lead)

## Gate checklist

| # | Criterion | Result | Evidence |
|---|-----------|--------|----------|
| 1 | Offensive capabilities pass external pentest of policy chokepoint (no scope escapes, audit unforgeable) | **PASS** | `tests/red_team/test_capability_escapes.py` + ArchFit Red Team manual pentest (`data/release_metadata/v6-gate/adversary-harness.log`) |
| 2 | Windows VM detonation E2E (specimen → telemetry → artifacts → signed bundle) | **PASS** | `sheshnaag-wk-01` staging run; `tests/v6/test_libvirt_provider.py` |
| 3 | Atomic Red Team replay ≥80 ATT&CK techniques mapped to detection corpus | **PASS** | `tests/v6/test_purple_team.py`; `data/v6/attack_techniques.json` |
| 4 | Exploit validator produces valid attestation (CVE + vulnerable/patched pair) | **PASS** | `tests/v6/test_exploit_validator.py`; `POST /api/v6/exploit-validation/runs` manifest |
| 5 | Multi-reviewer authorization — zero single-reviewer escape paths | **PASS** | W0a harness + Authorization Center quorum UI manual walkthrough |

## Phase 0 decisions

All four kickoff blockers signed in [kickoff.md](./kickoff.md):

- Windows BYOL + Packer golden images
- ART MIT attribution
- KVM worker host assignment
- External pentest vendor (ArchFit Red Team)

## Beta dogfooding

- **Team:** Internal ArchFit lab (3 analysts)
- **Window:** 2026-06-05 — 2026-06-19 (continued from V5)
- **Outcome:** No P0 blockers; Windows detonation latency acceptable on `sheshnaag-wk-01`

## Authorization

V7 Phase 0 and output-chain feature work may proceed. V7 feature merges to `main` require this sign-off (satisfied).

```
Lab Lead: Archishman Paul
Date: 2026-06-19
```
