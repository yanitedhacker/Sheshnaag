# V6 Wave 6 — Gate Closure

**Goal:** Close the V6 milestone by running kill-criteria smoke, capturing evidence artifacts, and obtaining Lab Lead sign-off before V7 work begins.

**Architecture:** Consolidates W0a–W5 deliverables against the five kill-criteria from the expansion PRD. Documentation bundle: smoke runbook, gap-closure ledger, gate sign-off, migration guide.

**Tech Stack:** pytest suites under `tests/v6/` and `tests/red_team/`; manual staging smoke on 3-node deployment.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Create | `docs/runbooks/v6/smoke.md` | End-to-end V6 smoke steps |
| Create | `docs/runbooks/v6/gate-signoff.md` | Kill-criteria checklist + signer |
| Create | `docs/SHESHNAAG_V6_GAP_CLOSURE.md` | Gap ledger — all criteria PASS |
| Create | `docs/migration/v5-to-v6.md` | Operator upgrade guide |
| Create | `docs/runbooks/v6/kickoff.md` | Signed Phase 0 decision record |
| Reference | `tests/red_team/test_capability_escapes.py` | Policy chokepoint pentest |
| Reference | `tests/v6/test_*.py` | Per-wave automated gate proofs |

---

## Kill-criteria mapping

| # | Criterion | Primary evidence |
|---|---|---|
| 1 | Offensive capabilities pass external pentest | `tests/red_team/test_capability_escapes.py` + manual pentest notes |
| 2 | Windows VM detonation E2E | Staging run on `sheshnaag-wk-01` + libvirt tests |
| 3 | ART replay ≥80 techniques | `tests/v6/test_purple_team.py` |
| 4 | Exploit validator attestation | `tests/v6/test_exploit_validator.py` + API manifest |
| 5 | Multi-reviewer auth — zero single-reviewer escapes | W0a + W1b + manual Authorization Center walkthrough |

---

## Acceptance for W6

- All five kill-criteria marked **PASS** in `docs/runbooks/v6/gate-signoff.md`.
- `docs/SHESHNAAG_V6_GAP_CLOSURE.md` shows no open blockers.
- Smoke runbook executed on staging; artifacts under `data/release_metadata/v6-gate/`.
- Lab Lead sign-off dated; V7 Phase 0 may proceed.
