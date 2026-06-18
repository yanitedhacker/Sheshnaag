# V6 Wave 4 — Purple Team

**Goal:** Activate `red_team_emulation` — Atomic Red Team replay with optional Caldera chaining and detection-coverage gap report (≥80 techniques).

**Architecture:** `PurpleTeamService` orchestrates `AtomicRunner` + optional `CalderaAdapter`. Technique catalog in `data/v6/attack_techniques.json`. Frontend page at `/purple-team`. Permission `purple.replay` seeded in migration `v6a02`.

**Tech Stack:** FastAPI service layer; simulated ART replay in CI; live ART operator-supplied.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Create | `app/services/purple_team_service.py` | Replay orchestration + coverage gap report |
| Create | `app/lab/redteam/atomic_runner.py` | ART technique replay (simulated when absent) |
| Create | `app/lab/redteam/caldera_adapter.py` | Lab-internal Caldera operation surface |
| Create | `data/v6/attack_techniques.json` | ≥85 technique catalog for gate |
| Create | `frontend/src/pages/PurpleTeamPage.tsx` | Operator replay + gap visualization |
| Create | `app/migrations/versions/v6a02_v6_permissions.py` | `purple.replay` permission |
| Modify | `app/api/routes/v6_routes.py` | POST `/api/v6/purple-team/replay` |
| Create | `tests/v6/test_purple_team.py` | `meets_gate_80` assertion |

---

## Coverage gap report

Compares executed technique IDs against lab detection corpus (Sigma + YARA stores via `PurpleTeamService.coverage_gap_report()`).

---

## Acceptance for W4

- `pytest tests/v6/test_purple_team.py -q` — `techniques_executed >= 80`, `meets_gate_80 is True`.
- Replay requires dual-signed `red_team_emulation` authorization.
- MIT attribution for Atomic Red Team documented per kickoff decision #2.
- Purple Team page renders gap summary from API response.
