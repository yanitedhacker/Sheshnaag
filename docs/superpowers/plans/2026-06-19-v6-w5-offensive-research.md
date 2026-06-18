# V6 Wave 5 — Offensive Research Workbench

**Goal:** Activate `offensive_research` capability — operator-driven fuzzing, debugger sessions, and AI-assisted crash triage inside signed scope.

**Architecture:** Research backends in `app/lab/research/`; API routes on `/api/v6/research/*`. Strictest review kind (`dual_plus_admin`) + engagement doc. Permission `research.write` in migration `v6a02`.

**Tech Stack:** Python harness orchestrators; React workbench page; capability policy gate.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Create | `app/lab/research/fuzzing.py` | AFL / libfuzzer harness launcher + corpus |
| Create | `app/lab/research/debugger.py` | gdb (Linux) + WinDbg (Windows) attach surface |
| Create | `app/lab/research/crash_triage.py` | Exploitable / needs_review / not_exploitable verdict |
| Create | `frontend/src/pages/ResearchWorkbenchPage.tsx` | Fuzz + triage operator UI |
| Modify | `app/api/routes/v6_routes.py` | POST `/api/v6/research/fuzz`, triage endpoints |
| Modify | `app/migrations/versions/v6a02_v6_permissions.py` | `research.write` for senior_analyst + lab_lead |
| Create | `tests/v6/test_offensive_research.py` | Fuzz → crash → triage pipeline |

---

## Scope enforcement

All research calls require active `offensive_research` authorization naming target binary/image in scope artifact. `CapabilityPolicy.evaluate()` rejects out-of-scope targets.

---

## Acceptance for W5

- `pytest tests/v6/test_offensive_research.py -q` passes.
- Fuzzing harness returns deduplicated crash records with input digests.
- Crash triage returns verdict + confidence for SIGSEGV inputs.
- Research Workbench page reachable only with `research.write` permission.
- No analyst or single-reviewer path to `offensive_research` (W0a + W1a).
