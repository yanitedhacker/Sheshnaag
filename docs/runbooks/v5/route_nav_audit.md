# V5 Route × Nav × Page Audit

**Status:** Draft for W2c (Frontend role-gate) lead.
**Date:** 2026-05-07
**Source files:** `frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`, `frontend/src/pages/*.tsx`
**Purpose:** Resolve Phase 0 decision blocker #6 — "Frontend route audit: 32 pages or 24 nav items?". Role-gating must cover **routes** (in `App.tsx`) and **nav items** (in `Layout.tsx`). This document enumerates both surfaces and the suggested default permission mapping for the 5 V5 roles.

---

## Counts

| Surface | Count |
|---|---:|
| `.tsx` files in `frontend/src/pages/` | 32 |
| `<Route>` entries in `App.tsx` (excluding index + `*` wildcard) | 24 |
| Nav items in `Layout.tsx` `operatorNavItems` | 24 |
| **Orphan pages** (file exists, no route, no nav) | **8** |
| Pages that are routed AND nav-linked | 24 |
| Pages that are routed but NOT nav-linked | 0 |

**Finding:** the route surface and nav surface are currently 1:1 — every routed page is also in the nav, and vice versa. So role-gating only needs to wrap the 24 routes + 24 nav items consistently. The 8 orphan pages are independent technical debt (see §"Orphan pages" below) and do not need V5 gating because they are unreachable from the running app.

---

## Routed pages × default V5 role mapping

The default `permission` slug below is a recommendation for the W2c `permissions.ts` static map. Final role assignments are the W2c lead's call; lab_lead can grant any role. `read_only` blocks all non-GET actions inside the page; routes themselves remain accessible.

| Path | Page component | Nav label | Suggested permission slug | Default-allowed roles |
|---|---|---|---|---|
| `/` (index) | `IntelDashboardPage` | (brand link → `/intel`) | `intel.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/intel` | `IntelDashboardPage` | Intel | `intel.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/review` | `ReviewQueuePage` | Review | `review.read` | analyst, senior_analyst, reviewer, lab_lead |
| `/candidates` | `CandidateQueuePage` | Candidates | `candidates.read` | analyst, senior_analyst, reviewer, lab_lead |
| `/recipes` | `RecipeBuilderPage` | Recipes | `recipes.write` | senior_analyst, lab_lead (read_only sees view; analyst sees view but cannot save) |
| `/runs` | `RunConsolePage` | Runs | `runs.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/authorization` | `AuthorizationCenterPage` | Auth | `authorization.review` | reviewer, lab_lead (analyst sees own requests only — handled inside the page) |
| `/attack-coverage` | `AttackCoveragePage` | ATT&CK | `attack.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/case-graph` | `CaseGraphPage` | Graph | `cases.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/autonomous` | `AutonomousAgentPage` | Agent | `autonomous.run` | senior_analyst, lab_lead (gated already by `autonomous_agent_run` capability — UI gate is belt-and-suspenders) |
| `/evidence` | `EvidenceExplorerPage` | Evidence | `evidence.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/artifacts` | `ArtifactForgePage` | Artifacts | `artifacts.write` | senior_analyst, lab_lead |
| `/provenance` | `ProvenanceCenterPage` | Provenance | `provenance.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/ledger` | `AnalystLedgerPage` | Ledger | `ledger.read` | senior_analyst, reviewer, lab_lead |
| `/disclosures` | `DisclosureBundlesPage` | Bundles | `disclosure.write` | reviewer, lab_lead (gated already by `external_disclosure` capability) |
| `/specimens` | `SpecimenIntakePage` | Specimens | `specimens.write` | analyst, senior_analyst, lab_lead |
| `/analysis-cases` | `AnalysisCasesPage` | Cases | `cases.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/sandbox-profiles` | `SandboxProfilesPage` | Profiles | `profiles.write` | senior_analyst, lab_lead |
| `/findings` | `BehaviorFindingsPage` | Findings | `findings.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/indicators` | `IndicatorForgeV3Page` | Indicators | `indicators.write` | analyst, senior_analyst, lab_lead |
| `/prevention-v3` | `PreventionForgeV3Page` | Prevention | `prevention.write` | senior_analyst, lab_lead |
| `/defang` | `DefangQueuePage` | Defang | `defang.review` | reviewer, lab_lead (gated already by `destructive_defang` capability) |
| `/reports` | `MalwareReportsPage` | Reports | `reports.read` | analyst, senior_analyst, reviewer, lab_lead, read_only |
| `/ai-sessions` | `AISessionsPage` | AI Drafts | `ai_sessions.read` | analyst, senior_analyst, reviewer, lab_lead |
| `/policy` | `PolicyCenterPage` | Policy | `policy.write` | lab_lead |
| `*` (catch-all → `IntelDashboardPage`) | `IntelDashboardPage` | (none) | inherits `intel.read` | (same as `/intel`) |

**24 routes + 1 catch-all + 1 index → 24 unique gated surfaces.**

---

## Orphan pages (file exists, NOT routed, NOT in nav)

These 8 pages have `.tsx` files but are not reachable in the current build. They appear to be V3-era surfaces that were superseded or partially deprecated.

| Page file | Likely status |
|---|---|
| `AssetExplorerPage.tsx` | V3 asset-explorer — superseded by `CaseGraphPage` for asset pivots. Verify before deletion. |
| `AttackGraphPage.tsx` | V3 ATT&CK graph — superseded by `AttackCoveragePage`. Verify before deletion. |
| `CveDetailPage.tsx` | V3 CVE detail — may be intended for deep-linking (`/cve/:id`?). Confirm intent. |
| `OperationsPage.tsx` | V3/V4 ops dashboard — `/ops/health` API exists but no UI route. Confirm whether to wire or delete. |
| `PatchDetailPage.tsx` | V3 patch detail — may be intended for deep-linking. Confirm intent. |
| `SimulatorPage.tsx` | Likely V3 detonation simulator — superseded by real `RunConsolePage`. Verify before deletion. |
| `TrustCenterPage.tsx` | V3 trust center — superseded by `AuthorizationCenterPage` + `ProvenanceCenterPage`. Verify before deletion. |
| `WorkbenchPage.tsx` | V3 analyst workbench — likely superseded by per-page surfaces. Verify before deletion. |

**Recommended action for W2c:** out of scope for V5 role-gating. Open a hygiene ticket post-V5 to either route + gate these or delete them. **Do not** wire them just to gate them — adds surface for no user benefit.

---

## Implementation hand-off for W2c

1. **`frontend/src/permissions.ts`** — paste the 24 permission slugs from the table above. Add a `RESERVED_FOR_V7` constant block at the bottom listing `cve_coordination`, `vendor_disclosure`, `public_intel_publish`, `dataset_publish` so V7 kickoff knows where they plug in (per locked decision §5 in the execution plan).

2. **`frontend/src/components/RoleGate.tsx`** — single component reading `useCurrentRole()`; renders children when the current role has the requested permission, otherwise renders null (for nav items) or a 403 fallback (for routes).

3. **`frontend/src/components/Layout.tsx:6-31`** — wrap each `operatorNavItems` entry with `<RoleGate permission="...">`.

4. **`frontend/src/App.tsx:31-58`** — wrap each `<Route>` element with `<RoleGate permission="..." fallback={<NotAuthorizedPage />}>`. The catch-all `*` route stays unwrapped (it falls through to `IntelDashboardPage`, which is itself gated; this gives the 404→intel behavior we want).

5. **`frontend/src/hooks/useCurrentRole.ts`** — reads `roles: string[]` from the JWT (post-W1a, the JWT decoded client-side carries roles); returns the highest-privilege role + a `hasPermission(perm: string) -> boolean` helper.

---

## Acceptance check at W2c gate

- Manual: log in as `analyst`, attempt to navigate to `/policy`. Expect: nav item hidden; direct URL navigation shows `NotAuthorizedPage`.
- Automated: Playwright spec `frontend/e2e/role_gating.spec.ts` covering ≥3 role × restricted-route pairs (the V5 kill-criteria item 4 covers backend; this covers frontend).
- Manual: log in as `lab_lead`, confirm all 24 nav items visible.
- Manual: log in as `read_only`, confirm read-pages are visible but write actions inside (e.g., "Save recipe", "Approve disclosure") are disabled or hidden.
