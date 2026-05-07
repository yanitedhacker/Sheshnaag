# V5 Wave 2 — Team Workflow Surface

**Three sub-tracks. Each ships standalone and lands in its own commit.**

## W2a — Lifecycle-aware review queues

**Approach:** add a *new* case-centric queue endpoint instead of expanding the existing 1500-line `SheshnaagService.list_review_queue` method (which is run/evidence/artifact-centric and would get unmaintainable). Frontend gets a new "Cases" section on `ReviewQueuePage` with per-state tabs.

**Files:**
- Create `app/api/routes/case_queue_routes.py` — `GET /api/v5/cases/queue?lifecycle_state=...`
- Modify `frontend/src/pages/ReviewQueuePage.tsx` — add Cases section with state tabs
- Modify `frontend/src/types.ts`, `frontend/src/api.ts`

**Out of scope for V5:** the `assignee_role` filter. AnalysisCase has `analyst_name` (string), not a role-typed assignee field — looking up the user's current role per-row would need a join through `tenant_memberships`. Deferred to V6 or whenever the assignee field changes shape.

## W2b — Slack / Linear / JIRA inbound integrations

**Approach:** new migration v5a06 for `case_integration_links`. Three thin inbound adapter modules + one shared webhook receiver route. Each adapter exports `verify_signature(headers, body) -> bool` (per Phase 0 §5 default). Webhook route 401s before JSON parsing.

**Files:**
- Create `app/migrations/versions/v5a06_integration_links.py`
- Create `app/models/integrations.py` — `CaseIntegrationLink` model
- Create `app/services/integrations/__init__.py`, `slack_inbound.py`, `linear_inbound.py`, `jira_inbound.py`
- Create `app/api/routes/integrations_webhook.py` — `POST /api/v5/integrations/webhook/{provider}`
- Modify `app/api/routes/__init__.py`, `app/main.py`

**Each adapter handles:**
1. `status_sync` — IdP-side status changes mirror to lifecycle state (via `CaseWorkflowService.transition`)
2. `mention_action` — `@sheshnaag triage CASE-123` style commands
3. `review_approval` — interactive button click → transition

The actual outbound integrations (sending messages back to Slack/etc.) are V4 work and stay untouched.

## W2c — Frontend role-gate

**Approach:** small. New `RoleGate` component, `useCurrentRole` hook, static `permissions.ts` map. Wrap nav items in `Layout.tsx` and routes in `App.tsx`. JWT-decode happens client-side via lightweight base64 (no signature check — the server already validates on every request; client gate is UX, not security).

**Files:**
- Create `frontend/src/components/RoleGate.tsx`
- Create `frontend/src/hooks/useCurrentRole.ts`
- Create `frontend/src/permissions.ts` (24 permission slugs from `route_nav_audit.md` + `RESERVED_FOR_V7` block)
- Create `frontend/src/pages/NotAuthorizedPage.tsx`
- Modify `frontend/src/components/Layout.tsx` — wrap nav items
- Modify `frontend/src/App.tsx` — wrap routes

## Acceptance for Wave 2

- W2a: `GET /api/v5/cases/queue?lifecycle_state=review` returns only cases in `review`. ReviewQueuePage Cases tab renders.
- W2b: webhook with invalid signature returns 401 *without* parsing JSON. With valid signature, mention `@sheshnaag transition CASE-1 to=review` triggers a `CaseStateTransition` row.
- W2c: log in as `analyst` → `/policy` route is hidden in nav AND redirects to `NotAuthorizedPage` on direct URL navigation.
