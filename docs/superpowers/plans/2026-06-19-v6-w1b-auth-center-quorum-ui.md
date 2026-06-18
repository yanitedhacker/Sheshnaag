# V6 Wave 1b — Authorization Center Quorum UI

**Goal:** Extend the existing Authorization Center so operators can request, review, and co-sign offensive capabilities with correct quorum (dual / dual_plus_admin) surfaced in the UI.

**Architecture:** Frontend reads capability metadata (`review_kind`, `requester_roles`, `requires_engagement_doc`) from `/api/v4/capabilities/registry`. Issue form adapts reviewer count and admin-approval checkbox. Backend routes unchanged from W1a.

**Tech Stack:** React + TypeScript; existing `frontend/src/api.ts` authorization methods.

---

## File Structure

| Action | File | Responsibility |
|---|---|---|
| Modify | `frontend/src/pages/AuthorizationCenterPage.tsx` | Quorum-aware reviewer fields, role gate on request button, engagement ref |
| Modify | `frontend/src/api.ts` | Typed registry + issuance payloads |
| Modify | `app/api/routes/authorization_routes.py` | Accept `reviewer_two`, `is_admin_approved`, `engagement_ref` |
| Reference | `app/api/routes/capability_routes.py` | Registry shape for UI |
| Reference | `frontend/src/App.tsx` | Route `authorization` behind RoleGate |

---

## UI behavior

- `review_kind === "single"` → one reviewer field.
- `review_kind === "dual"` → two reviewer fields, both required.
- `review_kind === "dual_plus_admin"` → two reviewers + admin-approved checkbox (`offensive_research`).
- Request button disabled when caller roles ∉ `requester_roles`.

---

## Acceptance for W1b

- Authorization Center renders dual-reviewer inputs for `exploit_validation` and `red_team_emulation`.
- `offensive_research` shows admin-approval toggle and engagement-doc field.
- Analyst role cannot submit offensive capability requests (UI + API 403/400).
- Manual smoke: issue → approve → artifact appears in list with `state=active`.
