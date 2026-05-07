/**
 * V5 W2c — static permission catalog.
 *
 * Source: docs/runbooks/v5/route_nav_audit.md (24 routes ↔ 24 nav items).
 * Backend authority is `app/migrations/versions/v5a01_roles_permissions.py`
 * — keep these names in sync. Frontend gating is UX (hide buttons,
 * redirect URLs to NotAuthorized); the backend re-checks every
 * request via `require_role` / `require_permission`.
 */

export type V5Role =
  | "read_only"
  | "analyst"
  | "senior_analyst"
  | "reviewer"
  | "lab_lead";

/** Permission slugs as seeded by the v5a01 migration. */
export const PERMISSIONS = [
  "intel.read",
  "review.read",
  "candidates.read",
  "recipes.write",
  "runs.read",
  "authorization.review",
  "attack.read",
  "cases.read",
  "autonomous.run",
  "evidence.read",
  "artifacts.write",
  "provenance.read",
  "ledger.read",
  "disclosure.write",
  "specimens.write",
  "profiles.write",
  "findings.read",
  "indicators.write",
  "prevention.write",
  "defang.review",
  "reports.read",
  "ai_sessions.read",
  "policy.write",
  "admin.roles.assign",
  "analytics.read",
] as const;

export type PermissionSlug = (typeof PERMISSIONS)[number];

/**
 * Route path → required permission slug.
 *
 * The keys must match `<Route path>` in App.tsx. The "/" key is
 * implicit (intel.read) because index renders IntelDashboardPage.
 */
export const ROUTE_PERMISSIONS: Record<string, PermissionSlug> = {
  intel: "intel.read",
  review: "review.read",
  candidates: "candidates.read",
  recipes: "recipes.write",
  runs: "runs.read",
  authorization: "authorization.review",
  "attack-coverage": "attack.read",
  "case-graph": "cases.read",
  autonomous: "autonomous.run",
  evidence: "evidence.read",
  artifacts: "artifacts.write",
  provenance: "provenance.read",
  ledger: "ledger.read",
  disclosures: "disclosure.write",
  specimens: "specimens.write",
  "analysis-cases": "cases.read",
  "sandbox-profiles": "profiles.write",
  findings: "findings.read",
  indicators: "indicators.write",
  "prevention-v3": "prevention.write",
  defang: "defang.review",
  reports: "reports.read",
  "ai-sessions": "ai_sessions.read",
  policy: "policy.write",
  workers: "admin.roles.assign", // worker fleet management is lab_lead-only
  analytics: "analytics.read",
};

/**
 * Role → set of permissions. Mirrors the seeded role_permissions rows
 * in v5a01 so the frontend can answer "does role X grant perm Y?"
 * without a backend round trip.
 */
export const ROLE_PERMISSIONS: Record<V5Role, ReadonlySet<PermissionSlug>> = {
  read_only: new Set([
    "intel.read",
    "runs.read",
    "attack.read",
    "cases.read",
    "evidence.read",
    "provenance.read",
    "findings.read",
    "reports.read",
  ]),
  analyst: new Set([
    "intel.read",
    "runs.read",
    "attack.read",
    "cases.read",
    "evidence.read",
    "provenance.read",
    "findings.read",
    "reports.read",
    "review.read",
    "candidates.read",
    "specimens.write",
    "indicators.write",
    "ai_sessions.read",
  ]),
  senior_analyst: new Set([
    "intel.read",
    "runs.read",
    "attack.read",
    "cases.read",
    "evidence.read",
    "provenance.read",
    "findings.read",
    "reports.read",
    "review.read",
    "candidates.read",
    "specimens.write",
    "indicators.write",
    "ai_sessions.read",
    "recipes.write",
    "artifacts.write",
    "profiles.write",
    "prevention.write",
    "autonomous.run",
    "ledger.read",
    "analytics.read",
  ]),
  reviewer: new Set([
    "intel.read",
    "runs.read",
    "attack.read",
    "cases.read",
    "evidence.read",
    "provenance.read",
    "findings.read",
    "reports.read",
    "review.read",
    "candidates.read",
    "authorization.review",
    "defang.review",
    "disclosure.write",
    "ai_sessions.read",
    "ledger.read",
    "analytics.read",
  ]),
  lab_lead: new Set(PERMISSIONS), // superuser
};

export function roleHasPermission(role: V5Role, permission: PermissionSlug): boolean {
  return ROLE_PERMISSIONS[role]?.has(permission) ?? false;
}

export function rolesHaveAny(roles: readonly string[], permission: PermissionSlug): boolean {
  return roles.some(
    (r) => (ROLE_PERMISSIONS as Record<string, ReadonlySet<PermissionSlug>>)[r]?.has(permission)
  );
}

/**
 * RESERVED_FOR_V7 — capability slugs reserved by the V5-V8 expansion
 * PRD's Output Chain milestone. Mirrors the comment block in
 * `app/services/capability_policy.py`. Adding any of these to a role
 * here without backend support is an error.
 */
export const RESERVED_FOR_V7 = [
  "cve_coordination",
  "vendor_disclosure",
  "public_intel_publish",
  "dataset_publish",
] as const;
