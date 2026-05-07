import { useEffect, useState } from "react";
import type { V5Role, PermissionSlug } from "../permissions";
import { rolesHaveAny } from "../permissions";

/**
 * V5 W2c — read the caller's V5 roles from the Sheshnaag JWT.
 *
 * The token is stored in localStorage under `sheshnaag.jwt` after a
 * successful OIDC callback (frontend OIDC flow lands in W4+; for V5
 * the token is set externally by the developer or a separate login
 * page). We base64-decode the payload client-side — no signature
 * check, because the server validates on every request and the
 * frontend gate is UX, not security.
 *
 * If no token is present, returns no roles. If the token is
 * malformed or expired, the same — components render their fallback.
 */

const JWT_STORAGE_KEY = "sheshnaag.jwt";


function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padding = "=".repeat((4 - (padded.length % 4)) % 4);
    const decoded = atob(padded + padding);
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}


function rolesFromPayload(payload: Record<string, unknown> | null): V5Role[] {
  if (!payload) return [];

  // Top-level "roles" claim wins (post-OIDC; service-to-service tokens).
  const explicit = payload.roles;
  if (Array.isArray(explicit)) {
    return explicit.filter((r): r is V5Role =>
      typeof r === "string" &&
      ["read_only", "analyst", "senior_analyst", "reviewer", "lab_lead"].includes(r)
    );
  }

  // Fall back to `memberships[*].role` (V4-era token shape).
  const memberships = payload.memberships;
  if (Array.isArray(memberships)) {
    const out: V5Role[] = [];
    const seen = new Set<string>();
    for (const m of memberships) {
      if (m && typeof m === "object" && typeof (m as { role?: unknown }).role === "string") {
        const role = (m as { role: string }).role;
        if (
          ["read_only", "analyst", "senior_analyst", "reviewer", "lab_lead"].includes(role) &&
          !seen.has(role)
        ) {
          out.push(role as V5Role);
          seen.add(role);
        }
      }
    }
    return out;
  }

  return [];
}


function isExpired(payload: Record<string, unknown> | null): boolean {
  if (!payload) return true;
  const exp = payload.exp;
  if (typeof exp !== "number") return false;
  return Date.now() / 1000 > exp;
}


export interface CurrentRoleInfo {
  roles: V5Role[];
  hasPermission: (perm: PermissionSlug) => boolean;
  isAuthenticated: boolean;
}


export function useCurrentRole(): CurrentRoleInfo {
  const [roles, setRoles] = useState<V5Role[]>([]);
  const [authenticated, setAuthenticated] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const token = window.localStorage.getItem(JWT_STORAGE_KEY);
    if (!token) {
      setRoles([]);
      setAuthenticated(false);
      return;
    }
    const payload = decodeJwtPayload(token);
    if (isExpired(payload)) {
      setRoles([]);
      setAuthenticated(false);
      return;
    }
    setRoles(rolesFromPayload(payload));
    setAuthenticated(true);

    // Listen for cross-tab changes.
    const handler = () => {
      const t = window.localStorage.getItem(JWT_STORAGE_KEY);
      if (!t) {
        setRoles([]);
        setAuthenticated(false);
        return;
      }
      const p = decodeJwtPayload(t);
      if (isExpired(p)) {
        setRoles([]);
        setAuthenticated(false);
        return;
      }
      setRoles(rolesFromPayload(p));
      setAuthenticated(true);
    };
    window.addEventListener("storage", handler);
    return () => window.removeEventListener("storage", handler);
  }, []);

  return {
    roles,
    hasPermission: (perm: PermissionSlug) => rolesHaveAny(roles, perm),
    isAuthenticated: authenticated,
  };
}
