import type { ReactNode } from "react";
import type { PermissionSlug } from "../permissions";
import { useCurrentRole } from "../hooks/useCurrentRole";

/**
 * V5 W2c — wrap nav items, action buttons, or full routes.
 *
 * - For nav items: omit `fallback` to render nothing when denied.
 * - For routes: pass a fallback (e.g., <NotAuthorizedPage />) so
 *   direct-URL navigation surfaces a 403-equivalent screen.
 *
 * If the caller is unauthenticated AND ``allowUnauthenticated`` is
 * false (the default), this gate also denies. In V5 dev with
 * ``settings.auth_enabled=False`` the backend lets the anonymous
 * caller through; the frontend gate, however, has no way to know
 * the backend is in dev mode, so it falls back to denying. To unblock
 * local dev set the JWT in localStorage manually (see hooks/useCurrentRole).
 */
export interface RoleGateProps {
  permission: PermissionSlug;
  children: ReactNode;
  fallback?: ReactNode;
  allowUnauthenticated?: boolean;
}

export function RoleGate({
  permission,
  children,
  fallback,
  allowUnauthenticated = false,
}: RoleGateProps) {
  const { hasPermission, isAuthenticated } = useCurrentRole();

  if (!isAuthenticated && !allowUnauthenticated) {
    return fallback ? <>{fallback}</> : null;
  }
  if (!hasPermission(permission)) {
    return fallback ? <>{fallback}</> : null;
  }
  return <>{children}</>;
}
