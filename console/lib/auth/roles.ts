/**
 * Role → scope matrix (API.md §2.2, plus `keys:read` from the G0 reconciliation item 5).
 * Action Gate scopes (ACTION-GATE.md §3) are hand-mapped until the API seeds them: everyone who
 * reads operations reads held actions; operators, security admins and Admins decide them; Admins
 * and security admins write action policies (four-eyes for tier-1 scopes is enforced per request).
 * Wave 3 (migrations 0018/0019): drift:read for every role, drift:write for Admin, Workspace admin and
 * Security admin; sentinel:read for those three plus Operator and Auditor; sentinel:admin for the three.
 * Wave 4 (migration 0025): monitors:admin (register, pause, revoke external monitors) for the same three.
 * The control plane is the authority; the console uses this only to decide what to show.
 * In demo mode the BFF also enforces it so a forbidden click returns a real 403 problem.
 */
import type { RoleName, Scope } from "@/lib/api/types";

const ALL_READ: Scope[] = ["tenant:read", "agents:read", "routing:read"];

export const ROLE_SCOPES: Readonly<Record<RoleName, readonly Scope[]>> = {
  owner: [
    ...ALL_READ,
    "tenant:write",
    "users:manage",
    "oidc:manage",
    "apikeys:manage",
    "apikeys:manage_agent",
    "agents:write",
    "agents:approve",
    "identity:write",
    "capture:write",
    "credentials:manage",
    "credentials:read",
    "keys:read",
    "keys:rotate",
    "routing:write",
    "incidents:act",
    "routing:override",
    "approvals:decide",
    "quarantine:act",
    "killswitch:pull",
    "killswitch:release",
    "queue:act",
    "packets:read",
    "payloads:read",
    "payloads:reveal",
    "alerts:act",
    "audit:read",
    "audit:verify",
    "audit:export",
    "data:export",
    "erasure:request",
    "erasure:approve",
    "holds:manage",
    "actions:read",
    "actions:decide",
    "action_policies:write",
    "drift:read",
    "drift:write",
    "sentinel:read",
    "sentinel:admin",
    "monitors:admin",
  ],
  admin: [
    ...ALL_READ,
    "users:manage",
    "oidc:manage",
    "apikeys:manage",
    "apikeys:manage_agent",
    "agents:write",
    "agents:approve",
    "identity:write",
    "capture:write",
    "credentials:manage",
    "credentials:read",
    "routing:write",
    "audit:read",
    "audit:verify",
    "erasure:request",
    "actions:read",
    "drift:read",
    "drift:write",
    "sentinel:read",
    "sentinel:admin",
    "monitors:admin",
  ],
  security_admin: [
    ...ALL_READ,
    "agents:approve",
    "identity:write",
    "capture:write",
    "credentials:manage",
    "credentials:read",
    "keys:read",
    "keys:rotate",
    "routing:write",
    "incidents:act",
    "routing:override",
    "approvals:decide",
    "quarantine:act",
    "killswitch:pull",
    "killswitch:release",
    "packets:read",
    "payloads:read",
    "payloads:reveal",
    "alerts:act",
    "audit:read",
    "audit:verify",
    "audit:export",
    "data:export",
    "erasure:request",
    "erasure:approve",
    "holds:manage",
    "actions:read",
    "actions:decide",
    "action_policies:write",
    "drift:read",
    "drift:write",
    "sentinel:read",
    "sentinel:admin",
    "monitors:admin",
  ],
  engineer: [
    ...ALL_READ,
    "apikeys:manage_agent",
    "agents:write",
    "identity:write",
    "credentials:read",
    "routing:write",
    "incidents:act",
    "routing:override",
    "packets:read",
    "payloads:read",
    "alerts:act",
    "audit:read",
    "actions:read",
    "drift:read",
  ],
  operator: [...ALL_READ, "incidents:act", "queue:act", "packets:read", "alerts:act", "actions:read", "actions:decide", "drift:read", "sentinel:read"],
  auditor: [
    ...ALL_READ,
    "credentials:read",
    "packets:read",
    "payloads:read",
    "payloads:reveal",
    "audit:read",
    "audit:verify",
    "audit:export",
    "data:export",
    "actions:read",
    "drift:read",
    "sentinel:read",
  ],
  viewer: [...ALL_READ, "drift:read"],
};

/** Scopes that need a fresh step-up (↑ in API §2.2) for the roles that hold them. */
export const STEP_UP_SCOPES: ReadonlySet<Scope> = new Set<Scope>([
  "tenant:write",
  "oidc:manage",
  "credentials:manage",
  "keys:rotate",
  "killswitch:pull",
  "killswitch:release",
  "erasure:approve",
  "holds:manage",
]);

export function scopesForRoles(roles: readonly RoleName[]): Scope[] {
  const out = new Set<Scope>();
  for (const role of roles) for (const s of ROLE_SCOPES[role]) out.add(s);
  return [...out].sort();
}

export function hasScope(scopes: readonly Scope[] | undefined, scope: Scope): boolean {
  return scopes?.includes(scope) ?? false;
}

/**
 * Display labels (chair ruling B17): the `owner` role reads as "Admin" everywhere in the UI and
 * the `admin` role as "Workspace admin", so the two never collide. RBAC keys are unchanged; this
 * map is the only place a role is turned into words.
 */
export const ROLE_LABEL: Readonly<Record<RoleName, string>> = {
  owner: "Admin",
  admin: "Workspace admin",
  security_admin: "Security admin",
  engineer: "Engineer",
  operator: "Operator",
  auditor: "Auditor",
  viewer: "Viewer",
};

/** Label for a role key from the API; unknown keys (a newer server) show as the key itself. */
export function roleLabel(role: string): string {
  return (ROLE_LABEL as Record<string, string>)[role] ?? role;
}
