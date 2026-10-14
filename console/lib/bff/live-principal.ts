/**
 * `/auth/me` → BffPrincipal (pure; unit-tested). Scopes come from the API (live, per request);
 * roles are the distinct `role_name`s of the caller's memberships in the session's tenant.
 */
import type { components } from "@/lib/api/schema.gen";
import type { RoleName, Scope } from "@/lib/api/types";
import { PERSONAS, type PersonaId } from "@/lib/auth/personas";
import { ROLE_SCOPES } from "@/lib/auth/roles";
import type { BffPrincipal } from "./principal-types";

export type MeBody = Omit<components["schemas"]["Principal"], "tenant" | "scopes"> & {
  tenant: { id: string; slug: string; name: string };
  scopes: readonly string[];
};

/** The dex static-password domain of the demo personas (deploy/compose/dex/personas.yaml). */
const DEMO_PERSONA_DOMAIN = "demo.sibyl.example";
const KNOWN_SCOPES: ReadonlySet<string> = new Set(Object.values(ROLE_SCOPES).flat());
const ROLE_ORDER: readonly RoleName[] = ["owner", "admin", "security_admin", "engineer", "operator", "auditor", "viewer"];

function initialsOf(fullName: string): string {
  const words = fullName.split(/[\s@]+/).filter(Boolean);
  if (fullName.includes("@")) return (words[0]?.[0] ?? "?").toUpperCase();
  return words
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}

/** Demo personas sign in through dex as <persona>@…; map them back for the avatar tint and short name. */
function personaFor(email: string | null): PersonaId | null {
  const [local, domain] = email?.toLowerCase().split("@") ?? [];
  // Persona ids are role words ("admin"), so only the demo dex domain counts: admin@acme.com is a person.
  if (domain !== DEMO_PERSONA_DOMAIN) return null;
  return PERSONAS.find((p) => p.id === local)?.id ?? null;
}

export function principalFromMe(me: MeBody): BffPrincipal {
  const email = me.user.email ?? null;
  const fullName = me.user.display_name?.trim() || email || "Signed-in user";
  const personaId = personaFor(email);
  // Demo personas are roles ("Platform Admin"), so their short name is the whole role name.
  const name = personaId
    ? (PERSONAS.find((p) => p.id === personaId)?.name ?? fullName)
    : me.user.display_name?.trim()
      ? (fullName.split(/\s+/)[0] ?? fullName)
      : (email?.split("@")[0] ?? fullName);
  const held = new Set(me.memberships.map((m) => m.role_name));
  const until = me.step_up_valid_until ? Date.parse(me.step_up_valid_until) : NaN;
  return {
    personaId,
    userId: me.user.id,
    name,
    fullName,
    email,
    initials: initialsOf(fullName),
    tenant: me.tenant.slug,
    tenantName: me.tenant.name,
    roles: ROLE_ORDER.filter((r) => held.has(r)),
    scopes: me.scopes.filter((s): s is Scope => KNOWN_SCOPES.has(s)),
    stepUpUntil: Number.isFinite(until) ? until : null,
  };
}
