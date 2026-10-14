import type { RoleName, Scope } from "@/lib/api/types";
import type { PersonaId } from "@/lib/auth/personas";

/**
 * Who the BFF is acting for on this request: a seeded demo persona, or (live mode) the user the
 * API resolved from the console session via `/auth/me`. In live mode the API stays the only
 * authority; these roles and scopes only decide what the console shows.
 */
export interface BffPrincipal {
  /** Demo persona, or the persona a live user maps to by email (avatar tint only); null otherwise. */
  personaId: PersonaId | null;
  userId: string;
  name: string;
  fullName: string;
  email: string | null;
  initials: string;
  tenant: string;
  tenantName: string;
  roles: readonly RoleName[];
  scopes: readonly Scope[];
  stepUpUntil: number | null;
}
