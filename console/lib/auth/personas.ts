/**
 * Demo personas (D29) and their tenant bindings (shipper B1, chair ruling B3):
 * the Platform Admin = owner in all three tenants; the On-call Operator = operator +
 * security_admin in meridian and northstar only; the Compliance Auditor = auditor in all three.
 * The names are roles, not people: the demo has no invented personal names.
 */
import type { RoleName } from "@/lib/api/types";

export type PersonaId = "admin" | "operator" | "auditor";
export type TenantSlug = "meridian" | "northstar" | "sandbox";

export interface Persona {
  id: PersonaId;
  userId: string;
  name: string;
  fullName: string;
  email: string;
  initials: string;
  title: string;
  bindings: Partial<Record<TenantSlug, readonly RoleName[]>>;
}

export const PERSONAS: readonly Persona[] = [
  {
    id: "admin",
    userId: "0192767f-0000-7000-8000-0000000000a1",
    name: "Platform Admin",
    fullName: "Platform Admin",
    email: "admin@meridian.example",
    initials: "PA",
    title: "AI platform engineer",
    bindings: { meridian: ["owner"], northstar: ["owner"], sandbox: ["owner"] },
  },
  {
    id: "operator",
    userId: "0192767f-0000-7000-8000-0000000000a2",
    name: "On-call Operator",
    fullName: "On-call Operator",
    email: "operator@meridian.example",
    initials: "OO",
    title: "Duty officer",
    bindings: { meridian: ["operator", "security_admin"], northstar: ["operator", "security_admin"] },
  },
  {
    id: "auditor",
    userId: "0192767f-0000-7000-8000-0000000000a3",
    name: "Compliance Auditor",
    fullName: "Compliance Auditor",
    email: "auditor@meridian.example",
    initials: "CA",
    title: "Internal auditor",
    bindings: { meridian: ["auditor"], northstar: ["auditor"], sandbox: ["auditor"] },
  },
];

export const TENANTS: readonly { slug: TenantSlug; name: string; blurb: string }[] = [
  { slug: "meridian", name: "Meridian Logistics", blurb: "20 agents · 3 providers" },
  { slug: "northstar", name: "Northstar Health", blurb: "3 agents · isolation proof" },
  { slug: "sandbox", name: "Sandbox", blurb: "Empty · onboarding" },
];

export const DEFAULT_PERSONA: PersonaId = "admin";
export const DEFAULT_TENANT: TenantSlug = "meridian";

export function personaById(id: string | undefined): Persona {
  return PERSONAS.find((p) => p.id === id) ?? (PERSONAS[0] as Persona);
}

export function isTenantSlug(v: string | undefined): v is TenantSlug {
  return v === "meridian" || v === "northstar" || v === "sandbox";
}

export function tenantsFor(persona: Persona): TenantSlug[] {
  return TENANTS.map((t) => t.slug).filter((slug) => persona.bindings[slug] !== undefined);
}

export function rolesFor(persona: Persona, tenant: TenantSlug): readonly RoleName[] {
  return persona.bindings[tenant] ?? [];
}

export const PERSONA_COOKIE = "sibyl_persona";
export const TENANT_COOKIE = "sibyl_tenant";
export const STEP_UP_COOKIE = "sibyl_step_up";
export const TZ_COOKIE = "sibyl_tz";
export const CSRF_COOKIE = "sibyl_csrf";
export const CSRF_HEADER = "x-sibyl-csrf";
