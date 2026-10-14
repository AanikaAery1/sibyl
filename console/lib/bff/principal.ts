/**
 * Resolves the acting principal.
 *
 * Demo mode: the persona and tenant cookies choose a seeded persona; step-up is a short-lived
 * cookie set by the simulated re-auth.
 *
 * Live mode: the API is the only authority. The console session cookie (`__Host-sibyl_session`,
 * set by the API's OIDC callback on the shared origin) is forwarded as a bearer, and `/auth/me`
 * says who the user is, in which tenant, with which scopes and whether step-up is fresh. The
 * persona cookies are ignored.
 */
import "server-only";
import { cache } from "react";
import { cookies } from "next/headers";
import { scopesForRoles } from "@/lib/auth/roles";
import {
  DEFAULT_TENANT,
  PERSONA_COOKIE,
  STEP_UP_COOKIE,
  TENANTS,
  TENANT_COOKIE,
  isTenantSlug,
  personaById,
  rolesFor,
  tenantsFor,
  type TenantSlug,
} from "@/lib/auth/personas";
import { sessionTokenOk } from "./live";
import { principalFromMe, type MeBody } from "./live-principal";
import { apiBaseUrl, consoleMode } from "./mode";
import type { BffPrincipal } from "./principal-types";

export const SESSION_COOKIE = "__Host-sibyl_session";
const ME_TIMEOUT_MS = 5_000;

/** Why a live principal could not be resolved: no/expired session, or the API is down. */
export class LiveAuthError extends Error {
  constructor(readonly code: "unauthenticated" | "upstream_unavailable") {
    super(code);
  }
}

async function demoPrincipal(): Promise<BffPrincipal> {
  const jar = await cookies();
  const persona = personaById(jar.get(PERSONA_COOKIE)?.value);
  const requested = jar.get(TENANT_COOKIE)?.value;
  const allowed = tenantsFor(persona);
  const tenant: TenantSlug = isTenantSlug(requested) && allowed.includes(requested) ? requested : (allowed[0] ?? DEFAULT_TENANT);
  const roles = rolesFor(persona, tenant);
  const stepUpRaw = Number(jar.get(STEP_UP_COOKIE)?.value ?? "");
  return {
    personaId: persona.id,
    userId: persona.userId,
    name: persona.name,
    fullName: persona.fullName,
    email: persona.email,
    initials: persona.initials,
    tenant,
    tenantName: TENANTS.find((t) => t.slug === tenant)?.name ?? tenant,
    roles,
    scopes: scopesForRoles(roles),
    stepUpUntil: Number.isFinite(stepUpRaw) && stepUpRaw > 0 ? stepUpRaw : null,
  };
}

/** The session cookie value, only when it looks like one the API minted. */
export async function liveSessionToken(): Promise<string | null> {
  const value = (await cookies()).get(SESSION_COOKIE)?.value ?? null;
  return sessionTokenOk(value) ? value : null;
}

/** `/auth/me` for the current session, once per server render. Throws LiveAuthError. */
const livePrincipal = cache(async (): Promise<BffPrincipal> => {
  const token = await liveSessionToken();
  if (!token) throw new LiveAuthError("unauthenticated");
  let res: Response;
  try {
    res = await fetch(`${apiBaseUrl()}/api/v1/auth/me`, {
      headers: { accept: "application/json", authorization: `Bearer sibyl_sess_${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(ME_TIMEOUT_MS),
    });
  } catch {
    throw new LiveAuthError("upstream_unavailable");
  }
  if (res.status === 401 || res.status === 403) throw new LiveAuthError("unauthenticated");
  if (!res.ok) throw new LiveAuthError("upstream_unavailable");
  return principalFromMe((await res.json()) as MeBody);
});

export async function currentPrincipal(): Promise<BffPrincipal> {
  return consoleMode() === "live" ? livePrincipal() : demoPrincipal();
}

/** For layouts: the principal, or why there is none (so the page can send the user to sign in). */
export async function principalOrReason(): Promise<{ principal: BffPrincipal } | { reason: LiveAuthError["code"] }> {
  try {
    return { principal: await currentPrincipal() };
  } catch (err) {
    if (err instanceof LiveAuthError) return { reason: err.code };
    throw err;
  }
}

/** The demo world a principal's tenant maps to (live tenants outside the demo set see the empty sandbox). */
export function demoTenantOf(tenant: string): TenantSlug {
  return isTenantSlug(tenant) ? tenant : "sandbox";
}
