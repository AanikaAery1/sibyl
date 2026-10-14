/**
 * Console session. GET → who am I, which tenants, which mode.
 * Demo: POST {persona?, tenant?, step_up?} switches persona/tenant or completes a simulated
 * step-up. Live: identity is the API's; a tenant switch is a fresh tenant-first sign-in, so POST
 * {tenant} answers with the sign-in URL, and step-up runs through /api/bff/auth/step-up.
 */
import type { NextRequest } from "next/server";
import { ProblemError } from "@/lib/api/problem";
import {
  PERSONAS,
  PERSONA_COOKIE,
  STEP_UP_COOKIE,
  TENANTS,
  TENANT_COOKIE,
  isTenantSlug,
  personaById,
  tenantsFor,
} from "@/lib/auth/personas";
import { roleLabel } from "@/lib/auth/roles";
import { tenantSlugOk } from "@/lib/bff/auth-relay";
import { assertCsrf, json, problem, readJson } from "@/lib/bff/http";
import { consoleMode } from "@/lib/bff/mode";
import { LiveAuthError, currentPrincipal } from "@/lib/bff/principal";
import { demoNow, getWorld } from "@/lib/demo/store";
import { appendAudit } from "@/lib/demo/world";

export const dynamic = "force-dynamic";

const STEP_UP_MS = 5 * 60_000;

export async function GET(): Promise<Response> {
  try {
    const p = await currentPrincipal();
    const live = consoleMode() === "live";
    const persona = p.personaId ? personaById(p.personaId) : null;
    return json({
      mode: consoleMode(),
      principal: { ...p, roleLabels: p.roles.map(roleLabel) },
      tenants: live || !persona ? [{ slug: p.tenant, name: p.tenantName }] : TENANTS.filter((t) => tenantsFor(persona).includes(t.slug)),
      personas: live ? [] : PERSONAS.map((x) => ({ id: x.id, name: x.name, fullName: x.fullName, initials: x.initials, title: x.title, tenants: tenantsFor(x) })),
    });
  } catch (err) {
    if (err instanceof LiveAuthError) return problem(new ProblemError(err.code === "unauthenticated" ? 401 : 502, err.code, err.code === "unauthenticated" ? "Sign in required" : "Control plane unreachable"));
    throw err;
  }
}

interface SessionBody {
  persona?: string;
  tenant?: string;
  step_up?: boolean;
}

function livePost(body: SessionBody): Response {
  if (body.persona) throw new ProblemError(409, "live_mode", "Persona switching is demo-only", "In live mode you are the user you signed in as.");
  if (body.step_up) throw new ProblemError(409, "live_mode", "Step-up runs in its own window", "Use the \"Confirm it's you\" dialog; it signs you in again at your identity provider.");
  if (body.tenant) {
    if (!tenantSlugOk(body.tenant)) throw new ProblemError(422, "validation_failed", "Unknown workspace", "Workspace names use lowercase letters, numbers and hyphens.");
    return json({ redirect: `/api/bff/auth/login?${new URLSearchParams({ tenant: body.tenant, return_to: "/" }).toString()}` });
  }
  return json({ ok: true });
}

export async function POST(req: NextRequest): Promise<Response> {
  try {
    assertCsrf(req);
    const body = ((await readJson(req)) ?? {}) as SessionBody;
    if (consoleMode() === "live") return livePost(body);
    const res = json({ ok: true });
    const opts = { path: "/", sameSite: "lax" as const, httpOnly: true, secure: req.nextUrl.protocol === "https:" };
    if (body.persona) {
      const persona = PERSONAS.find((p) => p.id === body.persona);
      if (!persona) throw new ProblemError(422, "validation_failed", "Unknown persona", "Pick the Platform Admin, On-call Operator or Compliance Auditor.");
      res.cookies.set(PERSONA_COOKIE, persona.id, opts);
      res.cookies.delete(STEP_UP_COOKIE);
      const current = req.cookies.get(TENANT_COOKIE)?.value;
      const allowed = tenantsFor(persona);
      if (!isTenantSlug(current) || !allowed.includes(current)) res.cookies.set(TENANT_COOKIE, allowed[0] ?? "meridian", opts);
    }
    if (body.tenant) {
      if (!isTenantSlug(body.tenant)) throw new ProblemError(422, "validation_failed", "Unknown tenant", "Pick meridian, northstar or sandbox.");
      const persona = personaById(body.persona ?? req.cookies.get(PERSONA_COOKIE)?.value);
      if (!tenantsFor(persona).includes(body.tenant)) throw new ProblemError(403, "forbidden", "No membership", `${persona.name} has no membership in ${body.tenant}.`);
      res.cookies.set(TENANT_COOKIE, body.tenant, opts);
    }
    if (body.step_up) {
      const p = await currentPrincipal();
      const until = demoNow() + STEP_UP_MS;
      res.cookies.set(STEP_UP_COOKIE, String(until), { ...opts, maxAge: 300 });
      appendAudit(getWorld(isTenantSlug(p.tenant) ? p.tenant : "sandbox"), { action: "access.step_up", actor_type: "human", actor_id: p.userId, resource_type: "session", resource_ref: p.personaId ?? p.userId, detail: { method: "dex (simulated)", valid_for_s: 300 } }, demoNow());
    }
    return res;
  } catch (err) {
    if (err instanceof ProblemError) return problem(err);
    throw err;
  }
}
