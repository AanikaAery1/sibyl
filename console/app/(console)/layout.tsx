import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import type { FleetHealth } from "@/lib/api/types";
import { PERSONAS, TENANTS, TZ_COOKIE, personaById, tenantsFor } from "@/lib/auth/personas";
import { roleLabel } from "@/lib/auth/roles";
import { safeReturnTo } from "@/lib/bff/auth-relay";
import { consoleMode, keyEnv, wallClock } from "@/lib/bff/mode";
import { principalOrReason } from "@/lib/bff/principal";
import type { BffPrincipal } from "@/lib/bff/principal-types";
import { serverGet } from "@/lib/bff/server";
import { demoNow, scenarioStatus } from "@/lib/demo/store";
import { DEFAULT_TZ } from "@/lib/format";
import { ClientRoot } from "@/components/shell/ClientRoot";
import type { SessionInfo } from "@/components/shell/Session";

export const dynamic = "force-dynamic";

function consoleNow(mode: "demo" | "live"): number {
  return mode === "demo" ? demoNow() : wallClock();
}

function sessionInfo(p: BffPrincipal, mode: "demo" | "live"): SessionInfo {
  const persona = p.personaId ? personaById(p.personaId) : null;
  const live = mode === "live";
  return {
    mode,
    keyEnv: keyEnv(),
    personaId: p.personaId,
    userId: p.userId,
    name: p.name,
    fullName: p.fullName,
    email: p.email,
    initials: p.initials,
    title: live ? (p.email ?? "Signed in") : (persona?.title ?? ""),
    tenant: p.tenant,
    tenantName: p.tenantName,
    roles: p.roles,
    roleLabels: p.roles.map(roleLabel),
    scopes: p.scopes,
    tenants: live || !persona ? [{ slug: p.tenant, name: p.tenantName, blurb: "Signed in" }] : TENANTS.filter((t) => tenantsFor(persona).includes(t.slug)),
    personas: live ? [] : PERSONAS.map((x) => ({ id: x.id, name: x.name, fullName: x.fullName, initials: x.initials, title: x.title, tenants: tenantsFor(x) })),
  };
}

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const mode = consoleMode();
  const who = await principalOrReason();
  if ("reason" in who) {
    const path = safeReturnTo((await headers()).get("x-sibyl-path"));
    redirect(`/login?${new URLSearchParams({ error: who.reason, return_to: path }).toString()}`);
  }
  const jar = await cookies();
  const tzRaw = jar.get(TZ_COOKIE)?.value;
  const tz = tzRaw && /^[A-Za-z_]+(\/[A-Za-z0-9_+-]+)*$/.test(decodeURIComponent(tzRaw)) ? decodeURIComponent(tzRaw) : DEFAULT_TZ;
  const fleet = await serverGet<FleetHealth>("/fleet/health");
  const status = mode === "demo" ? scenarioStatus() : null;

  return (
    <ClientRoot session={sessionInfo(who.principal, mode)} fleet={fleet.data} tz={tz} serverNow={consoleNow(mode)} paused={status?.paused ?? false}>
      {children}
    </ClientRoot>
  );
}
