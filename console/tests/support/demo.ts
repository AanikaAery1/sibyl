/** Test helpers: drive the demo scenario clock and pick a persona/tenant by cookie. */
import { expect, type APIRequestContext, type BrowserContext, type Page } from "@playwright/test";

export type Persona = "admin" | "operator" | "auditor";
export type Tenant = "meridian" | "northstar" | "sandbox";

const CSRF = "e2e-csrf-token";

function origin(baseURL: string | undefined): string {
  return baseURL ?? "http://localhost:3210";
}

/** Rebuild the demo world and jump to `t` seconds into the scenario, paused. */
export async function seek(request: APIRequestContext, t: number, pause = true): Promise<void> {
  const res = await request.post("/api/bff/demo", {
    headers: { "x-sibyl-csrf": CSRF, cookie: `sibyl_csrf=${CSRF}`, "content-type": "application/json" },
    data: { action: "seek", t, pause },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
}

export async function resetDemo(request: APIRequestContext): Promise<void> {
  const res = await request.post("/api/bff/demo", {
    headers: { "x-sibyl-csrf": CSRF, cookie: `sibyl_csrf=${CSRF}`, "content-type": "application/json" },
    data: { action: "reset" },
  });
  expect(res.ok()).toBeTruthy();
}

export async function as(context: BrowserContext, baseURL: string | undefined, persona: Persona, tenant: Tenant = "meridian"): Promise<void> {
  const url = origin(baseURL);
  await context.clearCookies();
  await context.addCookies([
    { name: "sibyl_persona", value: persona, url },
    { name: "sibyl_tenant", value: tenant, url },
    { name: "sibyl_tz", value: "Asia%2FKolkata", url },
  ]);
}

export async function agentIdBySlug(request: APIRequestContext, slug: string, persona: Persona = "admin", tenant: Tenant = "meridian"): Promise<string> {
  const res = await request.get(`/api/bff/agents?q=${slug}`, { headers: { cookie: `sibyl_persona=${persona}; sibyl_tenant=${tenant}` } });
  const body = (await res.json()) as { data: { id: string; slug: string }[] };
  const found = body.data.find((a) => a.slug === slug);
  if (!found) throw new Error(`agent ${slug} not found`);
  return found.id;
}

/** The newest top-level run of an agent, from `GET /runs` (D50). */
export async function latestRunId(request: APIRequestContext, slug: string): Promise<string> {
  const id = await agentIdBySlug(request, slug);
  const res = await request.get(`/api/bff/runs?agent_id=${id}&root_only=true&limit=1`, { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const body = (await res.json()) as { data: { run_id: string }[] };
  const run = body.data[0];
  if (!run) throw new Error(`no run for ${slug}`);
  return run.run_id;
}

export async function incidentFor(request: APIRequestContext, slug: string, predicate: (i: { state: string; kind: string }) => boolean = () => true): Promise<string> {
  const id = await agentIdBySlug(request, slug);
  const res = await request.get(`/api/bff/incidents?agent_id=${id}`, { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const body = (await res.json()) as { data: { id: string; state: string; kind: string }[] };
  const found = body.data.find(predicate);
  if (!found) throw new Error(`no incident for ${slug}`);
  return found.id;
}

/** Wait until the shell is hydrated and the event stream is connected (SSE never idles). */
export async function ready(page: Page): Promise<void> {
  await expect(page.getByTestId("open-palette")).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Live" }).first()).toBeVisible();
}
