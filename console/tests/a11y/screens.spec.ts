/**
 * axe-core on every screen in light and dark, plus the open overlays. Fails on any
 * serious or critical violation (WCAG 2.2 A/AA rule sets); minor/moderate are reported.
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { agentIdBySlug, as, incidentFor, latestRunId, ready, seek, type Persona, type Tenant } from "../support/demo";

interface Screen {
  name: string;
  persona: Persona;
  tenant?: Tenant;
  t: number;
  path: (r: Parameters<typeof agentIdBySlug>[0]) => Promise<string>;
  open?: (page: Page) => Promise<void>;
}

const SCREENS: Screen[] = [
  { name: "fleet", persona: "admin", t: 70, path: async () => "/fleet" },
  { name: "fleet list", persona: "admin", t: 70, path: async () => "/fleet?view=list" },
  { name: "agent", persona: "admin", t: 40, path: async (r) => `/agents/${await agentIdBySlug(r, "claims-triage")}` },
  { name: "incidents", persona: "operator", t: 215, path: async () => "/incidents" },
  { name: "incident approval", persona: "operator", t: 215, path: async (r) => `/incidents/${await incidentFor(r, "quote-assistant", (i) => i.state === "waiting_approval")}` },
  { name: "queue", persona: "operator", t: 80, path: async () => "/queue" },
  { name: "alerts", persona: "operator", t: 70, path: async () => "/alerts" },
  { name: "alerts unverdicted", persona: "operator", t: 70, path: async () => "/alerts?view=unverdicted" },
  { name: "audit", persona: "auditor", t: 80, path: async () => "/audit" },
  { name: "audit sheet", persona: "auditor", t: 80, path: async () => "/audit?action=route.changed", open: async (p) => {
    await p.getByTestId("audit-row").first().click();
    await p.getByTestId("decision-record").waitFor();
  } },
  { name: "onboarding", persona: "admin", tenant: "sandbox", t: 5, path: async () => "/onboarding" },
  { name: "settings keys", persona: "admin", t: 5, path: async () => "/settings" },
  { name: "settings tenant keys", persona: "admin", t: 5, path: async () => "/settings?tab=tenant-keys" },
  { name: "settings members", persona: "admin", t: 5, path: async () => "/settings?tab=members" },
  { name: "kill dialog", persona: "operator", t: 70, path: async () => "/fleet", open: async (p) => {
    await p.getByTestId("kill-switch").click();
    await p.getByTestId("kill-dialog").waitFor();
  } },
  { name: "palette", persona: "admin", t: 70, path: async () => "/fleet", open: async (p) => {
    await p.getByTestId("open-palette").click();
    await p.getByTestId("palette").waitFor();
  } },
  // Wave 3: drift, Sentinel, run tree, discovery, plug-and-play onboarding.
  { name: "drift fleet", persona: "operator", t: 130, path: async () => "/drift" },
  { name: "agent drift", persona: "admin", t: 130, path: async (r) => `/agents/${await agentIdBySlug(r, "route-optimizer")}` },
  { name: "drift reset dialog", persona: "admin", t: 130, path: async (r) => `/agents/${await agentIdBySlug(r, "route-optimizer")}`, open: async (p) => {
    await p.getByTestId("drift-reset-open").click();
    await p.getByTestId("drift-reset").waitFor();
  } },
  { name: "sentinel findings", persona: "operator", t: 130, path: async () => "/sentinel" },
  { name: "sentinel settings", persona: "admin", t: 130, path: async () => "/settings/sentinel" },
  { name: "discovered agents", persona: "admin", t: 130, path: async () => "/discovered" },
  { name: "run tree", persona: "admin", t: 130, path: async (r) => `/runs/${await latestRunId(r, "claims-triage")}` },
  { name: "runs list", persona: "operator", t: 130, path: async () => "/runs" },
  // Wave 4: external monitors (D53) and their findings next to Sentinel's.
  { name: "monitors", persona: "admin", t: 130, path: async () => "/monitors" },
  { name: "monitors read-only", persona: "auditor", t: 130, path: async () => "/monitors" },
  { name: "monitor detail", persona: "admin", t: 130, path: async (r) => `/monitors/${await monitorIdByName(r, "PagerDuty bridge")}` },
  { name: "monitor register dialog", persona: "admin", t: 130, path: async () => "/monitors", open: async (p) => {
    await p.getByTestId("monitor-register-open").click();
    await p.getByTestId("monitor-register").waitFor();
    await p.getByTestId("monitor-register-submit").click();
  } },
  { name: "monitor key shown once", persona: "admin", t: 130, path: async () => "/monitors", open: async (p) => {
    await p.getByTestId("monitor-register-open").click();
    await p.getByLabel("Name").fill("A11y probe monitor");
    await p.getByLabel("Reason").fill("Accessibility check of the key reveal.");
    await p.getByTestId("monitor-register-submit").click();
    await p.getByTestId("monitor-created").waitFor();
  } },
  { name: "webhook dialog", persona: "admin", t: 130, path: async (r) => `/monitors/${await monitorIdByName(r, "PagerDuty bridge")}`, open: async (p) => {
    await p.getByTestId("webhook-add-open").click();
    await p.getByTestId("webhook-add").waitFor();
  } },
  { name: "revoke dialog", persona: "admin", t: 130, path: async (r) => `/monitors/${await monitorIdByName(r, "Claude ops reviewer")}`, open: async (p) => {
    await p.getByTestId("monitor-revoke-open").click();
    await p.getByTestId("monitor-revoke").waitFor();
  } },
  { name: "findings from monitors", persona: "operator", t: 130, path: async () => "/sentinel?source=external" },
  { name: "external finding", persona: "admin", t: 130, path: async (r) => `/sentinel/${await externalFindingId(r)}` },
];

async function monitorIdByName(r: Parameters<typeof agentIdBySlug>[0], name: string): Promise<string> {
  const res = await r.get("/api/bff/monitors?limit=100", { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const found = ((await res.json()) as { data: { id: string; name: string }[] }).data.find((m) => m.name === name);
  if (!found) throw new Error(`monitor ${name} not found`);
  return found.id;
}

async function externalFindingId(r: Parameters<typeof agentIdBySlug>[0]): Promise<string> {
  const res = await r.get("/api/bff/findings?source=external&kind=held_action_review&limit=5", { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const found = ((await res.json()) as { data: { id: string }[] }).data[0];
  if (!found) throw new Error("no external finding");
  return found.id;
}

for (const scheme of ["light", "dark"] as const) {
  test.describe(`axe · ${scheme}`, () => {
    test.use({ colorScheme: scheme });
    for (const s of SCREENS) {
      test(`${s.name} has no serious or critical violations`, async ({ page, context, request, baseURL }) => {
        await seek(request, s.t);
        await as(context, baseURL, s.persona, s.tenant);
        await page.goto(await s.path(request));
        await ready(page);
        if (s.open) await s.open(page);
        await page.waitForTimeout(450);
        const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
        const blocking = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
        const summary = blocking.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
        expect(summary, summary.join("\n")).toEqual([]);
      });
    }
  });
}

test("keyboard: skip link, focus ring and Esc-to-close on the palette", async ({ page, context, request, baseURL }) => {
  await seek(request, 10);
  await as(context, baseURL, "admin");
  await page.goto("/fleet");
  await ready(page);
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
  await page.keyboard.press("ControlOrMeta+k");
  await expect(page.getByTestId("palette")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("palette")).not.toBeVisible();
  await expect(page.getByTestId("open-palette")).toBeVisible();
});
