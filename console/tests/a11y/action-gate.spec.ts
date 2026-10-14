/**
 * axe-core on the Action Gate screens in light and dark, including the inline 409 states and
 * the simulate result. Same bar as screens.spec.ts: no serious or critical violation.
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { as, ready, seek, type Persona } from "../support/demo";

const T = 120;
const COOKIE = { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" };

async function heldId(r: APIRequestContext, tool: string): Promise<string> {
  const body = (await (await r.get("/api/bff/held-actions?limit=100", { headers: COOKIE })).json()) as { data: { held_action_id: string; tool: string }[] };
  return body.data.find((h) => h.tool === tool)?.held_action_id ?? "missing";
}

async function policyId(r: APIRequestContext, name: string): Promise<string> {
  const body = (await (await r.get("/api/bff/action-policies?limit=200", { headers: COOKIE })).json()) as { data: { id: string; name: string; state: string }[] };
  return body.data.find((p) => p.name === name && p.state === "approved")?.id ?? "missing";
}

interface Screen {
  name: string;
  persona: Persona;
  path: (r: APIRequestContext) => Promise<string>;
  open?: (page: Page) => Promise<void>;
}

const SCREENS: Screen[] = [
  { name: "held actions", persona: "operator", path: async () => "/held-actions" },
  { name: "held actions decided", persona: "operator", path: async () => "/held-actions?view=all" },
  { name: "held action detail", persona: "operator", path: async (r) => `/held-actions/${await heldId(r, "refunds.issue")}` },
  {
    name: "held action self-approval refused",
    persona: "admin",
    path: async (r) => `/held-actions/${await heldId(r, "payments.transfer")}`,
    open: async (p) => {
      await p.getByLabel("Decision reason").fill("My own payout; approving it anyway.");
      await p.getByTestId("held-approve").click();
      await p.getByTestId("step-up-confirm").click();
      await p.getByTestId("held-error").waitFor();
    },
  },
  { name: "action policies", persona: "admin", path: async () => "/action-policies" },
  { name: "action policy", persona: "admin", path: async (r) => `/action-policies/${await policyId(r, "Claims payouts")}` },
  {
    name: "action policy simulate",
    persona: "admin",
    path: async (r) => `/action-policies/${await policyId(r, "Claims payouts")}?tab=simulate`,
    open: async (p) => {
      await p.getByRole("button", { name: "transfer-limit" }).click();
      await p.getByTestId("sim-result").waitFor();
    },
  },
  {
    name: "action policy editor",
    persona: "admin",
    path: async (r) => `/action-policies/new?from=${await policyId(r, "Claims payouts")}`,
    open: async (p) => {
      await p.getByTestId("editor-simulate").click();
      await p.getByRole("button", { name: "transfer-limit" }).click();
      await p.getByTestId("sim-result").waitFor();
    },
  },
  { name: "audit actions", persona: "auditor", path: async () => "/audit?action=action" },
];

for (const scheme of ["light", "dark"] as const) {
  test.describe(`axe · Action Gate · ${scheme}`, () => {
    test.use({ colorScheme: scheme });
    for (const s of SCREENS) {
      test(`${s.name} has no serious or critical violations`, async ({ page, context, request, baseURL }) => {
        await seek(request, T);
        await as(context, baseURL, s.persona);
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
