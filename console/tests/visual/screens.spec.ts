/**
 * Visual regression at 320 / 768 / 1024 / 1440 in light and dark. The demo clock is paused at
 * a fixed second with a fixed anchor, so scores, countdowns and relative times are stable.
 * Update baselines with `npm run test:visual:update` after an intended design change.
 */
import { expect, test } from "@playwright/test";
import { agentIdBySlug, as, incidentFor, ready, seek, type Persona, type Tenant } from "../support/demo";

const WIDTHS = [320, 768, 1024, 1440] as const;

interface Shot {
  name: string;
  persona: Persona;
  tenant?: Tenant;
  t: number;
  path: (r: Parameters<typeof agentIdBySlug>[0]) => Promise<string>;
  widths?: readonly number[];
}

const SHOTS: Shot[] = [
  { name: "fleet", persona: "admin", t: 70, path: async () => "/fleet" },
  { name: "agent", persona: "admin", t: 40, path: async (r) => `/agents/${await agentIdBySlug(r, "claims-triage")}` },
  { name: "incident", persona: "operator", t: 215, path: async (r) => `/incidents/${await incidentFor(r, "quote-assistant", (i) => i.state === "waiting_approval")}` },
  { name: "queue", persona: "operator", t: 80, path: async () => "/queue" },
  { name: "audit", persona: "auditor", t: 80, path: async () => "/audit", widths: [1440] },
  { name: "alerts", persona: "operator", t: 70, path: async () => "/alerts", widths: [1440] },
  { name: "onboarding", persona: "admin", tenant: "sandbox", t: 5, path: async () => "/onboarding", widths: [1440] },
  { name: "settings", persona: "admin", t: 5, path: async () => "/settings", widths: [1440] },
  // Wave 4: external monitors (D53).
  { name: "monitors", persona: "admin", t: 130, path: async () => "/monitors", widths: [320, 1440] },
  { name: "monitor-detail", persona: "admin", t: 130, path: async (r) => `/monitors/${await monitorIdByName(r, "PagerDuty bridge")}`, widths: [320, 1440] },
];

async function monitorIdByName(r: Parameters<typeof agentIdBySlug>[0], name: string): Promise<string> {
  const res = await r.get("/api/bff/monitors?limit=100", { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const found = ((await res.json()) as { data: { id: string; name: string }[] }).data.find((m) => m.name === name);
  if (!found) throw new Error(`monitor ${name} not found`);
  return found.id;
}

for (const scheme of ["light", "dark"] as const) {
  test.describe(`visual · ${scheme}`, () => {
    test.use({ colorScheme: scheme });
    for (const s of SHOTS) {
      for (const width of s.widths ?? WIDTHS) {
        test(`${s.name} @${width}`, async ({ page, context, request, baseURL }) => {
          await seek(request, s.t);
          await as(context, baseURL, s.persona, s.tenant);
          await page.setViewportSize({ width, height: 900 });
          await page.goto(await s.path(request));
          if (width > 900) await ready(page);
          else await expect(page.getByTestId("menu-toggle")).toBeVisible();
          await page.waitForTimeout(600);
          // No horizontal page scroll at any width (user web rules).
          const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
          expect(overflow, "horizontal overflow").toBeLessThanOrEqual(1);
          await expect(page).toHaveScreenshot(`${s.name}-${width}-${scheme}.png`, { fullPage: true, mask: [page.getByTestId("demo-chip")] });
        });
      }
    }
  });
}
