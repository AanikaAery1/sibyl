/**
 * The console against the real control plane (live mode). Requires a running, seeded stack:
 * SIBYL_E2E_LIVE_URL (the shared Caddy origin) and SIBYL_E2E_PASSWORD (dex persona password).
 * Each test signs in fresh, so they are independent.
 */
import { expect, test } from "@playwright/test";
import { bffGet, requireLive, signIn, type Page_ } from "./support";

requireLive();

interface AgentRow {
  id: string;
  slug: string;
  name: string;
  health: { band: string | null; score: number | null };
}
interface Factor {
  rule: string;
  penalty?: number;
}
interface AlertRow {
  id: string;
  state: string;
  verdict: string | null;
  agent_id: string | null;
}

test.describe("sign-in", () => {
  test("an unauthenticated visit lands on the glass sign-in, tenant first", async ({ page }) => {
    await page.goto("/fleet");
    await expect(page).toHaveURL(/\/login\?/);
    await expect(page.getByTestId("signin-tenant")).toBeVisible();
  });

  test("an unknown workspace comes back as a sentence, not JSON", async ({ page }) => {
    await page.goto("/login");
    await page.getByTestId("signin-tenant").fill("no-such-workspace");
    await page.getByTestId("signin-continue").click();
    await expect(page.getByTestId("signin-message")).toContainText(/workspace/i);
  });

  test("The Platform Admin signs in through dex and is an Admin in meridian, on live data", async ({ page }) => {
    await signIn(page, "admin");
    await expect(page.getByTestId("persona-menu")).toContainText("Admin");
    await expect(page.getByText(/^Live API/)).toBeVisible();
    await expect(page.getByTestId("demo-chip")).toHaveCount(0);
    const session = await bffGet<{ mode: string; principal: { tenant: string; roles: string[] } }>(page, "/session");
    expect(session).toMatchObject({ mode: "live", principal: { tenant: "meridian" } });
    expect(session.principal.roles).toContain("owner");
  });

  test("signing out revokes the session", async ({ page }) => {
    await signIn(page, "admin");
    await page.getByTestId("persona-menu").click();
    await page.getByTestId("sign-out").click();
    await expect(page).toHaveURL(/\/login\?error=signed_out/);
    expect((await page.request.get("/api/bff/fleet/health")).status()).toBe(401);
  });
});

test.describe("fleet", () => {
  test("every agent the API lists has a tile", async ({ page }) => {
    await signIn(page, "admin");
    const agents = await bffGet<Page_<AgentRow>>(page, "/agents?limit=200");
    expect(agents.data.length).toBeGreaterThan(0);
    await expect(page.locator('[data-testid^="tile-"]')).toHaveCount(agents.data.length);
    const first = agents.data[0];
    if (first) await expect(page.getByTestId(`tile-${first.slug}`)).toContainText(first.name);
  });
});

test.describe("agent detail", () => {
  test("a scored agent shows the worker's real factors, and the arithmetic checks", async ({ page }) => {
    await signIn(page, "admin");
    const agents = await bffGet<Page_<AgentRow>>(page, "/agents?limit=200");
    const scored = agents.data.find((a) => a.health.band !== null);
    test.skip(!scored, "No agent has a health snapshot yet; run the simulator so the worker scores one.");
    if (!scored) return;
    const doc = await bffGet<{ score: number; factors: Factor[] }>(page, `/agents/${scored.id}/health`);
    const rules = doc.factors.filter((f) => !f.rule.startsWith("_") && (f.penalty ?? 0) > 0);

    await page.goto(`/agents/${scored.id}`);
    await expect(page.getByTestId("agent-name")).toHaveText(scored.name);
    await expect(page.locator('[data-testid^="factor-"]')).toHaveCount(rules.length);
    for (const f of rules) await expect(page.getByTestId(`factor-${f.rule}`).locator(".f-pen")).toHaveText(`−${f.penalty}`);
    await expect(page.getByText("arithmetic checks")).toBeVisible();
    await expect(page.getByTestId("factor-_hysteresis")).toHaveCount(0);
  });
});

test.describe("alerts", () => {
  test("closing needs a verdict; with one, it is recorded at the API", async ({ page }) => {
    await signIn(page, "admin");
    const alerts = await bffGet<Page_<AlertRow>>(page, "/alerts?limit=200&include_suppressed=true");
    const target = alerts.data.find((a) => a.state !== "resolved") ?? alerts.data.find((a) => a.state === "resolved" && a.verdict === null);
    test.skip(!target, "The seed has no open or unverdicted alert to close.");
    if (!target) return;

    await page.goto(target.state === "resolved" ? "/alerts?view=unverdicted" : "/alerts");
    const row = page.locator(`[data-alert-id="${target.id}"]`);
    const group = page.getByTestId("alert-group").filter({ has: row });
    if ((await group.count()) > 0 && !(await row.isVisible())) await group.locator("summary").click();
    await row.getByTestId("close-alert").click();
    await page.getByTestId("verdict-submit").click();
    await expect(page.getByTestId("verdict-error")).toBeVisible();

    await page.getByTestId("verdict-tp").click();
    await page.getByTestId("verdict-submit").click();
    await expect(page.getByTestId("verdict-dialog")).toBeHidden();
    const after = await bffGet<{ state: string; verdict: string | null }>(page, `/alerts/${target.id}`);
    expect(after).toMatchObject({ state: "resolved", verdict: "tp" });
  });
});

test.describe("audit", () => {
  test("The Compliance Auditor verifies the real hash chain", async ({ page }) => {
    await signIn(page, "auditor", "meridian", "/audit");
    await expect(page.locator('[data-testid="audit-row"]').first()).toBeVisible();
    await page.getByTestId("verify-chain").click();
    await expect(page.getByTestId("verify-result").or(page.getByTestId("verify-job"))).toBeVisible();
    const result = page.getByTestId("verify-result");
    if (await result.isVisible()) await expect(result).toContainText("Chain intact");
  });
});

test.describe("settings · API keys", () => {
  test("The Platform Admin mints a key (secret shown once), then revokes it", async ({ page }) => {
    await signIn(page, "admin", "meridian", "/settings");
    const name = `e2e-live-${Date.now().toString(36)}`;
    await page.getByTestId("new-key").click();
    await page.getByLabel("Name").fill(name);
    await page.getByRole("radio", { name: /Registry automation/ }).check();
    await page.getByTestId("create-key").click();
    await expect(page.getByTestId("key-secret")).toHaveText(/^sbl_(live|test)_/);
    await page.getByTestId("key-done").click();

    const row = page.getByTestId(`key-row-${name}`);
    await expect(row).toContainText("active");
    await row.getByTestId("revoke-key").click();
    await page.getByTestId("revoke-submit").click();
    await expect(row).toContainText("revoked");
  });

  test("tenant keys are listed from the API", async ({ page }) => {
    await signIn(page, "admin", "meridian", "/settings?tab=tenant-keys");
    const keys = await bffGet<{ data: { purpose: string }[] }>(page, "/tenant-keys");
    expect(keys.data.length).toBeGreaterThan(0);
    await expect(page.getByTestId("rotate-payload")).toBeVisible();
  });
});

test.describe("demo fallback", () => {
  test("routes the API does not serve yet are marked as demo data on their panel", async ({ page }) => {
    await signIn(page, "admin", "meridian", "/queue");
    const res = await page.request.get("/api/bff/queue?limit=100");
    test.skip(res.headers()["x-sibyl-console-source"] !== "demo-fallback", "The queue is live on this stack; nothing to mark.");
    await expect(page.getByTestId("demo-mark").first()).toBeVisible();
  });
});
