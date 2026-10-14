/**
 * The Phase 1 demo flow (shipper §1.2, PM beats B1–B9) through the console in demo mode.
 * Each test seeks the scripted scenario to the second it needs, so they are independent.
 */
import { expect, test } from "@playwright/test";
import { agentIdBySlug, as, incidentFor, ready, seek } from "../support/demo";

test.describe("B1 · fleet", () => {
  test("The Platform Admin sees 20 meridian agents across 3 providers, clearly labelled as demo data", async ({ page, context, request, baseURL }) => {
    await seek(request, 10);
    await as(context, baseURL, "admin");
    await page.goto("/fleet");
    await ready(page);
    await expect(page.getByRole("heading", { level: 1, name: "Fleet" })).toBeVisible();
    await expect(page.getByTestId("demo-chip")).toContainText("Demo data");
    await expect(page.locator('[data-testid^="tile-"]')).toHaveCount(20);
    for (const g of ["anthropic", "openai", "ollama"]) await expect(page.getByTestId(`group-${g}`)).toBeVisible();
    await expect(page.getByTestId("tile-kyc-verifier")).toContainText("Degraded mode");
  });

  test("list view and band filter live in the URL", async ({ page, context, request, baseURL }) => {
    await seek(request, 10);
    await as(context, baseURL, "admin");
    await page.goto("/fleet?view=list");
    await ready(page);
    await expect(page.locator("table tbody tr")).toHaveCount(20);
    await page.getByRole("button", { name: /^Watch/ }).click();
    await expect(page).toHaveURL(/band=watch/);
  });
});

test.describe("B2–B4 · outage, one incident, tiered failover", () => {
  test("provider outage collapses into one incident and every anthropic agent moves", async ({ page, context, request, baseURL }) => {
    await seek(request, 70);
    await as(context, baseURL, "admin");
    await page.goto("/fleet");
    await ready(page);
    await expect(page.getByTestId("incident-banner")).toContainText("Anthropic is down");
    await expect(page.getByTestId("provider-incident")).toContainText("7 of 7 moved");
    await expect(page.getByTestId("tile-claims-triage")).toContainText("Failed over");
    await expect(page.getByTestId("tile-claims-triage")).toContainText("Serving from OpenAI");
  });

  test("the score is explainable: penalties sum to 100 − score", async ({ page, context, request, baseURL }) => {
    await seek(request, 36);
    await as(context, baseURL, "admin");
    const id = await agentIdBySlug(request, "kyc-verifier");
    await page.goto(`/agents/${id}`);
    await ready(page);
    const arithmetic = (await page.getByTestId("score-arithmetic").textContent()) ?? "";
    expect(arithmetic).toMatch(/^100 − /);
    const penalties = await page.locator('[data-testid^="factor-"] .f-pen').allTextContents();
    expect(penalties.length).toBeGreaterThan(0);
    const sum = penalties.map((t) => Number(t.replace("−", ""))).reduce((a, b) => a + b, 0);
    const score = Number(/= (-?\d+)/.exec(arithmetic)?.[1]);
    expect(100 - sum).toBe(score);
    await expect(page.getByText("arithmetic checks")).toBeVisible();
  });
});

test.describe("B5 · four-eyes approval", () => {
  test("The Platform Admin cannot approve their own tier-1 backup-agent request; the On-call Operator can", async ({ page, context, request, baseURL }) => {
    await seek(request, 10);
    await as(context, baseURL, "admin");
    const id = await agentIdBySlug(request, "quote-assistant");
    await page.goto(`/agents/${id}`);
    await ready(page);
    await page.getByTestId("action-failover").click();
    await page.getByRole("radio", { name: /Backup agent/ }).check();
    await page.getByLabel("Reason").fill("Rate limits climbing; moving to the standby agent before customers notice.");
    await page.getByTestId("action-submit").click();
    await expect(page).toHaveURL(/\/incidents\//);
    await expect(page.getByTestId("approval-card")).toContainText("Approval needed");

    await page.getByLabel("Decision reason").fill("Approving my own request to check the rule.");
    await page.getByTestId("approve").click();
    await expect(page.getByTestId("approval-error")).toContainText("Four-eyes rule");

    const url = page.url();
    await as(context, baseURL, "operator");
    await page.goto(url);
    await ready(page);
    await page.getByLabel("Decision reason").fill("Verified the rate-limit trend; approving the standby move.");
    await page.getByTestId("approve").click();
    await expect(page.getByTestId("approval-card")).toContainText("Approval approved");
    await expect(page.getByText("Failed over").first()).toBeVisible();
  });

  test("the scripted L3 prediction waits for approval with a countdown", async ({ page, context, request, baseURL }) => {
    await seek(request, 215);
    await as(context, baseURL, "operator");
    await page.goto("/incidents");
    await ready(page);
    await expect(page.getByTestId("incident-row-quote-assistant")).toContainText("Decide in");
  });
});

test.describe("B6 · operator queue", () => {
  test("The On-call Operator claims and completes a checkpoint packet; the completed counter ticks", async ({ page, context, request, baseURL }) => {
    await seek(request, 10);
    await as(context, baseURL, "operator");
    await page.goto("/queue");
    await ready(page);
    await expect(page.locator("main .lede")).toContainText("2 tasks completed despite");
    await expect(page.getByTestId("packet").locator(".untrusted[data-label=\"Untrusted agent content\"]")).toBeVisible();
    await page.getByTestId("claim").click();
    await page.getByTestId("complete").click();
    await page.getByLabel("What you did").fill("Agreed the split pickup with Apex dispatch and booked both slots.");
    await page.getByTestId("complete-submit").click();
    await expect(page.locator("main .lede")).toContainText("3 tasks completed despite");
  });
});

test.describe("D24 · verdicts", () => {
  test("closing an alert without a verdict is refused (422); with a verdict it closes", async ({ page, context, request, baseURL }) => {
    await seek(request, 10);
    await as(context, baseURL, "operator");
    await page.goto("/alerts");
    await ready(page);
    const row = page.getByTestId("alert-row").filter({ hasText: "Tool loop" });
    await row.getByTestId("close-alert").click();
    await page.getByTestId("verdict-submit").click();
    await expect(page.getByTestId("verdict-error")).toContainText("verdict");
    await page.getByTestId("verdict-tp").click();
    await page.getByTestId("verdict-submit").click();
    await expect(page.getByTestId("verdict-dialog")).not.toBeVisible();
    await page.getByTestId("alerts-resolved").click();
    await expect(page.getByTestId("alert-row").filter({ hasText: "Tool loop" })).toContainText("TP");
  });
});

test.describe("B7 · undo, hold and kill", () => {
  test("The On-call Operator undoes an automatic failover and automation pauses for 30 minutes", async ({ page, context, request, baseURL }) => {
    await seek(request, 70);
    await as(context, baseURL, "operator");
    const incident = await incidentFor(request, "invoice-reconciler", (i) => i.kind === "failover");
    await page.goto(`/incidents/${incident}`);
    await ready(page);
    await page.getByTestId("action-undo").click();
    await page.getByLabel("Reason").fill("Finance close must stay on the contracted provider; holding manually.");
    await page.getByTestId("incident-action-submit").click();
    await expect(page.getByTestId("hold-banner")).toContainText("Automation paused until");
  });

  test("The On-call Operator pulls the kill switch on one agent after step-up", async ({ page, context, request, baseURL }) => {
    await seek(request, 70);
    await as(context, baseURL, "operator");
    await page.goto("/fleet");
    await ready(page);
    await page.getByTestId("kill-switch").click();
    const dialog = page.getByTestId("kill-dialog");
    await dialog.getByLabel("Agent", { exact: true }).selectOption({ label: "Email summarizer · T3" });
    await dialog.getByLabel("Reason").fill("Summaries leaking internal ticket notes to customers; stopping now.");
    await page.getByTestId("kill-confirm").click();
    await expect(page.getByTestId("step-up")).toBeVisible();
    await page.getByTestId("step-up-confirm").click();
    await expect(page.getByTestId("kill-dialog")).toContainText("Kill switch applied");
    await expect(page.getByTestId("kill-dialog")).toContainText("1 / 1");
  });
});

test.describe("B8 · the auditor", () => {
  test("The Compliance Auditor verifies the chain, sees a tampered copy fail, reads a decision record and exports", async ({ page, context, request, baseURL }) => {
    await seek(request, 80);
    await as(context, baseURL, "auditor");
    await page.goto("/audit");
    await ready(page);
    await page.getByTestId("verify-chain").click();
    await expect(page.getByTestId("verify-result")).toContainText("Chain intact");
    await page.getByTestId("tamper").click();
    await expect(page.getByTestId("verify-result")).toContainText("Break at seq");

    await page.goto("/audit?action=route.changed");
    await page.getByTestId("audit-row").first().click();
    await expect(page.getByTestId("decision-arithmetic")).toContainText("100 −");

    await page.keyboard.press("Escape");
    await page.getByTestId("export").click();
    await expect(page.getByTestId("download")).toBeVisible({ timeout: 15_000 });
  });

  test("The Compliance Auditor is read-only on incidents and cannot pull the kill switch", async ({ page, context, request, baseURL }) => {
    await seek(request, 215);
    await as(context, baseURL, "auditor");
    const incident = await incidentFor(request, "quote-assistant", (i) => i.state === "waiting_approval");
    await page.goto(`/incidents/${incident}`);
    await ready(page);
    await expect(page.getByTestId("approve")).toHaveCount(0);
    await expect(page.getByTestId("kill-switch")).toHaveCount(0);
    await expect(page.getByText("cannot decide approvals")).toBeVisible();
  });

  test("northstar stays quiet throughout the outage (isolation)", async ({ page, context, request, baseURL }) => {
    await seek(request, 70);
    await as(context, baseURL, "auditor", "northstar");
    await page.goto("/fleet");
    await ready(page);
    await expect(page.locator('[data-testid^="tile-"]')).toHaveCount(3);
    await expect(page.getByTestId("incident-banner")).toHaveCount(0);
  });
});

test.describe("Onboarding · sandbox", () => {
  test("no key before a capture policy; policy, key shown once, agent discovered", async ({ page, context, request, baseURL }) => {
    await seek(request, 5, false);
    await as(context, baseURL, "admin", "sandbox");
    await page.goto("/onboarding");
    await ready(page);
    await page.getByTestId("mint-key").click();
    await expect(page.getByTestId("key-error")).toContainText("capture_policy_missing");
    await expect(page.getByTestId("capture-full")).toBeChecked();
    await page.getByTestId("capture-ack").check();
    await page.getByTestId("save-policy").click();
    await expect(page.getByTestId("policy-summary")).toContainText("Full capture");
    await page.getByTestId("mint-key").click();
    await expect(page.getByTestId("key-secret")).toContainText(/^sbl_live_[A-Za-z0-9]{12}_/);
    await page.getByTestId("key-done").click();
    await expect(page.getByTestId("discovered-agent")).toContainText("quote-worker", { timeout: 20_000 });
    await expect(page.getByTestId("discovered-agent")).toContainText("Request-only");
  });
});

test.describe("Shell", () => {
  test("⌘K palette jumps to an agent; persona switch changes what is allowed", async ({ page, context, request, baseURL }) => {
    await seek(request, 10);
    await as(context, baseURL, "admin");
    await page.goto("/fleet");
    await ready(page);
    await page.keyboard.press("ControlOrMeta+k");
    await expect(page.getByTestId("palette")).toBeVisible();
    await page.keyboard.type("claims triage");
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("agent-name")).toHaveText("Claims triage");

    await page.getByTestId("persona-menu").click();
    await page.getByTestId("persona-auditor").click();
    await expect(page.getByTestId("persona-menu")).toContainText("Compliance Auditor");
    await expect(page.getByText("View only")).toBeVisible();
  });

  test("BFF refuses mutations without the CSRF token", async ({ request }) => {
    const res = await request.post("/api/bff/alerts/x/actions", { data: { action: "ack" } });
    expect(res.status()).toBe(403);
    expect((await res.json()).type).toContain("csrf_failed");
  });
});
