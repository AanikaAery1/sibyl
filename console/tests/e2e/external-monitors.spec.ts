/**
 * Wave 4 in demo mode (D53): external monitors (register with a key shown once, pause/resume
 * with If-Match, webhooks with a signing secret shown once and test deliveries, issue a key,
 * revoke) and their advisory findings next to Sentinel's.
 */
import { expect, test, type APIRequestContext } from "@playwright/test";
import { as, ready, seek } from "../support/demo";

const ADMIN = "sibyl_persona=admin; sibyl_tenant=meridian";

async function monitorId(request: APIRequestContext, name: string): Promise<string> {
  const res = await request.get("/api/bff/monitors?limit=100", { headers: { cookie: ADMIN } });
  const found = ((await res.json()) as { data: { id: string; name: string }[] }).data.find((m) => m.name === name);
  if (!found) throw new Error(`monitor ${name} not found`);
  return found.id;
}

test.describe("monitors", () => {
  test("the list shows each monitor's kind, state, watched groups and webhook health; revoked last", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto("/fleet");
    await ready(page);
    await page.getByTestId("nav-monitors").click();
    await expect(page).toHaveURL(/\/monitors$/);
    await expect(page.getByRole("heading", { level: 1, name: "Monitors" })).toBeVisible();
    await expect(page.getByTestId("monitor-advisory")).toContainText("never allows, blocks, approves");
    const rows = page.getByTestId("monitor-row");
    await expect(rows).toHaveCount(4);
    await expect(rows.last()).toContainText("Legacy Slack relay");
    await expect(rows.last()).toHaveAttribute("data-state", "revoked");
    const pd = rows.filter({ hasText: "PagerDuty bridge" });
    await expect(pd.getByTestId("monitor-kind")).toContainText("Webhook");
    await expect(pd.getByTestId("monitor-watches")).toContainText("Claims & payouts, Logistics");
    await expect(pd.getByTestId("monitor-webhooks")).toContainText("Retrying");
    await expect(rows.filter({ hasText: "Claude ops reviewer" }).getByTestId("monitor-findings-24h")).toContainText("2");
    await page.getByTestId("monitor-filter-paused").click();
    await expect(page).toHaveURL(/state=paused/);
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("Nightly audit script");
  });

  test("register: validation, the key shown once with MCP setup, then the detail; a duplicate name is refused", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto("/monitors");
    await ready(page);
    await page.getByTestId("monitor-register-open").click();
    const dialog = page.getByTestId("monitor-register");
    await dialog.getByTestId("monitor-register-submit").click();
    await expect(dialog.getByText("Name the monitor.")).toBeVisible();
    await expect(dialog.getByTestId("monitor-register-submit")).toBeDisabled();
    await dialog.getByLabel("Name").fill("Claude incident scribe");
    await dialog.getByTestId("mon-all-groups").uncheck();
    await expect(dialog.getByText("Pick at least one agent group")).toBeVisible();
    await dialog.getByTestId("mon-groups").getByLabel("Claims & payouts").check();
    await dialog.getByLabel("Reason").fill("Writes incident timelines for the post-mortem doc.");
    await dialog.getByTestId("monitor-register-submit").click();

    const created = page.getByTestId("monitor-created");
    await expect(created).toContainText("Shown once.");
    const secret = (await created.getByTestId("monitor-key-value").textContent()) ?? "";
    expect(secret).toMatch(/^sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}$/);
    await expect(created.getByTestId("snippet-code")).toContainText('"SIBYL_MONITOR_KEY"');
    await expect(created.getByTestId("snippet-code")).toContainText(secret);
    await created.getByTestId("snippet-claude-code").click();
    await expect(created.getByTestId("snippet-code")).toContainText("claude mcp add sibyl");
    await created.getByTestId("monitor-created-done").click();

    await expect(page).toHaveURL(/\/monitors\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("monitor-name")).toHaveText("Claude incident scribe");
    await expect(page.getByTestId("monitor-watches")).toHaveText("Claims & payouts");
    await expect(page.getByTestId("monitor-keys").locator("tbody tr")).toHaveCount(1);
    // The secret is never shown again on the detail.
    await expect(page.getByText(secret)).toHaveCount(0);

    await page.goto("/monitors");
    await page.getByTestId("monitor-register-open").click();
    await page.getByLabel("Name").fill("PagerDuty bridge");
    await page.getByLabel("Reason").fill("Trying to register the same name twice.");
    await page.getByTestId("monitor-register-submit").click();
    await expect(page.getByTestId("monitor-register-error")).toContainText("already exists");
  });

  test("pause and resume send If-Match; a stale version is refused with 412", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    const id = await monitorId(request, "Claude ops reviewer");
    const stale = await request.patch(`/api/bff/monitors/${id}`, {
      headers: { cookie: `${ADMIN}; sibyl_csrf=t`, "x-sibyl-csrf": "t", "if-match": '"1"' },
      data: { state: "paused" },
    });
    expect(stale.status()).toBe(412);
    await page.goto(`/monitors/${id}`);
    await ready(page);
    await page.getByTestId("monitor-pause").click();
    await expect(page.getByTestId("monitor-paused")).toContainText("409 not_active");
    await expect(page.getByTestId("monitor-state")).toHaveText("Paused");
    await page.getByTestId("monitor-resume").click();
    await expect(page.getByTestId("monitor-state")).toHaveText("Active");
    await expect(page.getByTestId("monitor-pause")).toBeVisible();
  });

  test("webhooks: test deliveries report the receiver's answer; a new webhook shows its whsec_ secret once", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto(`/monitors/${await monitorId(request, "PagerDuty bridge")}`);
    await ready(page);
    const hooks = page.getByTestId("webhook-row");
    await expect(hooks).toHaveCount(2);
    await hooks.nth(0).getByTestId("webhook-test").click();
    await expect(hooks.nth(0).getByTestId("webhook-test-result")).toContainText("HTTP 202");
    await hooks.nth(1).getByTestId("webhook-test").click();
    await expect(hooks.nth(1).getByTestId("webhook-test-result")).toContainText("HTTP 503");

    await page.getByTestId("webhook-add-open").click();
    const add = page.getByTestId("webhook-add");
    await add.getByLabel("Receiver URL").fill("http://hooks.example.com/sibyl");
    await add.getByTestId("webhook-add-submit").click();
    await expect(add.getByText("Webhooks are https only.")).toBeVisible();
    await add.getByLabel("Receiver URL").fill("https://ops.meridian-logistics.example/sibyl/drift");
    await add.getByTestId("hook-event-drift.detected").check();
    await add.getByTestId("webhook-add-submit").click();
    const created = page.getByTestId("webhook-created");
    await expect(created.getByTestId("webhook-secret-value")).toHaveText(/^whsec_[A-Za-z0-9_-]{43}$/);
    await created.getByTestId("webhook-created-done").click();
    await expect(hooks).toHaveCount(3);
    await expect(hooks.nth(2)).toContainText("No delivery yet");
  });

  test("issue a key (shown once) and revoke with a reason; a revoked monitor is read-only", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto(`/monitors/${await monitorId(request, "Nightly audit script")}`);
    await ready(page);
    await page.getByTestId("monitor-issue-key").click();
    await page.getByTestId("monitor-key-submit").click();
    await expect(page.getByTestId("monitor-key-value")).toHaveText(/^sbl_/);
    await page.getByTestId("monitor-key-done").click();
    await expect(page.getByTestId("monitor-keys").locator("tbody tr")).toHaveCount(2);

    await page.getByTestId("monitor-revoke-open").click();
    const dialog = page.getByTestId("monitor-revoke");
    await expect(dialog.getByTestId("monitor-revoke-confirm")).toBeDisabled();
    await dialog.getByLabel("Reason").fill("Finance moved the job to the new data platform.");
    await dialog.getByTestId("monitor-revoke-confirm").click();
    await expect(page.getByTestId("monitor-revoked")).toContainText("Finance moved the job");
    await expect(page.getByTestId("monitor-state")).toHaveText("Revoked");
    await expect(page.getByTestId("monitor-pause")).toHaveCount(0);
    await expect(page.getByTestId("monitor-resume")).toHaveCount(0);
    await expect(page.getByTestId("monitor-issue-key")).toHaveCount(0);
  });

  test("Sentinel readers without monitors:admin (the auditor) see monitors read-only", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "auditor");
    await page.goto("/monitors");
    await ready(page);
    await expect(page.getByTestId("monitors-read-only")).toBeVisible();
    await expect(page.getByTestId("monitor-register-open")).toHaveCount(0);
    await page.getByTestId("monitor-row").filter({ hasText: "PagerDuty bridge" }).click();
    await expect(page.getByTestId("monitor-name")).toHaveText("PagerDuty bridge");
    await expect(page.getByTestId("monitor-pause")).toHaveCount(0);
    await expect(page.getByTestId("webhook-test")).toHaveCount(0);
    await expect(page.getByTestId("webhook-add-open")).toHaveCount(0);
  });
});

test.describe("external findings next to Sentinel", () => {
  test("the feed labels the source and filters to monitors; monitor text stays plain text", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "operator");
    await page.goto("/sentinel");
    await ready(page);
    await page.getByTestId("source-external").click();
    await expect(page).toHaveURL(/source=external/);
    const rows = page.getByTestId("finding-row");
    await expect(rows).toHaveCount(4);
    await expect(rows.first().getByTestId("finding-source")).toHaveText("Monitor: Claude ops reviewer");
    await rows.first().click();
    await expect(page.getByTestId("finding-summary")).toContainText("payee bank changed");
    const body = page.getByTestId("external-body");
    await expect(body).toHaveAttribute("data-label", /untrusted/);
    await expect(body.locator("a, img, script")).toHaveCount(0);
    await expect(page.getByTestId("finding-recommendation")).toContainText("Leans deny");
    await expect(page.getByTestId("finding-monitor")).toBeVisible();
    await page.getByTestId("feedback-useful").click();
    await expect(page.getByTestId("feedback-useful")).toHaveAttribute("aria-pressed", "true");
  });

  test("the held action shows the monitor's review apart from Sentinel's and the decision", async ({ page, context, request, baseURL }) => {
    await seek(request, 60);
    await as(context, baseURL, "operator");
    const res = await request.get("/api/bff/held-actions?limit=50", { headers: { cookie: "sibyl_persona=operator; sibyl_tenant=meridian" } });
    const held = ((await res.json()) as { data: { id: string; tool: string }[] }).data.find((h) => h.tool === "payments.transfer");
    await page.goto(`/held-actions/${held?.id}`);
    await ready(page);
    await expect(page.getByTestId("sentinel-recommendation")).toContainText("Needs more information");
    const mon = page.getByTestId("monitor-recommendation");
    await expect(mon).toHaveCount(1);
    await expect(mon).toContainText("Claude ops reviewer");
    await expect(mon).toContainText("Leans deny");
    await expect(mon).toContainText("a monitor cannot approve");
    await expect(mon.getByTestId("held-approve")).toHaveCount(0);
    await expect(page.getByTestId("held-decision")).toBeVisible();
  });

  test("Runs and Monitors are in the sidebar", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto("/fleet");
    await ready(page);
    await page.getByTestId("nav-runs").click();
    await expect(page).toHaveURL(/\/runs/);
    await expect(page.getByTestId("nav-runs")).toHaveAttribute("aria-current", "page");
    await expect(page.getByTestId("nav-monitors")).toBeVisible();
  });
});
