/**
 * Action Gate end to end in demo mode, against the API's shapes and rules:
 *   - held actions: list, "acting for", approve after step-up, deny, the 409 self_approval for
 *     the person the agent acted for, and a four-eyes hold that needs two distinct approvers
 *     (409 duplicate_approver for the same person twice);
 *   - policies: simulate a stored version, revise it in the editor (local draft simulate in
 *     demo), submit a draft, and the author's own approval refused (tier-1 agent in scope).
 * Scenario: at 0:45 claims-triage proposes a ₹75,000 payout acting for the Platform Admin
 * (sensitive tool, one approver); at 1:30 the sixth refund in a minute is held (two approvers).
 */
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { as, ready, seek, type Persona } from "../support/demo";

const T = 120;

async function heldId(request: APIRequestContext, tool: string, persona: Persona = "operator"): Promise<string> {
  const res = await request.get("/api/bff/held-actions?state=pending&limit=100", { headers: { cookie: `sibyl_persona=${persona}; sibyl_tenant=meridian` } });
  const body = (await res.json()) as { data: { held_action_id: string; tool: string; args?: unknown; history?: unknown }[] };
  const found = body.data.find((h) => h.tool === tool);
  if (!found) throw new Error(`no pending held action for ${tool}`);
  // The API lists neither arguments nor the trail; the demo answers the same way.
  expect(found.args ?? null).toBeNull();
  expect(found.history).toBeUndefined();
  return found.held_action_id;
}

async function policyId(request: APIRequestContext, name: string): Promise<string> {
  const res = await request.get("/api/bff/action-policies?limit=200", { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const body = (await res.json()) as { data: { id: string; name: string; state: string }[] };
  const found = body.data.find((p) => p.name === name && p.state === "approved");
  if (!found) throw new Error(`no approved policy ${name}`);
  return found.id;
}

async function decide(page: Page, action: "approve" | "deny", reason: string, stepUp: boolean): Promise<void> {
  await page.getByLabel("Decision reason").fill(reason);
  await page.getByTestId(action === "approve" ? "held-approve" : "held-deny").click();
  if (stepUp) {
    await expect(page.getByTestId("step-up")).toBeVisible();
    await page.getByTestId("step-up-confirm").click();
  }
}

test.describe.serial("Action Gate · held actions", () => {
  test("the queue lists waiting actions with who the agent acted for and the approvals needed", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    await as(context, baseURL, "operator");
    await page.goto("/held-actions");
    await ready(page);
    const rows = page.getByTestId("held-row");
    await expect(rows).toHaveCount(2);
    const transfer = rows.filter({ hasText: "payments.transfer" });
    await expect(transfer.getByTestId("acting-for")).toHaveText(/acting for Platform Admin/);
    await expect(transfer).toContainText("transfer-review · v3");
    await expect(rows.filter({ hasText: "refunds.issue" })).toContainText("0 of 2 approvals");
  });

  test("the person the agent acted for cannot approve: 409 self_approval inline, recorded on the trail", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await heldId(request, "payments.transfer");
    await as(context, baseURL, "admin");
    await page.goto(`/held-actions/${id}`);
    await ready(page);
    await expect(page.getByTestId("held-on-behalf")).toHaveText("you");
    await expect(page.getByTestId("held-for-me")).toBeVisible();
    await decide(page, "approve", "My own payout; approving it anyway.", true);
    const error = page.getByTestId("held-error");
    await expect(error).toHaveAttribute("data-code", "self_approval");
    await expect(error).toContainText("Four-eyes rule (409 self_approval)");
    await expect(page.getByRole("list", { name: "Decision history" })).toContainText("Self-approval refused");
    await expect(page.getByTestId("held-decision")).toBeVisible();
  });

  test("a second person approves after step-up; the call runs and the decision is final", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await heldId(request, "payments.transfer");
    await as(context, baseURL, "operator");
    await page.goto(`/held-actions/${id}`);
    await ready(page);
    await decide(page, "approve", "Matches claim CLM-204871 and the surveyor's report.", true);
    await expect(page.getByTestId("held-decided")).toContainText("Approved");
    await expect(page.getByRole("list", { name: "Decision history" })).toContainText("Approved by you · step-up");
  });

  test("deny needs a reason and step-up on a sensitive tool, and ends the hold", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await heldId(request, "payments.transfer");
    await as(context, baseURL, "operator");
    await page.goto(`/held-actions/${id}`);
    await ready(page);
    await page.getByLabel("Decision reason").fill("too short");
    await expect(page.getByTestId("held-deny")).toBeDisabled();
    await decide(page, "deny", "Payee bank details do not match the claim file.", true);
    await expect(page.getByTestId("held-decided")).toContainText("Denied");
  });

  test("a four-eyes hold needs two different approvers: the same person twice is refused (409 duplicate_approver)", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await heldId(request, "refunds.issue");
    await as(context, baseURL, "operator");
    await page.goto(`/held-actions/${id}`);
    await ready(page);
    await expect(page.getByTestId("held-approve")).toContainText("Approve (first of two)");
    await decide(page, "approve", "Damaged in transit; photos attached to the ticket.", false);
    await expect(page.getByTestId("held-four-eyes")).toContainText("1 of 2 approvals");
    await decide(page, "approve", "Approving again to speed this up.", false);
    await expect(page.getByTestId("held-error")).toHaveAttribute("data-code", "duplicate_approver");

    await as(context, baseURL, "admin");
    await page.goto(`/held-actions/${id}`);
    await ready(page);
    await decide(page, "approve", "Second review: refund amount matches the order.", false);
    await expect(page.getByTestId("held-decided")).toContainText("Approved");
    const trail = page.getByRole("list", { name: "Decision history" });
    await expect(trail).toContainText("First approval by On-call Operator");
    await expect(trail).toContainText("Second approval by the same person refused");
  });
});

test.describe.serial("Action Gate · policies", () => {
  test("simulate a stored version: an over-limit transfer is blocked by transfer-limit", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await policyId(request, "Claims payouts");
    await as(context, baseURL, "admin");
    await page.goto(`/action-policies/${id}?tab=simulate`);
    await ready(page);
    await page.getByRole("button", { name: "transfer-limit" }).click();
    const result = page.getByTestId("sim-result");
    await expect(result).toHaveAttribute("data-effect", "block");
    await expect(page.getByTestId("sim-rule")).toHaveText("transfer-limit");
  });

  test("simulate counts the cap from the counters given: over the daily total escalates", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await policyId(request, "Claims payouts");
    await as(context, baseURL, "admin");
    await page.goto(`/action-policies/${id}?tab=simulate`);
    await ready(page);
    await page.getByTestId("sim-tool").fill("payments.transfer");
    await page.getByTestId("sim-args").fill(JSON.stringify({ amount: 40000, currency: "INR", reference: "CLM-204871" }));
    await page.getByTestId("sim-used-transfer-routine").fill("480000");
    await page.getByTestId("sim-run").click();
    await expect(page.getByTestId("sim-result")).toHaveAttribute("data-effect", "escalate");
    await page.getByTestId("sim-used-transfer-routine").fill("100000");
    await page.getByTestId("sim-run").click();
    await expect(page.getByTestId("sim-result")).toHaveAttribute("data-effect", "allow");
    await expect(page.getByTestId("sim-counter")).toContainText("100000 + 40000 of 500000");
  });

  test("revise, simulate the draft, submit; the author's own approval is refused (tier-1 agent in scope)", async ({ page, context, request, baseURL }) => {
    await seek(request, T);
    const id = await policyId(request, "Claims payouts");
    await as(context, baseURL, "admin");
    await page.goto(`/action-policies/${id}`);
    await ready(page);
    await page.getByTestId("policy-revise").click();
    await expect(page.getByRole("heading", { name: "Revise Claims payouts" })).toBeVisible();
    await page.getByTestId("pol-note").fill("Lower the review threshold to ₹40,000 after the October audit");
    await page.getByTestId("editor-simulate").click();
    await expect(page.getByTestId("sim-note")).toHaveText("Evaluated in the console against this draft");
    await page.getByRole("button", { name: "transfer-limit" }).click();
    await expect(page.getByTestId("sim-result")).toHaveAttribute("data-effect", "block");
    await page.getByTestId("sim-tool").fill("payments.transfer");
    await page.getByTestId("sim-args").fill(JSON.stringify({ amount: 75000, currency: "INR" }));
    await page.getByTestId("sim-run").click();
    await expect(page.getByTestId("sim-result")).toHaveAttribute("data-effect", "escalate");
    await expect(page.getByTestId("sim-rule")).toHaveText("transfer-review");
    await page.getByTestId("policy-submit").click();
    await expect(page).toHaveURL(/\/action-policies\/[^/?]+$/);
    await expect(page.getByRole("heading", { name: "Claims payouts" })).toBeVisible();
    await expect(page.getByText("v4", { exact: true })).toBeVisible();
    await expect(page.getByTestId("policy-decision")).toContainText("Awaiting approval");
    await page.getByLabel("Reason").fill("Reviewed the rules and ran the simulate samples");
    await page.getByTestId("policy-approve").click();
    await expect(page.getByTestId("policy-error")).toHaveAttribute("data-code", "self_approval");
    await page.getByTestId("policy-tab-versions").click();
    await expect(page.getByRole("region", { name: "Versions" }).getByRole("link")).toHaveCount(3);
  });
});

test("the audit view filters Action Gate rows by agent and time", async ({ page, context, request, baseURL }) => {
  await seek(request, T);
  const res = await request.get("/api/bff/agents?q=hr-helpdesk", { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
  const agent = ((await res.json()) as { data: { id: string; slug: string }[] }).data.find((a) => a.slug === "hr-helpdesk")?.id ?? "";
  await as(context, baseURL, "auditor");
  await page.goto(`/audit?action=action.blocked&agent_id=${agent}`);
  await ready(page);
  await expect(page.getByTestId("audit-agent-chip")).toBeVisible();
  await expect(page.getByTestId("audit-row")).toHaveCount(1);
  await page.getByTestId("audit-row").first().click();
  await expect(page.getByTestId("action-record")).toContainText("email.send_external");
  await page.goto(`/audit?action=action.blocked&agent_id=${agent}&occurred_after=2030-01-01T00:00:00Z`);
  await ready(page);
  await expect(page.getByText("No events match")).toBeVisible();
});
