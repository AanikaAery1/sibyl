/**
 * Wave 3 in demo mode: model drift (watch-only, reset baseline), Sentinel (advisory findings,
 * setup with step-up, recommendation beside the human decision), run tree, discovery and claim,
 * plug-and-play onboarding.
 */
import { expect, test } from "@playwright/test";
import { agentIdBySlug, as, latestRunId, ready, seek } from "../support/demo";

const ADMIN = { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" };

test.describe("model drift", () => {
  test("the fleet view ranks drift first, flags the model change and says watch-only", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "operator");
    await page.goto("/drift");
    await ready(page);
    await expect(page.getByRole("heading", { level: 1, name: "Model drift" })).toBeVisible();
    await expect(page.getByTestId("watch-only")).toContainText("never triggers a failover");
    const first = page.getByTestId("drift-row").first();
    await expect(first).toContainText("Route optimizer");
    await expect(first).toContainText("Drift");
    await page.getByTestId("drift-filter-identity").click();
    await expect(page).toHaveURL(/filter=identity/);
    await expect(page.getByTestId("drift-row")).toHaveCount(1);
    await expect(page.getByTestId("drift-row").first()).toContainText("Sales copilot");
    await expect(page.getByTestId("identity-flag").first()).toBeVisible();
  });

  test("an agent's drift shows every feature's numbers and the new snapshot", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto(`/agents/${await agentIdBySlug(request, "sales-copilot")}`);
    await ready(page);
    const drift = page.getByTestId("agent-drift");
    await expect(drift.getByTestId("feature-table")).toBeVisible();
    await expect(drift.getByTestId("feature-output_tokens")).toContainText("Watch");
    await expect(drift.getByTestId("identity-finding").first()).toContainText("gpt-5-2026-10-08");
    await expect(drift.getByTestId("served-new").first()).toBeVisible();
    await expect(drift.getByTestId("drift-alerts")).toContainText("model change");
  });

  test("reset baseline needs a reason, supersedes the baseline and resolves the drift alert", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto(`/agents/${await agentIdBySlug(request, "route-optimizer")}`);
    await ready(page);
    await page.getByTestId("drift-reset-open").click();
    const dialog = page.getByTestId("drift-reset");
    await expect(dialog.getByTestId("drift-reset-submit")).toBeDisabled();
    await dialog.getByLabel("Reason").fill("Geocoder cache fixed; the new tool sequence is expected.");
    await dialog.getByTestId("drift-reset-submit").click();
    await expect(page.getByTestId("baseline-state").first()).toContainText("Collecting");
    await expect(page.getByTestId("drift-alerts")).toHaveCount(0);
  });

  test("the auditor reads drift but cannot reset it", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "auditor");
    await page.goto(`/agents/${await agentIdBySlug(request, "route-optimizer")}`);
    await ready(page);
    await expect(page.getByTestId("feature-table")).toBeVisible();
    await expect(page.getByTestId("drift-reset-open")).toHaveCount(0);
  });

  test("fleet tiles carry a drift hint", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto("/fleet");
    await ready(page);
    await expect(page.getByTestId("tile-route-optimizer").getByTestId("drift-hint")).toContainText("Drift");
    await expect(page.getByTestId("tile-sales-copilot").getByTestId("drift-hint")).toContainText("Model changed");
  });
});

test.describe("Sentinel", () => {
  test("findings are advisory, with cost and today's budget; the auditor reads but cannot set up", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "auditor");
    await page.goto("/sentinel");
    await ready(page);
    await expect(page.getByTestId("advisory-note")).toContainText("never allows, blocks, approves");
    await expect(page.getByTestId("budget")).toContainText("of $5.00 today");
    // Unified feed (D53): Sentinel's six plus four from external monitors, each labelled.
    await expect(page.getByTestId("finding-row")).toHaveCount(10);
    await page.getByTestId("source-sentinel").click();
    await expect(page).toHaveURL(/source=sentinel/);
    await expect(page.getByTestId("finding-row")).toHaveCount(6);
    await expect(page.getByTestId("sentinel-setup")).toHaveCount(0);
    await page.getByTestId("kind-held_action_review").click();
    await expect(page.getByTestId("finding-row")).toHaveCount(2);
    await page.getByTestId("finding-row").first().click();
    await expect(page.getByTestId("provenance")).toContainText("gemini-2.5-flash");
    await page.getByTestId("feedback-useful").click();
    await expect(page.getByTestId("feedback-useful")).toHaveAttribute("aria-pressed", "true");
  });

  test("the held action shows Sentinel's review apart from the decision", async ({ page, context, request, baseURL }) => {
    await seek(request, 60);
    await as(context, baseURL, "operator");
    const res = await request.get("/api/bff/held-actions?limit=50", { headers: { cookie: "sibyl_persona=operator; sibyl_tenant=meridian" } });
    const held = ((await res.json()) as { data: { id: string; tool: string }[] }).data.find((h) => h.tool === "payments.transfer");
    await page.goto(`/held-actions/${held?.id}`);
    await ready(page);
    const rec = page.getByTestId("sentinel-recommendation");
    await expect(rec).toContainText("Needs more information");
    await expect(rec).toContainText("Advisory only");
    await expect(rec.getByTestId("held-approve")).toHaveCount(0);
    await expect(page.getByTestId("held-decision")).toBeVisible();
  });

  test("the incident shows Sentinel's explanation", async ({ page, context, request, baseURL }) => {
    await seek(request, 60);
    await as(context, baseURL, "admin");
    const id = await agentIdBySlug(request, "claims-triage");
    const res = await request.get(`/api/bff/incidents?agent_id=${id}`, { headers: { cookie: "sibyl_persona=admin; sibyl_tenant=meridian" } });
    const inc = ((await res.json()) as { data: { id: string }[] }).data[0];
    await page.goto(`/incidents/${inc?.id}`);
    await ready(page);
    await expect(page.getByTestId("sentinel-recommendation")).toContainText("failed over to OpenAI");
  });

  test("setup: the key is write-only, saving needs If-Match and a step-up, the test reports latency", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto("/settings/sentinel");
    await ready(page);
    await expect(page.getByTestId("sentinel-key")).toHaveValue("");
    await expect(page.getByTestId("sentinel-key")).toHaveAttribute("placeholder", /Vaulted …k3Qz/);
    await page.getByTestId("sentinel-test").click();
    await expect(page.getByTestId("sentinel-test-result")).toContainText("HTTP 200");
    await page.getByTestId("provider-anthropic").click();
    await expect(page.getByLabel("Model")).toHaveValue("claude-haiku-4-5");
    await page.getByLabel("Reason for the change").fill("Move Sentinel to Haiku for the pilot.");
    await page.getByTestId("sentinel-save").click();
    // Demo step-up: the re-auth dialog appears; confirming retries the same request.
    await page.getByTestId("step-up-confirm").click();
    await expect(page.getByText("Sentinel saved")).toBeVisible();
    await expect(page.getByText(/v4 · updated/)).toBeVisible();
  });
});

test.describe("Sentinel connection test and If-Match", () => {
  test("the save sends the GET's ETag; a failed test is explained from its error code", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto("/settings/sentinel");
    await ready(page);
    await page.getByLabel("Model").fill("no-such-model");
    await page.getByLabel("Reason for the change").fill("Check the connection test reports a bad model name.");
    const put = page.waitForRequest((r) => r.url().endsWith("/api/bff/sentinel/config") && r.method() === "PUT");
    await page.getByTestId("sentinel-save").click();
    expect((await put).headers()["if-match"]).toBe('"3"');
    await page.getByTestId("step-up-confirm").click();
    await expect(page.getByText("Sentinel saved")).toBeVisible();
    await page.getByTestId("sentinel-test").click();
    const result = page.getByTestId("sentinel-test-result");
    await expect(result).toHaveAttribute("data-ok", "false");
    await expect(result).toContainText("Connection failed.");
    await expect(result).toContainText("does not know this model or endpoint (HTTP 404)");
    await expect(result.getByTestId("sentinel-test-detail")).toContainText("no-such-model");
    await expect(result.getByTestId("sentinel-test-detail")).toContainText("http_error");
  });

  test("before the first save the ETag is \"0\"; testing an unset Sentinel is a 409", async ({ request }) => {
    await seek(request, 10);
    const csrf = "e2e-csrf-token";
    const headers = { cookie: `sibyl_persona=admin; sibyl_tenant=sandbox; sibyl_csrf=${csrf}`, "x-sibyl-csrf": csrf };
    const get = await request.get("/api/bff/sentinel/config", { headers });
    expect(get.headers()["etag"]).toBe('"0"');
    expect(((await get.json()) as { configured: boolean }).configured).toBe(false);
    const test409 = await request.post("/api/bff/sentinel/config/test", { headers: { ...headers, "content-type": "application/json", "idempotency-key": crypto.randomUUID() }, data: {} });
    expect(test409.status()).toBe(409);
    expect(((await test409.json()) as { type: string }).type).toMatch(/not_active$/);
  });
});

test.describe("held actions list", () => {
  test("deciders see masked arguments on each row; views filter on the server with repeated state", async ({ page, context, request, baseURL }) => {
    await seek(request, 120);
    await as(context, baseURL, "operator");
    const list = page.waitForResponse((r) => r.url().includes("/api/bff/held-actions?") && r.url().includes("include=args"));
    await page.goto("/held-actions");
    await ready(page);
    expect((await list).ok()).toBe(true);
    const transfer = page.getByTestId("held-row").filter({ hasText: "payments.transfer" }).first();
    await expect(transfer.getByTestId("held-args")).toContainText("amount");
    // "Decided" asks the API for every decided state (repeated `state`), not a client-side filter.
    const decidedReq = page.waitForRequest((r) => r.url().includes("/api/bff/held-actions?") && r.url().includes("state=approved"));
    await page.getByTestId("held-view-decided").click();
    await expect(page).toHaveURL(/view=decided/);
    expect(new URL((await decidedReq).url()).searchParams.getAll("state")).toEqual(["approved", "denied", "expired", "cancelled"]);
    // Nothing has been decided yet at this point of the scenario.
    await expect(page.getByTestId("held-row")).toHaveCount(0);

    // The API side: repeated state, args only for deciders.
    const op = { cookie: "sibyl_persona=operator; sibyl_tenant=meridian" };
    const mixed = (await (await request.get("/api/bff/held-actions?state=pending&state=expired&include=args&limit=100", { headers: op })).json()) as { data: { state: string; args: unknown }[] };
    expect(mixed.data.length).toBeGreaterThan(0);
    expect(mixed.data.every((h) => h.state === "pending" || h.state === "expired")).toBe(true);
    expect(mixed.data.some((h) => h.args !== null)).toBe(true);
    const none = (await (await request.get("/api/bff/held-actions?state=approved&state=denied&limit=100", { headers: op })).json()) as { data: unknown[] };
    expect(none.data).toHaveLength(0);
    expect((await request.get("/api/bff/held-actions?state=bogus", { headers: op })).status()).toBe(422);
    const auditor = (await (await request.get("/api/bff/held-actions?include=args&limit=100", { headers: { cookie: "sibyl_persona=auditor; sibyl_tenant=meridian" } })).json()) as { data: { args: unknown }[] };
    expect(auditor.data.length).toBeGreaterThan(0);
    expect(auditor.data.every((h) => h.args === null)).toBe(true);
    const plain = (await (await request.get("/api/bff/held-actions?limit=100", { headers: { cookie: "sibyl_persona=operator; sibyl_tenant=meridian" } })).json()) as { data: { args: unknown }[] };
    expect(plain.data.every((h) => h.args === null)).toBe(true);
  });

  test("an auditor's list has no arguments to show", async ({ page, context, request, baseURL }) => {
    await seek(request, 120);
    await as(context, baseURL, "auditor");
    await page.goto("/held-actions?view=all");
    await ready(page);
    await expect(page.getByTestId("held-row").first()).toBeVisible();
    await expect(page.getByTestId("held-args")).toHaveCount(0);
  });
});

test.describe("drift history paging", () => {
  test("the history window and page size go to the API as since and limit", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    await page.goto(`/agents/${await agentIdBySlug(request, "route-optimizer")}`);
    await ready(page);
    const drift = page.getByTestId("agent-drift");
    await expect(drift.getByTestId("drift-history-count")).toBeVisible();
    const windowed = page.waitForRequest((r) => /\/api\/bff\/agents\/[^/]+\/drift\?since=/.test(r.url()));
    await drift.getByTestId("drift-range-24h").click();
    expect(new URL((await windowed).url()).searchParams.get("since")).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    await expect(drift.getByTestId("drift-range-24h")).toHaveAttribute("aria-pressed", "true");
    const id = await agentIdBySlug(request, "route-optimizer");
    const two = (await (await request.get(`/api/bff/agents/${id}/drift?limit=2`, { headers: ADMIN })).json()) as { history: { evaluated_at: string }[] };
    expect(two.history).toHaveLength(2);
    expect(Date.parse(two.history[0]?.evaluated_at ?? "")).toBeGreaterThanOrEqual(Date.parse(two.history[1]?.evaluated_at ?? ""));
    expect((await request.get(`/api/bff/agents/${id}/drift?limit=0`, { headers: ADMIN })).status()).toBe(422);
  });
});

test.describe("run tree, discovery and onboarding", () => {
  test("the claims run tree comes from /runs: nested runs, served model mismatch, handoff, held transfer", async ({ page, context, request, baseURL }) => {
    await seek(request, 60);
    await as(context, baseURL, "admin");
    const runId = await latestRunId(request, "claims-triage");
    const detail = page.waitForResponse((r) => r.url().includes(`/api/bff/runs/${runId}`) && r.request().method() === "GET");
    await page.goto(`/runs/${runId}`);
    await ready(page);
    // The page hydrates from the server read, then revalidates from GET /runs/{run_id}.
    expect((await detail).ok()).toBe(true);
    const tree = page.getByTestId("run-tree");
    await expect(tree.getByTestId("rt-run")).toHaveCount(4);
    await expect(tree).toContainText("served gpt-5-2025-08-07");
    const mismatch = tree.locator('[data-mismatch="true"]');
    await expect(mismatch).toHaveCount(1);
    await expect(mismatch.getByTestId("rt-model-mismatch")).toContainText("asked for gpt-5, got gpt-5-mini-2025-08-07");
    await expect(page.getByText("1 served a different model")).toBeVisible();
    await expect(tree).toContainText("Handoff to");
    await expect(tree.getByTestId("rt-discovered")).toContainText("awaiting confirmation");
    await expect(page.getByTestId("run-truncated")).toHaveCount(0);
    await expect(tree.locator('[data-gate="held"]')).toContainText("Held for a person");
    await tree.getByTestId("rt-held-link").click();
    await expect(page).toHaveURL(/\/held-actions\//);
  });

  test("the API's run detail has the documented shape and the list honours its filters", async ({ request }) => {
    await seek(request, 60);
    const runId = await latestRunId(request, "claims-triage");
    const detail = (await (await request.get(`/api/bff/runs/${runId}`, { headers: ADMIN })).json()) as { steps: { kind: string; tool_call?: { action_gate: { effect: string; held_action_id: string | null } | null } | null }[]; children: unknown[]; handoffs: { via: string; to_agent: string; to_agent_id: string | null }[]; truncated: boolean; run_count: number };
    expect(detail.run_count).toBe(4);
    expect(detail.truncated).toBe(false);
    expect(detail.steps.map((s) => s.kind)).toEqual(["child_run", "child_run", "tool_call", "child_run", "tool_call"]);
    expect(detail.steps.at(-1)?.tool_call?.action_gate).toMatchObject({ effect: "held" });
    expect(detail.handoffs.find((h) => h.via === "tool")).toMatchObject({ to_agent: "payout-agent" });
    expect(detail.handoffs.find((h) => h.via === "tool")?.to_agent_id).toBeTruthy();
    const id = await agentIdBySlug(request, "claims-triage");
    const errored = (await (await request.get(`/api/bff/runs?agent_id=${id}&root_only=true&status=error`, { headers: ADMIN })).json()) as { data: { status: string; parent_run_id: string | null }[] };
    expect(errored.data.length).toBeGreaterThan(0);
    expect(errored.data.every((r) => r.status === "error" && !r.parent_run_id)).toBe(true);
    expect((await request.get("/api/bff/runs?status=bogus", { headers: ADMIN })).status()).toBe(422);
    expect((await request.get("/api/bff/runs/0192aaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa", { headers: ADMIN })).status()).toBe(404);
  });

  test("the agent page lists recent runs from /runs and opens the filtered runs list", async ({ page, context, request, baseURL }) => {
    await seek(request, 60);
    await as(context, baseURL, "admin");
    await page.goto(`/agents/${await agentIdBySlug(request, "claims-triage")}`);
    await ready(page);
    await expect(page.getByTestId("run-row")).toHaveCount(2);
    await page.getByTestId("all-runs").click();
    await expect(page).toHaveURL(/\/runs\?agent_id=/);
    await expect(page.getByTestId("runs-agent-chip")).toContainText("Claims triage");
    await expect(page.getByTestId("runs-row")).toHaveCount(2);
    await page.getByTestId("runs-status").selectOption("error");
    await expect(page).toHaveURL(/status=error/);
    await expect(page.getByTestId("runs-row")).toHaveCount(1);
    await page.getByTestId("runs-scope-all").click();
    await expect(page).toHaveURL(/scope=all/);
    await expect(page.getByTestId("runs-scope-all")).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("runs-row")).toHaveCount(1);
    // Child runs too: the claims root runs plus intake and coverage (the payout child ran as another agent).
    await page.getByTestId("runs-status").selectOption("");
    await expect(page.getByTestId("runs-row")).toHaveCount(4);
    await page.getByTestId("runs-row").first().click();
    await expect(page.getByTestId("run-tree")).toBeVisible();
  });

  test("discovered agents show how and where they were first seen, and when they were confirmed", async ({ page, context, request, baseURL }) => {
    await seek(request, 130);
    await as(context, baseURL, "admin");
    const agents = (await (await request.get("/api/bff/agents?lifecycle=discovered&limit=200", { headers: ADMIN })).json()) as { data: { slug: string; discovered_via: string | null; first_trace_id: string | null; confirmed_at: string | null; is_provisional: boolean }[] };
    expect(agents.data.map((a) => a.slug).sort()).toEqual(["crm-enricher", "payout-agent"]);
    expect(agents.data.find((a) => a.slug === "payout-agent")).toMatchObject({ discovered_via: "run_tree", confirmed_at: null, is_provisional: true });
    expect(agents.data.find((a) => a.slug === "payout-agent")?.first_trace_id).toMatch(/^[0-9a-f]{32}$/);
    expect(agents.data.find((a) => a.slug === "crm-enricher")).toMatchObject({ discovered_via: "span_attr", first_trace_id: null, confirmed_at: null });
    const registered = (await (await request.get("/api/bff/agents?q=claims-triage", { headers: ADMIN })).json()) as { data: { discovered_via: string | null; confirmed_at: string | null }[] };
    expect(registered.data[0]).toMatchObject({ discovered_via: null, confirmed_at: null });

    await page.goto("/fleet");
    await ready(page);
    await expect(page.getByTestId("discovered-banner")).toContainText("2 discovered agents");
    await page.goto("/discovered");
    await ready(page);
    const row = page.getByTestId("discovered-payout-agent");
    await expect(row).toHaveAttribute("data-discovery", "awaiting");
    await expect(row).toContainText("Unconfirmed");
    await expect(row.getByTestId("discovered-via")).toContainText("handoff in a run tree");
    await expect(page.getByTestId("discovered-crm-enricher").getByTestId("discovered-via")).toContainText("span attribute");
    await expect(page.getByTestId("discovered-crm-enricher").getByTestId("first-trace")).toHaveCount(0);
    await row.getByTestId("claim-payout-agent").click();
    await expect(row).toHaveAttribute("data-discovery", "confirmed");
    await expect(row).toContainText("Confirmed");
    await expect(row.getByTestId("confirmed-at")).toBeVisible();
    await expect(page.getByTestId("discovered-crm-enricher")).toContainText("Unconfirmed");
    // The first trace opens the run tree that first named the agent.
    await row.getByTestId("first-trace").click();
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}$/);
    await expect(page.getByTestId("run-tree")).toContainText("Payout agent");
    await expect(page.getByTestId("rt-discovered")).toHaveCount(0);
  });

  test("onboarding offers one-line, zero-code and gateway snippets per framework", async ({ page, context, request, baseURL }) => {
    await seek(request, 5);
    await as(context, baseURL, "admin", "sandbox");
    await page.goto("/onboarding");
    await ready(page);
    const step = page.getByTestId("instrument");
    await expect(step.getByTestId("instrument-snippet")).toContainText("sibyl.instrument()");
    await step.getByTestId("mode-zero-code").click();
    await expect(step.getByTestId("instrument-snippet")).toContainText("sibyl-run app.py");
    await step.getByTestId("fw-anthropic").click();
    await step.getByTestId("mode-gateway").click();
    await expect(page).toHaveURL(/framework=anthropic/);
    await expect(step.getByTestId("instrument-snippet")).toContainText("anthropic.Anthropic(");
    await step.getByTestId("fw-crewai").click();
    await expect(step.getByTestId("mode-gateway")).toHaveCount(0);
    await expect(step.getByTestId("instrument-snippet")).toContainText("sibyl.instrument()");
  });
});
