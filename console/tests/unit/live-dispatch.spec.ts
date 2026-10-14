/**
 * BFF live/fallback routing (lib/bff/live.ts): which requests go to the API, which fall back to
 * demo data, and what is forwarded upstream.
 */
import { expect, test } from "@playwright/test";
import { CONTRACT_PATHS } from "@/lib/api/paths.gen";
import { PENDING_PATHS, contractTemplate, isPendingTemplate, safeSegment } from "@/lib/bff/contract";
import { forcedDemoMatch, runLive, sessionTokenOk, type BffResponse, type LiveDeps, type LiveRequest } from "@/lib/bff/live";

const TOKEN = "a".repeat(43);
const NOT_IMPLEMENTED = { type: "https://sibyl.dev/problems/not_implemented", title: "Not implemented", status: 501 };

interface Harness extends LiveDeps {
  calls: { url: string; init: RequestInit }[];
  demoCalls: () => number;
}

const DEMO_ROUTES: Record<string, string[]> = {
  "/incidents": ["GET", "POST"],
  "/incidents/{incident_id}": ["GET"],
  "/queue": ["GET"],
  "/alerts": ["GET"],
  "/agents": ["GET"],
  "/kill-switches": ["GET", "POST"],
};

function templateOf(path: string): string | null {
  if (path.startsWith("/incidents/")) return "/incidents/{incident_id}";
  return path in DEMO_ROUTES ? path : null;
}

function harness(over: Partial<LiveDeps> = {}, respond?: (url: string, init: RequestInit) => Response | Promise<Response>): Harness {
  const calls: Harness["calls"] = [];
  let demo = 0;
  return {
    apiBase: "https://api.test",
    token: TOKEN,
    forcedDemo: [],
    contractTemplateOf: contractTemplate,
    templateOf,
    hasDemoRoute: (path, method) => {
      const t = templateOf(path);
      return Boolean(t && DEMO_ROUTES[t]?.includes(method));
    },
    runDemo: (): BffResponse => {
      demo += 1;
      return { status: 200, body: { data: ["demo"] }, headers: {}, source: "demo-fallback" };
    },
    fetch: async (url, init) => {
      calls.push({ url: String(url), init });
      return respond ? respond(String(url), init) : Response.json({ ok: true });
    },
    ...over,
    calls,
    demoCalls: () => demo,
  };
}

const get = (path: string, search = ""): LiveRequest => ({ method: "GET", path, search });
const sentHeaders = (h: Harness, i = 0): Headers => new Headers(h.calls[i]?.init.headers);

test.describe("live passthrough", () => {
  test("forwards the session cookie as a sibyl_sess_ bearer to /api/v1<path><search>", async () => {
    const h = harness();
    const res = await runLive(get("/agents", "?limit=200"), h);
    expect(res).toMatchObject({ status: 200, source: "live" });
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0]?.url).toBe("https://api.test/api/v1/agents?limit=200");
    expect(sentHeaders(h).get("authorization")).toBe(`Bearer sibyl_sess_${TOKEN}`);
    expect(sentHeaders(h).get("accept")).toBe("application/json");
  });

  test("does not send the demo tenant header: the session decides the tenant", async () => {
    const h = harness();
    await runLive(get("/fleet/health"), h);
    expect(sentHeaders(h).has("x-sibyl-tenant")).toBe(false);
  });

  test("passes Idempotency-Key, If-Match and a JSON body on mutations, and relays ETag and the audit receipt", async () => {
    const h = harness({}, () => Response.json({ id: "a1" }, { status: 201, headers: { etag: '"7"', "x-sibyl-audit-receipt": "r1" } }));
    const res = await runLive({ method: "POST", path: "/alerts/a1/actions", body: { action: "close", verdict: "true_positive" }, idempotencyKey: "k-1", ifMatch: '"6"' }, h);
    const init = h.calls[0]?.init;
    expect(init?.method).toBe("POST");
    expect(sentHeaders(h).get("idempotency-key")).toBe("k-1");
    expect(sentHeaders(h).get("if-match")).toBe('"6"');
    expect(sentHeaders(h).get("content-type")).toBe("application/json");
    expect(JSON.parse(String(init?.body))).toEqual({ action: "close", verdict: "true_positive" });
    expect(res.status).toBe(201);
    expect(res.headers.etag).toBe('"7"');
    expect(res.headers["x-sibyl-audit-receipt"]).toBe("r1");
  });

  test("passes problems through unchanged (403 step_up_required stays a live 403)", async () => {
    const problem = { type: "https://sibyl.dev/problems/step_up_required", title: "Step-up required", status: 403 };
    const h = harness({}, () => Response.json(problem, { status: 403, headers: { "content-type": "application/problem+json" } }));
    const res = await runLive({ method: "POST", path: "/tenant-keys/payload/rotate", body: {} }, h);
    expect(res).toMatchObject({ status: 403, source: "live", body: problem });
    expect(res.headers["content-type"]).toBe("application/problem+json");
  });

  test("204 responses carry a null body", async () => {
    const h = harness({}, () => new Response(null, { status: 204 }));
    const res = await runLive({ method: "POST", path: "/api-keys/k1/revoke", body: {} }, h);
    expect(res).toMatchObject({ status: 204, body: null, source: "live" });
  });

  test("an unreachable API is a 502 upstream_unavailable problem, never demo data", async () => {
    const h = harness({}, () => Promise.reject(new TypeError("fetch failed")));
    const res = await runLive(get("/agents"), h);
    expect(res.status).toBe(502);
    expect((res.body as { type: string }).type).toContain("upstream_unavailable");
    expect(h.demoCalls()).toBe(0);
  });

  test("non-JSON upstream bodies become an unexpected_response problem", async () => {
    const h = harness({}, () => new Response("<html>bad gateway</html>", { status: 502, headers: { "content-type": "text/html" } }));
    const res = await runLive(get("/agents"), h);
    expect(res.status).toBe(502);
    expect((res.body as { type: string }).type).toContain("unexpected_response");
  });
});

test.describe("session", () => {
  test("no session cookie: 401 unauthenticated without calling the API", async () => {
    const h = harness({ token: null });
    const res = await runLive(get("/agents"), h);
    expect(res.status).toBe(401);
    expect((res.body as { type: string }).type).toContain("unauthenticated");
    expect(h.calls).toHaveLength(0);
  });

  test("a malformed cookie value is treated as no session", async () => {
    expect(sessionTokenOk(TOKEN)).toBe(true);
    expect(sessionTokenOk("short")).toBe(false);
    expect(sessionTokenOk(`${"a".repeat(40)}\r\nx-evil: 1`)).toBe(false);
    expect(sessionTokenOk("a".repeat(200))).toBe(false);
    expect(sessionTokenOk(null)).toBe(false);
    const h = harness({ token: "bad value" });
    expect((await runLive(get("/agents"), h)).status).toBe(401);
    expect(h.calls).toHaveLength(0);
  });
});

test.describe("demo fallback", () => {
  test("a GET the API answers with 501 falls back to demo data, labelled demo-fallback", async () => {
    const h = harness({}, () => Response.json(NOT_IMPLEMENTED, { status: 501 }));
    const res = await runLive(get("/queue", "?limit=100"), h);
    expect(res.source).toBe("demo-fallback");
    expect(res.body).toEqual({ data: ["demo"] });
    expect(h.demoCalls()).toBe(1);
  });

  test("a mutation the API answers with 501 is NOT faked by the demo engine", async () => {
    const h = harness({}, () => Response.json(NOT_IMPLEMENTED, { status: 501 }));
    const res = await runLive({ method: "POST", path: "/kill-switches", body: { scope: "tenant" } }, h);
    expect(res).toMatchObject({ status: 501, source: "live" });
    expect(h.demoCalls()).toBe(0);
    expect((res.body as { detail?: string }).detail).toMatch(/not available/i);
  });

  test("a 501 with no demo implementation stays a 501", async () => {
    const h = harness({}, () => Response.json(NOT_IMPLEMENTED, { status: 501 }));
    const res = await runLive(get("/jobs/j1"), h);
    expect(res.status).toBe(501);
    expect(h.demoCalls()).toBe(0);
  });

  test("routes in SIBYL_DEMO_ROUTES serve demo reads and refuse writes, never reaching the API", async () => {
    const h = harness({ forcedDemo: ["/incidents"] });
    const read = await runLive(get("/incidents/i-1"), h);
    const write = await runLive({ method: "POST", path: "/incidents", body: {} }, h);
    expect(read.source).toBe("demo-fallback");
    expect(write.status).toBe(409);
    expect((write.body as { type: string }).type).toContain("demo_route_readonly");
    expect(h.demoCalls()).toBe(1);
    expect(h.calls).toHaveLength(0);
  });

  test("forced demo routes still need a session", async () => {
    const h = harness({ forcedDemo: ["/queue"], token: null });
    expect((await runLive(get("/queue"), h)).status).toBe(401);
    expect(h.demoCalls()).toBe(0);
  });

  test("forced-route matching is by template on segment boundaries", () => {
    expect(forcedDemoMatch("/queue", ["/queue"])).toBe(true);
    expect(forcedDemoMatch("/incidents/{incident_id}/actions", ["/incidents"])).toBe(true);
    expect(forcedDemoMatch("/incidents-archive", ["/incidents"])).toBe(false);
    expect(forcedDemoMatch("/alerts", ["/queue", " /alerts "])).toBe(true);
    expect(forcedDemoMatch("/alerts", [])).toBe(false);
    expect(forcedDemoMatch(null, ["/alerts"])).toBe(false);
  });
});

test.describe("only contract routes are forwarded", () => {
  test("`..` segments (e.g. /api/bff/%2e%2e/%2e%2e/healthz) never reach the API", async () => {
    const h = harness();
    for (const path of ["/../../healthz", "/agents/../../metrics", "/agents/..", "/agents/./health"]) {
      expect((await runLive(get(path), h)).status).toBe(404);
    }
    expect(h.calls).toHaveLength(0);
    expect(safeSegment("..")).toBe(false);
    expect(safeSegment(".")).toBe(false);
    expect(safeSegment("a.b")).toBe(true);
  });

  test("non-contract paths, auth endpoints and gateway-only policy routes are refused", async () => {
    const h = harness();
    for (const path of ["/metrics", "/docs", "/auth/me", "/auth/logout", "/policy/snapshot", "/policy/keys"]) {
      expect((await runLive(get(path), h)).status).toBe(404);
    }
    expect(h.calls).toHaveLength(0);
  });

  test("contract templates match by segment, parameters included", () => {
    expect(contractTemplate("/agents/0192a000-0000-7000-8000-0000000000a1/health/history")).toBe("/agents/{agent_id}/health/history");
    expect(contractTemplate("/blast-radius/provider/p1")).toBe("/blast-radius/{node_kind}/{node_id}");
    expect(contractTemplate("/agents/a1/nope")).toBeNull();
  });

  test("a Location header from the API is not relayed to the browser fetch", async () => {
    const h = harness({}, () => new Response(null, { status: 303, headers: { location: "https://elsewhere.example/" } }));
    const res = await runLive(get("/agents"), h);
    expect(res.headers.location).toBeUndefined();
  });
});

test.describe("Action Gate paths (in the generated contract)", () => {
  const NOT_FOUND = { type: "https://sibyl.dev/problems/not_found", title: "Not found", status: 404 };
  const AG_ROUTES: Record<string, string[]> = {
    "/held-actions": ["GET"],
    "/held-actions/{held_action_id}": ["GET"],
    "/held-actions/{held_action_id}/actions": ["POST"],
    "/action-policies": ["GET", "POST"],
    "/action-policies/{policy_id}/simulate": ["POST"],
  };
  const agHarness = (respond: (url: string) => Response): Harness =>
    harness({ isPendingTemplate, templateOf: contractTemplate, hasDemoRoute: (p, m) => Boolean(AG_ROUTES[contractTemplate(p) ?? ""]?.includes(m)) }, respond);

  test("the Action Gate paths are contract paths now: nothing is left pending", () => {
    const AG_PATHS = ["/action-policies", "/action-policies/simulate", "/action-policies/{policy_id}", "/action-policies/{policy_id}/approve", "/action-policies/{policy_id}/retire", "/action-policies/{policy_id}/simulate", "/action-summary", "/held-actions", "/held-actions/{held_action_id}", "/held-actions/{held_action_id}/actions"];
    for (const p of AG_PATHS) expect(CONTRACT_PATHS).toContain(p);
    expect(PENDING_PATHS).toEqual([]);
    expect(isPendingTemplate("/held-actions")).toBe(false);
    expect(contractTemplate("/held-actions")).toBe("/held-actions");
    // The literal draft-simulate segment wins over the {policy_id} slot.
    expect(contractTemplate("/action-policies/simulate")).toBe("/action-policies/simulate");
    expect(contractTemplate("/action-summary")).toBe("/action-summary");
    expect(contractTemplate("/held-actions/0192aaaa-0000-7000-8000-000000000001/actions")).toBe("/held-actions/{held_action_id}/actions");
    expect(contractTemplate("/action-policies/p1/simulate")).toBe("/action-policies/{policy_id}/simulate");
    expect(contractTemplate("/action-policies/p1/delete")).toBeNull();
    expect(contractTemplate("/held-actions/../tenant")).toBeNull();
  });

  test("once the contract has a spec path, a 404 on a GET is a real 404, not demo data", async () => {
    const h = agHarness(() => Response.json(NOT_FOUND, { status: 404 }));
    const res = await runLive(get("/held-actions", "?state=pending"), h);
    expect(h.calls[0]?.url).toBe("https://api.test/api/v1/held-actions?state=pending");
    expect(PENDING_PATHS.includes("/held-actions")).toBe(false);
    expect(res).toMatchObject({ status: 404, source: "live" });
    expect(h.demoCalls()).toBe(0);
  });

  test("once the contract has a spec path, a 404 on a write passes through and is never faked", async () => {
    const h = agHarness(() => Response.json(NOT_FOUND, { status: 404 }));
    const res = await runLive({ method: "POST", path: "/held-actions/h1/actions", body: { action: "approve", reason: "checked with finance" } }, h);
    expect(res).toMatchObject({ status: 404, source: "live" });
    expect(h.demoCalls()).toBe(0);
  });

  test("once the API answers, the route is live (a 501 stub still falls back on reads)", async () => {
    const live = agHarness(() => Response.json({ data: [{ id: "h1" }], next_cursor: null, has_more: false }));
    expect(await runLive(get("/held-actions"), live)).toMatchObject({ status: 200, source: "live" });
    const stub = agHarness(() => Response.json(NOT_IMPLEMENTED, { status: 501 }));
    expect((await runLive(get("/action-policies"), stub)).source).toBe("demo-fallback");
  });

  test("a 404 on a contract path is still a real 404", async () => {
    const h = agHarness(() => Response.json(NOT_FOUND, { status: 404 }));
    const res = await runLive(get("/agents/0192aaaa-0000-7000-8000-000000000001"), h);
    expect(res).toMatchObject({ status: 404, source: "live" });
    expect(h.demoCalls()).toBe(0);
  });

  test("a four-eyes 409 on a mounted route passes through unchanged", async () => {
    const selfApproval = { type: "https://sibyl.dev/problems/self_approval", title: "You requested this action", status: 409 };
    const h = agHarness(() => Response.json(selfApproval, { status: 409, headers: { "content-type": "application/problem+json" } }));
    const res = await runLive({ method: "POST", path: "/held-actions/h1/actions", body: { action: "approve", reason: "my own transfer" } }, h);
    expect(res).toMatchObject({ status: 409, body: selfApproval, source: "live" });
  });
});
