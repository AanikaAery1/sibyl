#!/usr/bin/env node
/**
 * Captures every console screen in light and dark against a running console in demo mode.
 *
 *   BASE_URL=http://localhost:3000 npm run screenshots            # all screens
 *   BASE_URL=http://localhost:3100 node scripts/screenshots.mjs fleet agent   # a subset
 *
 * Each shot seeks the scripted scenario to a fixed second (paused), picks the persona and
 * tenant by cookie, opens the page, optionally runs a step (open a sheet, verify the chain),
 * then saves docs/screenshots/<name>-<light|dark>.png at 1440 px.
 *
 *   PLAIN_NAMES=1 SCHEMES=light node scripts/screenshots.mjs drift-fleet …   # <name>.png (one scheme)
 */
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const OUT = process.env.OUT_DIR ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "docs", "screenshots");
const WIDTH = Number(process.env.WIDTH ?? 1440);
const SCHEMES = (process.env.SCHEMES ?? "light,dark").split(",");
const only = process.argv.slice(2);
const PLAIN = process.env.PLAIN_NAMES === "1" && SCHEMES.length === 1;

async function post(p, body) {
  const res = await fetch(`${BASE}/api/bff${p}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-sibyl-csrf": "shot", cookie: "sibyl_csrf=shot" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${p} → ${res.status} ${await res.text()}`);
  return res.json();
}

async function get(p, cookie = "") {
  const res = await fetch(`${BASE}/api/bff${p}`, { headers: { cookie } });
  return res.json();
}

const agentId = async (slug, tenant = "meridian") => {
  const page = await get(`/agents?q=${slug}`, `sibyl_tenant=${tenant}`);
  return page.data.find((a) => a.slug === slug)?.id;
};

const incidentFor = async (slug, predicate = () => true) => {
  const id = await agentId(slug);
  const page = await get(`/incidents?agent_id=${id}`);
  return page.data.find(predicate)?.id;
};

const heldFor = async (tool) => {
  const page = await get("/held-actions?limit=100", "sibyl_persona=admin");
  return page.data.find((h) => h.tool === tool)?.held_action_id;
};

const findingFor = async (kind) => {
  const page = await get(`/sentinel/findings?kind=${kind}&limit=50`, "sibyl_persona=admin");
  return page.data.at(-1)?.id;
};

/** The newest top-level run of an agent (D50 run tree, `GET /runs`). */
const latestRun = async (slug) => {
  const id = await agentId(slug);
  const page = await get(`/runs?agent_id=${id}&root_only=true&limit=1`, "sibyl_persona=admin");
  return page.data[0]?.run_id;
};

const monitorNamed = async (name) => {
  const page = await get("/monitors?limit=100", "sibyl_persona=admin");
  return page.data.find((m) => m.name === name)?.id;
};

const externalFinding = async (kind) => {
  const page = await get(`/findings?source=external&kind=${kind}&limit=50`, "sibyl_persona=admin");
  return page.data[0]?.id;
};

const policyNamed = async (name) => {
  const page = await get("/action-policies?limit=200", "sibyl_persona=admin");
  return page.data.find((p) => p.name === name && p.state === "approved")?.id;
};

/** name → { t, persona, tenant, url(), step?(page) } */
const SHOTS = {
  "held-actions": { t: 120, persona: "operator", url: async () => "/held-actions" },
  "held-action-detail": {
    t: 120,
    persona: "admin",
    url: async () => `/held-actions/${await heldFor("payments.transfer")}`,
    step: async (page) => {
      // The agent acted for the Platform Admin: after step-up, the API refuses (409 self_approval).
      await page.getByLabel("Decision reason").fill("Payee verified against claim CLM-204871.");
      await page.getByTestId("held-approve").click();
      await page.getByTestId("step-up-confirm").click();
      await page.getByTestId("held-error").waitFor();
      await page.waitForTimeout(400);
    },
  },
  "action-policies": { t: 120, persona: "admin", url: async () => "/action-policies" },
  "action-policy-editor": { t: 120, persona: "admin", url: async () => `/action-policies/new?from=${await policyNamed("Claims payouts")}` },
  "action-policy-simulate": {
    t: 120,
    persona: "admin",
    url: async () => `/action-policies/${await policyNamed("Claims payouts")}?tab=simulate`,
    step: async (page) => {
      await page.getByRole("button", { name: "transfer-limit" }).click();
      await page.getByTestId("sim-result").waitFor();
      await page.waitForTimeout(400);
    },
  },
  "drift-fleet": { t: 130, persona: "admin", url: async () => "/drift" },
  "drift-agent": {
    t: 130,
    persona: "admin",
    url: async () => `/agents/${await agentId("route-optimizer")}`,
    step: async (page) => {
      await page.getByTestId("feature-table").first().waitFor();
    },
  },
  "sentinel-findings": { t: 130, persona: "operator", url: async () => "/sentinel" },
  "sentinel-finding": { t: 130, persona: "admin", url: async () => `/sentinel/${await findingFor("held_action_review")}` },
  "sentinel-settings": { t: 130, persona: "admin", url: async () => "/settings/sentinel" },
  // Wave 4: external monitors (D53) and their findings next to Sentinel's.
  monitors: { t: 130, persona: "admin", url: async () => "/monitors" },
  "monitor-detail": { t: 130, persona: "admin", url: async () => `/monitors/${await monitorNamed("PagerDuty bridge")}` },
  "monitor-register": {
    t: 130,
    persona: "admin",
    url: async () => "/monitors",
    step: async (page) => {
      await page.getByTestId("monitor-register-open").click();
      await page.getByLabel("Name").fill("Gemini cost watcher");
      await page.getByTestId("mon-kind-api").click();
      await page.getByLabel("Reason").fill("Daily spend review by the finance team's Gemini agent.");
      await page.getByTestId("monitor-register-submit").click();
      await page.getByTestId("monitor-created").waitFor();
      await page.waitForTimeout(500);
    },
    clip: "monitor-created",
  },
  "findings-external": { t: 130, persona: "operator", url: async () => "/sentinel?source=external" },
  "finding-external": { t: 130, persona: "admin", url: async () => `/sentinel/${await externalFinding("held_action_review")}` },
  "held-action-monitors": { t: 130, persona: "operator", url: async () => `/held-actions/${await heldFor("payments.transfer")}` },
  "onboarding-instrument": { t: 10, persona: "admin", tenant: "sandbox", url: async () => "/onboarding?framework=langchain&mode=one-line", clip: "instrument" },
  "run-tree": { t: 130, persona: "admin", url: async () => `/runs/${await latestRun("claims-triage")}` },
  "discovered-agents": { t: 130, persona: "admin", url: async () => "/discovered" },
  runs: { t: 130, persona: "admin", url: async () => `/runs?agent_id=${await agentId("claims-triage")}&scope=all` },
  "audit-actions": { t: 120, persona: "auditor", url: async () => "/audit?action=action" },
  fleet: { t: 75, persona: "admin", url: async () => "/fleet" },
  "fleet-outage": { t: 38, persona: "admin", url: async () => "/fleet" },
  "fleet-list": { t: 75, persona: "admin", url: async () => "/fleet?view=list" },
  agent: { t: 38, persona: "admin", url: async () => `/agents/${await agentId("claims-triage")}` },
  "agent-held": { t: 75, persona: "admin", url: async () => `/agents/${await agentId("kyc-verifier")}` },
  incidents: { t: 215, persona: "operator", url: async () => "/incidents" },
  "incident-failover": { t: 75, persona: "admin", url: async () => `/incidents/${await incidentFor("claims-triage")}` },
  "incident-approval": { t: 215, persona: "operator", url: async () => `/incidents/${await incidentFor("quote-assistant", (i) => i.state === "waiting_approval")}` },
  queue: { t: 80, persona: "operator", url: async () => "/queue" },
  alerts: { t: 75, persona: "operator", url: async () => "/alerts" },
  "alerts-unverdicted": { t: 75, persona: "operator", url: async () => "/alerts?view=unverdicted" },
  audit: {
    t: 80,
    persona: "auditor",
    url: async () => "/audit",
    step: async (page) => {
      await page.getByTestId("verify-chain").click();
      await page.getByTestId("verify-result").waitFor();
    },
  },
  "audit-decision": {
    t: 80,
    persona: "auditor",
    url: async () => "/audit?action=route.changed",
    step: async (page) => {
      await page.getByTestId("audit-row").first().click();
      await page.getByTestId("decision-record").waitFor();
      await page.waitForTimeout(500);
    },
  },
  onboarding: { t: 10, persona: "admin", tenant: "sandbox", url: async () => "/onboarding" },
  settings: { t: 10, persona: "admin", url: async () => "/settings" },
  "settings-tenant-keys": { t: 10, persona: "admin", url: async () => "/settings?tab=tenant-keys" },
  "settings-members": { t: 10, persona: "admin", url: async () => "/settings?tab=members" },
  northstar: { t: 75, persona: "auditor", tenant: "northstar", url: async () => "/fleet" },
  "kill-switch": {
    t: 75,
    persona: "operator",
    url: async () => "/fleet",
    step: async (page) => {
      await page.getByTestId("kill-switch").click();
      await page.getByTestId("kill-dialog").waitFor();
      await page.waitForTimeout(500);
    },
  },
  palette: {
    t: 75,
    persona: "admin",
    url: async () => "/fleet",
    step: async (page) => {
      await page.getByTestId("open-palette").click();
      await page.getByTestId("palette").waitFor();
      await page.keyboard.type("claims");
      await page.waitForTimeout(500);
    },
  },
};

await mkdir(OUT, { recursive: true });
const browser = await chromium.launch();
const names = Object.keys(SHOTS).filter((n) => only.length === 0 || only.includes(n));
for (const name of names) {
  const shot = SHOTS[name];
  await post("/demo", { action: "seek", t: shot.t, pause: true });
  const tenant = shot.tenant ?? "meridian";
  const url = await shot.url();
  for (const scheme of SCHEMES) {
    const ctx = await browser.newContext({ viewport: { width: WIDTH, height: 900 }, colorScheme: scheme, deviceScaleFactor: 1, reducedMotion: "reduce" });
    const host = new URL(BASE).hostname;
    await ctx.addCookies([
      { name: "sibyl_persona", value: shot.persona, domain: host, path: "/" },
      { name: "sibyl_tenant", value: tenant, domain: host, path: "/" },
      { name: "sibyl_tz", value: "Asia%2FKolkata", domain: host, path: "/" },
    ]);
    const page = await ctx.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(`${BASE}${url}`, { waitUntil: "load" });
    await page.waitForTimeout(900);
    if (shot.step) await shot.step(page);
    const file = path.join(OUT, PLAIN ? `${name}.png` : `${name}-${scheme}.png`);
    // `clip`: a section's test id; the shot frames that section (with a little context) instead of the page.
    if (shot.clip) await page.getByTestId(shot.clip).first().screenshot({ path: file });
    else await page.screenshot({ path: file, fullPage: true });
    console.log(`${errors.length ? "!" : "✓"} ${file}${errors.length ? `  (${errors.join(" | ")})` : ""}`);
    await ctx.close();
  }
}
await post("/demo", { action: "reset" });
await browser.close();
