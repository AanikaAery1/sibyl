#!/usr/bin/env node
/**
 * Performance budgets (user web rules, "app page"): JS < 300 KB and CSS < 50 KB transferred
 * (compressed), LCP < 2.5 s, CLS < 0.1, FCP < 1.5 s, measured in Chromium against a running
 * production server:   npm run build && npm start &  BASE_URL=http://localhost:3000 npm run test:budget
 */
import { chromium } from "@playwright/test";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
const PAGES = ["/fleet", "/incidents", "/queue", "/alerts", "/audit", "/settings"];
const BUDGET = { jsKb: 300, cssKb: 50, lcpMs: 2500, cls: 0.1, fcpMs: 1500 };

const browser = await chromium.launch();
let failed = false;
const rows = [];
for (const path of PAGES) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addCookies([{ name: "sibyl_persona", value: path === "/audit" ? "auditor" : "admin", url: BASE }]);
  const page = await ctx.newPage();
  await page.addInitScript(() => {
    window.__vitals = { lcp: 0, cls: 0 };
    new PerformanceObserver((l) => {
      for (const e of l.getEntries()) window.__vitals.lcp = e.startTime;
    }).observe({ type: "largest-contentful-paint", buffered: true });
    new PerformanceObserver((l) => {
      for (const e of l.getEntries()) if (!e.hadRecentInput) window.__vitals.cls += e.value;
    }).observe({ type: "layout-shift", buffered: true });
  });
  await page.goto(`${BASE}${path}`, { waitUntil: "load" });
  await page.waitForTimeout(1500);
  const m = await page.evaluate(() => {
    const res = performance.getEntriesByType("resource");
    const sum = (pred) => res.filter(pred).reduce((a, r) => a + (r.transferSize || r.encodedBodySize || 0), 0);
    const fcp = performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? 0;
    return {
      js: sum((r) => r.initiatorType === "script" || r.name.endsWith(".js")),
      css: sum((r) => r.initiatorType === "link" && r.name.includes(".css")) + sum((r) => r.initiatorType === "css"),
      fcp,
      ...window.__vitals,
    };
  });
  const row = { path, jsKb: +(m.js / 1024).toFixed(1), cssKb: +(m.css / 1024).toFixed(1), fcpMs: Math.round(m.fcp), lcpMs: Math.round(m.lcp), cls: +m.cls.toFixed(3) };
  const over = Object.entries(BUDGET).filter(([k, v]) => row[k] > v).map(([k]) => k);
  if (over.length) failed = true;
  rows.push({ ...row, status: over.length ? `over: ${over.join(",")}` : "ok" });
  await ctx.close();
}
await browser.close();
console.table(rows);
console.log(`budgets: JS < ${BUDGET.jsKb} KB, CSS < ${BUDGET.cssKb} KB, FCP < ${BUDGET.fcpMs} ms, LCP < ${BUDGET.lcpMs} ms, CLS < ${BUDGET.cls}`);
process.exit(failed ? 1 : 0);
