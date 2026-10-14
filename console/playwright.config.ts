import { defineConfig, devices } from "@playwright/test";

/**
 * Three projects share one production server in demo mode with a fixed scenario anchor so
 * times and scores are deterministic:
 *   e2e    — the demo flow end to end (personas, approvals, queue, verdicts, undo, kill, audit)
 *   a11y   — axe on every screen, light and dark; no serious or critical violations
 *   visual — screenshots at 320 / 768 / 1024 / 1440, light and dark
 * Tests drive one shared demo world, so they run serially.
 * Point at an already running console with PW_BASE_URL (e.g. a dev server) to skip the build.
 */
const PORT = Number(process.env.PW_PORT ?? 3210);
const external = process.env.PW_BASE_URL;
const baseURL = external ?? `http://localhost:${PORT}`;

export default defineConfig({
  testDir: "tests",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: {
    timeout: 10_000,
    toHaveScreenshot: { maxDiffPixelRatio: 0.01, animations: "disabled", caret: "hide" },
  },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  snapshotPathTemplate: "{testDir}/__screenshots__/{arg}{ext}",
  use: {
    baseURL,
    trace: "retain-on-failure",
    reducedMotion: "reduce",
    timezoneId: "Asia/Kolkata",
    locale: "en-GB",
  },
  projects: [
    { name: "e2e", testDir: "tests/e2e", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "a11y", testDir: "tests/a11y", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 900 } } },
    { name: "visual", testDir: "tests/visual", use: { ...devices["Desktop Chrome"] } },
  ],
  webServer: external
    ? undefined
    : {
        command: `npx next build && npx next start --port ${PORT}`,
        url: `http://localhost:${PORT}/healthz`,
        timeout: 300_000,
        reuseExistingServer: !process.env.CI,
        env: { SIBYL_CONSOLE_MODE: "demo", SIBYL_DEMO_ANCHOR: "2026-10-10T03:30:00Z" },
      },
});
