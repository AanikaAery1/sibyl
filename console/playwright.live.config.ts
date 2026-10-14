import { defineConfig, devices } from "@playwright/test";

/**
 * Live-mode e2e against a running, seeded stack (compose: Caddy + api + worker + dex + console in
 * SIBYL_CONSOLE_MODE=live). Nothing is started here.
 *
 *   SIBYL_E2E_LIVE_URL=https://localhost:8443 SIBYL_E2E_PASSWORD=… npm run test:live
 *
 * Without SIBYL_E2E_LIVE_URL every test is skipped. Caddy's internal CA is not trusted by the
 * test browser, so HTTPS errors are ignored for this origin only (the stack is local).
 */
const baseURL = process.env.SIBYL_E2E_LIVE_URL;

export default defineConfig({
  testDir: "tests/live",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report-live" }]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
    timezoneId: "Asia/Kolkata",
    locale: "en-GB",
  },
  projects: [{ name: "live" }],
});
