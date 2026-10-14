import { defineConfig } from "@playwright/test";

/**
 * Unit tests for the BFF's pure modules (live/fallback routing, auth relay, live principal,
 * SSE resume, role labels). No browser and no web server: Playwright is only the TypeScript
 * test runner here, so the console needs no second test framework.
 */
export default defineConfig({
  testDir: "tests/unit",
  fullyParallel: true,
  reporter: [["list"]],
  projects: [{ name: "unit" }],
});
