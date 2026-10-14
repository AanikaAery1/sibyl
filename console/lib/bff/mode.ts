/**
 * Console data mode. `demo` (default) serves deterministic fixtures and the scripted
 * scenario; `live` proxies each route to SIBYL_API_URL and falls back to demo, visibly,
 * for routes the API still answers with 501 or that are listed in SIBYL_DEMO_ROUTES.
 */
export type ConsoleMode = "demo" | "live";

/**
 * Fails closed: a production server whose SIBYL_CONSOLE_MODE is missing or misspelled runs live
 * (sign-in required), never the open demo with its pick-any-persona switcher. Demo deployments
 * say so explicitly (the console image sets SIBYL_CONSOLE_MODE=demo).
 */
export function consoleMode(): ConsoleMode {
  const v = process.env.SIBYL_CONSOLE_MODE?.trim().toLowerCase();
  if (v === "live" || v === "demo") return v;
  return process.env.NODE_ENV === "production" ? "live" : "demo";
}

export function apiBaseUrl(): string {
  return (process.env.SIBYL_API_URL ?? "http://localhost:8010").replace(/\/+$/, "");
}

/** Comma-separated path templates forced to demo even in live mode, e.g. "/queue,/alerts". */
export function forcedDemoRoutes(): string[] {
  return (process.env.SIBYL_DEMO_ROUTES ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * The `env` new API keys are minted for. The API refuses a key whose env differs from its own
 * SIBYL_ENV (compose runs `test`), so live consoles set SIBYL_KEY_ENV to match.
 */
export function keyEnv(): "live" | "test" {
  const v = (process.env.SIBYL_KEY_ENV ?? process.env.SIBYL_ENV ?? "").trim().toLowerCase();
  return v === "test" ? "test" : "live";
}

/** Real time, for live mode (demo mode runs on the scenario clock). */
export function wallClock(): number {
  return Date.now();
}

/** Response header telling the browser where the data came from. */
export const SOURCE_HEADER = "x-sibyl-console-source";
export type DataSource = "demo" | "live" | "demo-fallback";
