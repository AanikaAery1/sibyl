/**
 * Live e2e helpers: real tenant-first sign-in through dex, and BFF reads/writes with the signed-in
 * browser's cookies (so the API sees exactly what the console sees).
 */
import { expect, test, type Page } from "@playwright/test";

export type Persona = "admin" | "operator" | "auditor";

export const LIVE_URL = process.env.SIBYL_E2E_LIVE_URL;
const PASSWORD = process.env.SIBYL_E2E_PASSWORD ?? "";
const EMAIL_DOMAIN = process.env.SIBYL_E2E_EMAIL_DOMAIN ?? "demo.sibyl.example";

/** Skip the whole file unless a live stack was named. */
export function requireLive(): void {
  test.skip(!LIVE_URL, "SIBYL_E2E_LIVE_URL is not set; live-mode e2e needs a running, seeded stack.");
  test.skip(Boolean(LIVE_URL) && !PASSWORD, "SIBYL_E2E_PASSWORD (the dex demo persona password) is not set.");
}

/** Glass sign-in → dex local login → back on `returnTo`. */
export async function signIn(page: Page, persona: Persona, tenant = "meridian", returnTo = "/fleet"): Promise<void> {
  await page.goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
  await expect(page.getByRole("heading", { level: 1, name: "Sign in" })).toBeVisible();
  await page.getByTestId("signin-tenant").fill(tenant);
  await page.getByTestId("signin-continue").click();
  // dex's password connector form (login / password / submit-login).
  await page.locator('input[name="login"]').fill(`${persona}@${EMAIL_DOMAIN}`);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.locator('button[type="submit"]').click();
  await page.waitForURL((url) => url.pathname === returnTo.split("?")[0], { timeout: 30_000 });
  await expect(page.getByTestId("open-palette")).toBeVisible();
}

export async function bffGet<T>(page: Page, path: string): Promise<T> {
  const res = await page.request.get(`/api/bff${path}`, { headers: { accept: "application/json" } });
  expect(res.ok(), `${path}: ${res.status()} ${await res.text()}`).toBeTruthy();
  return (await res.json()) as T;
}

export interface Page_<T> {
  data: T[];
  has_more?: boolean;
  next_cursor?: string | null;
}
