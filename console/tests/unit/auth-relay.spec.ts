/** Login / step-up / logout relay helpers (lib/bff/auth-relay.ts). */
import { expect, test } from "@playwright/test";
import { loginErrorMessage, loginUpstreamUrl, relayRedirect, relayableCookie, relayableLocation, safeReturnTo, tenantSlugOk } from "@/lib/bff/auth-relay";

test("tenant slugs follow the API pattern", () => {
  expect(tenantSlugOk("meridian")).toBe(true);
  expect(tenantSlugOk("north-star2")).toBe(true);
  expect(tenantSlugOk("M")).toBe(false);
  expect(tenantSlugOk("-bad")).toBe(false);
  expect(tenantSlugOk("a/b")).toBe(false);
  expect(tenantSlugOk("")).toBe(false);
  expect(tenantSlugOk(undefined)).toBe(false);
});

test("return_to only keeps same-origin absolute paths, never the login screen itself", () => {
  expect(safeReturnTo("/fleet?view=list")).toBe("/fleet?view=list");
  expect(safeReturnTo("//evil.example/x")).toBe("/");
  expect(safeReturnTo("https://evil.example")).toBe("/");
  expect(safeReturnTo("/\\evil")).toBe("/");
  expect(safeReturnTo("/ok\nbad")).toBe("/");
  expect(safeReturnTo(null)).toBe("/");
  expect(safeReturnTo("/login?x=1")).toBe("/");
});

test("the upstream login URL is tenant-first and encodes return_to", () => {
  expect(loginUpstreamUrl("https://api.test", "meridian", "/agents/a1?x=1")).toBe("https://api.test/api/v1/auth/login?tenant=meridian&return_to=%2Fagents%2Fa1%3Fx%3D1");
});

test("a 302 from the API is relayed with its Set-Cookie headers", () => {
  const headers = new Headers();
  headers.set("location", "https://idp.test/auth?state=s");
  headers.append("set-cookie", "__Host-sibyl_oidc_state=abc; Path=/; Secure; HttpOnly; SameSite=lax");
  const out = relayRedirect(new Response(null, { status: 302, headers }), null);
  expect(out).toEqual({ ok: true, location: "https://idp.test/auth?state=s", cookies: ["__Host-sibyl_oidc_state=abc; Path=/; Secure; HttpOnly; SameSite=lax"] });
});

test("anything but a redirect with a Location is a failure carrying the problem code", () => {
  const notRedirect = relayRedirect(new Response(null, { status: 404 }), { type: "https://sibyl.dev/problems/tenant_unknown" });
  expect(notRedirect).toEqual({ ok: false, code: "tenant_unknown", status: 404 });
  const noLocation = relayRedirect(new Response(null, { status: 302 }), null);
  expect(noLocation).toEqual({ ok: false, code: "unexpected_response", status: 302 });
});

test("only the API's own __Host- cookies are relayed", () => {
  expect(relayableCookie("__Host-sibyl_session=abc; Path=/; Secure; HttpOnly; SameSite=lax")).toBe(true);
  expect(relayableCookie("__Host-sibyl_session=; Max-Age=0; Path=/; Secure; HttpOnly")).toBe(true);
  expect(relayableCookie("sibyl_persona=admin; Path=/; Secure")).toBe(false);
  expect(relayableCookie("__Host-sibyl_session=abc; Path=/; HttpOnly")).toBe(false);
  expect(relayableCookie("__Host-sibyl_session=abc; Path=/; Secure; Domain=example.com")).toBe(false);
  const headers = new Headers({ location: "https://idp.test/a" });
  headers.append("set-cookie", "__Host-sibyl_oidc_state=s; Path=/; Secure; HttpOnly");
  headers.append("set-cookie", "tracker=1; Path=/");
  const out = relayRedirect(new Response(null, { status: 302, headers }), null);
  expect(out.ok && out.cookies).toEqual(["__Host-sibyl_oidc_state=s; Path=/; Secure; HttpOnly"]);
});

test("redirects only go to http(s) URLs or same-origin paths", () => {
  expect(relayableLocation("https://idp.test/auth")).toBe(true);
  expect(relayableLocation("/auth/done?status=ok")).toBe(true);
  expect(relayableLocation("//evil.example")).toBe(false);
  expect(relayableLocation("javascript:alert(1)")).toBe(false);
  expect(relayRedirect(new Response(null, { status: 302, headers: { location: "javascript:alert(1)" } }), null)).toEqual({ ok: false, code: "unexpected_response", status: 302 });
});

test("login errors read as sentences", () => {
  expect(loginErrorMessage("tenant_unknown")).toMatch(/workspace/i);
  expect(loginErrorMessage("oidc_failed")).toMatch(/sign-in/i);
  expect(loginErrorMessage("whatever")).toMatch(/try again/i);
  expect(loginErrorMessage(null)).toBeNull();
});
