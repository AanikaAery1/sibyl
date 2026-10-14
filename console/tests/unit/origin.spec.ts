/** The console origin behind Caddy (lib/bff/origin.ts). */
import { expect, test } from "@playwright/test";
import { consoleOrigins, isHttps } from "@/lib/bff/origin";

test("behind Caddy the browser's https origin is accepted alongside Next's own", () => {
  expect(consoleOrigins("http://localhost:8443", { proto: "https", host: "localhost:8443", forwardedHost: null })).toEqual(["http://localhost:8443", "https://localhost:8443"]);
});

test("without forwarding headers only Next's origin counts", () => {
  expect(consoleOrigins("http://localhost:3000", { proto: null, host: "localhost:3000", forwardedHost: null })).toEqual(["http://localhost:3000"]);
});

test("junk forwarding headers are ignored", () => {
  expect(consoleOrigins("http://a:1", { proto: "javascript", host: "a:1", forwardedHost: null })).toEqual(["http://a:1"]);
  expect(consoleOrigins("http://a:1", { proto: "https", host: "evil.example/x", forwardedHost: null })).toEqual(["http://a:1"]);
});

test("https is detected from the URL or X-Forwarded-Proto", () => {
  expect(isHttps("https:", null)).toBe(true);
  expect(isHttps("http:", "https")).toBe(true);
  expect(isHttps("http:", "http")).toBe(false);
});
