/**
 * The console's own origin as the browser sees it (pure; unit-tested). Behind Caddy the Node
 * server speaks plain HTTP, so Next's `nextUrl.origin` says `http://host` while the browser sends
 * `Origin: https://host`; Caddy's X-Forwarded-Proto/-Host say what the browser used. Accepting
 * that origin is safe: a cross-site page cannot set these headers on the victim's request, and
 * an attacker's own forged headers only describe their own request.
 */
const PROTO_RE = /^https?$/;
const HOST_RE = /^[A-Za-z0-9.-]+(:\d{1,5})?$/;

export interface ForwardedHeaders {
  proto: string | null;
  host: string | null;
  forwardedHost: string | null;
}

export function consoleOrigins(nextOrigin: string, h: ForwardedHeaders): string[] {
  const out = new Set([nextOrigin]);
  const proto = h.proto?.split(",")[0]?.trim().toLowerCase() ?? "";
  const host = (h.forwardedHost ?? h.host)?.split(",")[0]?.trim() ?? "";
  if (PROTO_RE.test(proto) && HOST_RE.test(host)) out.add(`${proto}://${host}`);
  return [...out];
}

export function isHttps(nextProtocol: string, proto: string | null): boolean {
  return nextProtocol === "https:" || proto?.split(",")[0]?.trim().toLowerCase() === "https";
}
