/**
 * Live-mode routing, kept free of Next.js and server-only imports so it is unit-testable:
 * which BFF request goes to the control-plane API, which falls back to demo data, and what is
 * forwarded upstream.
 *
 * Rules:
 *  1. Every live request needs the console session (`__Host-sibyl_session`); without it the BFF
 *     answers 401 itself and never calls the API. The cookie value is forwarded as
 *     `Authorization: Bearer sibyl_sess_<value>` (API §2.1); the session decides the tenant.
 *  2. Only contract paths are forwarded (lib/bff/contract.ts): anything else is a 404 here, so
 *     no `..` segment or non-contract API path ever reaches the control plane.
 *  3. Reads on routes listed in SIBYL_DEMO_ROUTES are served by the demo engine. Writes on them
 *     are refused (409 demo_route_readonly): live mode never fakes a change.
 *  4. A GET the API answers with 501 falls back to demo data (labelled `demo-fallback`).
 *     A mutation answered with 501 is never faked: it stays a 501 the UI can explain.
 *  5. Hand-typed spec paths not yet in the OpenAPI document (contract.ts PENDING_PATHS) are
 *     forwarded too. Until the API mounts them it answers 404, so on those paths a 404 is read as
 *     "not implemented yet": a GET falls back to demo data and a write becomes the same 501
 *     "not available yet". Once the contract has the paths, only the 501 rule applies.
 *  6. Everything else (problems included) passes through unchanged.
 */
import { ProblemError } from "@/lib/api/problem";
import type { DataSource } from "./mode";

export interface LiveRequest {
  method: string;
  path: string;
  search?: string;
  body?: unknown;
  idempotencyKey?: string | null;
  ifMatch?: string | null;
}

export interface BffResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
  source: DataSource;
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface LiveDeps {
  apiBase: string;
  token: string | null;
  forcedDemo: readonly string[];
  /** The contract template a path matches, or null when the BFF must not forward it. */
  contractTemplateOf: (path: string) => string | null;
  /** True when the template is a spec path the OpenAPI document does not have yet (rule 5). */
  isPendingTemplate?: (template: string | null) => boolean;
  /** The demo engine's template for a path (forced-demo matching). */
  templateOf: (path: string) => string | null;
  hasDemoRoute: (path: string, method: string) => boolean;
  runDemo: () => BffResponse | Promise<BffResponse>;
  fetch: FetchLike;
}

const UPSTREAM_TIMEOUT_MS = 10_000;
// No `location`: a 3xx relayed to a browser fetch would be followed as a redirect.
const PASS_HEADERS = ["etag", "x-sibyl-audit-receipt", "idempotency-replayed", "content-type", "retry-after", "x-request-id"] as const;
const TOKEN_RE = /^[A-Za-z0-9_-]{32,128}$/;

/** The session cookie value as the API mints it (token_urlsafe(32)); anything else is no session. */
export function sessionTokenOk(token: string | null | undefined): token is string {
  return typeof token === "string" && TOKEN_RE.test(token);
}

/** Entries are path templates matched on segment boundaries ("/incidents" covers "/incidents/{id}/actions"). */
export function forcedDemoMatch(template: string | null, forced: readonly string[]): boolean {
  if (!template) return false;
  return forced.map((f) => f.trim()).some((f) => f !== "" && (template === f || template.startsWith(`${f}/`)));
}

function problem(err: ProblemError, source: DataSource = "live"): BffResponse {
  return { status: err.status, body: err.problem, headers: { "content-type": "application/problem+json" }, source };
}

function upstreamHeaders(req: LiveRequest, token: string): Record<string, string> {
  const headers: Record<string, string> = { accept: "application/json", authorization: `Bearer sibyl_sess_${token}` };
  if (req.idempotencyKey) headers["idempotency-key"] = req.idempotencyKey;
  if (req.ifMatch) headers["if-match"] = req.ifMatch;
  if (req.body !== undefined) headers["content-type"] = "application/json";
  return headers;
}

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return new ProblemError(res.status, "unexpected_response", "Unexpected response", "The control plane answered with something that is not JSON.").problem;
  }
}

function notAvailableYet(body: unknown, method: string, path: string): unknown {
  const detail = `${method} ${path} is not available on this control plane yet, so nothing was changed. Reads on this route show demo data.`;
  return body && typeof body === "object" ? { ...body, detail } : new ProblemError(501, "not_implemented", "Not implemented", detail).problem;
}

export async function runLive(req: LiveRequest, deps: LiveDeps): Promise<BffResponse> {
  if (!sessionTokenOk(deps.token)) {
    return problem(new ProblemError(401, "unauthenticated", "Sign in required", "Your console session is missing or has expired. Sign in again."));
  }
  const template = deps.contractTemplateOf(req.path);
  if (!template) {
    return problem(new ProblemError(404, "not_found", "Not found", "That is not a route the console serves."));
  }
  if (forcedDemoMatch(deps.templateOf(req.path), deps.forcedDemo)) {
    if (req.method !== "GET") {
      return problem(new ProblemError(409, "demo_route_readonly", "Demo data is read-only", `${req.path} is served from demo data on this console (SIBYL_DEMO_ROUTES), so nothing was changed.`), "demo-fallback");
    }
    if (deps.hasDemoRoute(req.path, req.method)) return deps.runDemo();
  }

  let res: Response;
  try {
    res = await deps.fetch(`${deps.apiBase}/api/v1${req.path}${req.search ?? ""}`, {
      method: req.method,
      headers: upstreamHeaders(req, deps.token),
      body: req.body === undefined ? undefined : JSON.stringify(req.body),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
  } catch {
    return problem(new ProblemError(502, "upstream_unavailable", "Control plane unreachable", "The console could not reach the Sibyl API. Check SIBYL_API_URL and that the api service is healthy."));
  }

  // Rule 5: an unmounted spec path answers 404; treat it exactly like a 501.
  const unmounted = res.status === 404 && (deps.isPendingTemplate?.(template) ?? false);
  const notImplemented = res.status === 501 || unmounted;
  if (notImplemented && req.method === "GET" && deps.hasDemoRoute(req.path, req.method)) return deps.runDemo();

  let body = await readBody(res);
  let status = res.status;
  if (notImplemented && req.method !== "GET") {
    body = notAvailableYet(unmounted ? null : body, req.method, req.path);
    status = 501;
  }
  const headers: Record<string, string> = {};
  for (const name of PASS_HEADERS) {
    const v = res.headers.get(name);
    if (v) headers[name] = v;
  }
  if (unmounted) headers["content-type"] = "application/problem+json";
  return { status, body, headers, source: "live" };
}
