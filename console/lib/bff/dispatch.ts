/**
 * The BFF core: one function used by route handlers (browser → /api/bff/*) and by server
 * components (in-process, no HTTP hop) so first paint and live refreshes see the same data.
 * Demo mode runs the demo engine; live mode is lib/bff/live.ts (routing rules documented there).
 */
import "server-only";
import { ProblemError } from "@/lib/api/problem";
import { demoHandle, hasDemoRoute, matchRoute } from "@/lib/demo/handlers";
import { demoNow, getWorld } from "@/lib/demo/store";
import { appendAudit } from "@/lib/demo/world";
import { contractTemplate, isPendingTemplate } from "./contract";
import { runLive, type BffResponse } from "./live";
import { apiBaseUrl, consoleMode, forcedDemoRoutes, type DataSource } from "./mode";
import type { BffPrincipal } from "./principal-types";
import { LiveAuthError, demoTenantOf, liveSessionToken } from "./principal";

export type { BffResponse } from "./live";

export interface BffRequest {
  method: string;
  path: string;
  search?: string;
  body?: unknown;
  idempotencyKey?: string | null;
  ifMatch?: string | null;
  /** Resolved lazily: a live passthrough never needs it, only demo data does. */
  principal: () => Promise<BffPrincipal>;
}

const IDEMPOTENT_METHODS = new Set(["POST"]);

function problemResponse(err: ProblemError, source: DataSource): BffResponse {
  return { status: err.status, body: err.problem, headers: { "content-type": "application/problem+json" }, source };
}

function runDemo(req: BffRequest, principal: BffPrincipal, source: DataSource): BffResponse {
  const w = getWorld(demoTenantOf(principal.tenant));
  const t = demoNow();
  const idemKey = req.idempotencyKey ? `${principal.userId}|${req.method}|${req.path}|${req.idempotencyKey}` : null;
  if (IDEMPOTENT_METHODS.has(req.method) && idemKey) {
    const prior = w.idempotency.get(idemKey);
    if (prior) return { status: prior.status, body: prior.body, headers: { "idempotency-replayed": "true" }, source };
  }
  try {
    const out = demoHandle({ method: req.method, query: new URLSearchParams(req.search ?? ""), body: req.body, principal, w, t, ifMatch: req.ifMatch ?? null }, req.path);
    if (IDEMPOTENT_METHODS.has(req.method) && idemKey && out.status < 300) w.idempotency.set(idemKey, { status: out.status, body: out.body });
    // A receipt only exists for the demo's own chain; never dress fallback data up as a real one.
    const receipt = req.method !== "GET" && source === "demo" ? w.audit.at(-1) : undefined;
    return {
      status: out.status,
      body: out.body,
      headers: { ...(out.headers ?? {}), "x-sibyl-now": String(t), ...(receipt ? { "x-sibyl-audit-receipt": `${w.slug}:${receipt.seq}:${receipt.hash.slice(0, 16)}` } : {}) },
      source,
    };
  } catch (err) {
    if (err instanceof ProblemError) {
      if (err.status === 403 && err.code === "forbidden") {
        appendAudit(w, { action: "access.denied", actor_type: "human", actor_id: principal.userId, resource_type: "route", resource_ref: `${req.method} ${req.path}`, detail: { required_scope: err.problem.required_scope ?? null }, severity: "warning" }, t);
      }
      return problemResponse(err, source);
    }
    throw err;
  }
}

async function demoFallback(req: BffRequest): Promise<BffResponse> {
  try {
    return runDemo(req, await req.principal(), "demo-fallback");
  } catch (err) {
    if (err instanceof LiveAuthError) {
      const status = err.code === "unauthenticated" ? 401 : 502;
      return problemResponse(new ProblemError(status, err.code, status === 401 ? "Sign in required" : "Control plane unreachable"), "live");
    }
    throw err;
  }
}

export async function dispatch(req: BffRequest): Promise<BffResponse> {
  if (consoleMode() !== "live") return runDemo(req, await req.principal(), "demo");
  return runLive(req, {
    apiBase: apiBaseUrl(),
    token: await liveSessionToken(),
    forcedDemo: forcedDemoRoutes(),
    contractTemplateOf: contractTemplate,
    isPendingTemplate,
    templateOf: (path) => matchRoute(path)?.template ?? null,
    hasDemoRoute,
    runDemo: () => demoFallback(req),
    fetch: (url, init) => fetch(url, init),
  });
}
