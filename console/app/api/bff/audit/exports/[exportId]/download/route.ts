/**
 * Download a finished audit export (JSONL rows + the export anchor).
 *
 * Demo: served from the demo world. Live: the API's `download_url` points at
 * `/api/v1/payloads/{ref}` on the control plane, which is bearer-only, so a browser link cannot
 * open it. The BFF reads the export, then streams the payload with the session bearer. Reading a
 * stored payload is a reveal for auditors, so the BFF states why (`X-Sibyl-Reveal-Reason`, naming
 * the export and its range) and the API writes `data.revealed`. Because that read is audited, the
 * download is refused unless the browser says it came from the console itself (Sec-Fetch-Site:
 * same-origin; a missing header is refused), so a cross-site link cannot trigger reveals.
 */
import { json } from "@/lib/bff/http";
import { apiBaseUrl, consoleMode } from "@/lib/bff/mode";
import { currentPrincipal, demoTenantOf, liveSessionToken } from "@/lib/bff/principal";
import { getWorld } from "@/lib/demo/store";

export const dynamic = "force-dynamic";

const ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const UPSTREAM_TIMEOUT_MS = 30_000;
const CONTENT_TYPES = new Set(["application/x-ndjson", "application/jsonl", "text/csv", "application/octet-stream"]);

type Ctx = { params: Promise<{ exportId: string }> };

const num = (v: unknown): number => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0);

async function live(req: Request, exportId: string): Promise<Response> {
  if (req.headers.get("sec-fetch-site") !== "same-origin") return json({ type: "https://sibyl.dev/problems/csrf_failed", title: "Download refused", status: 403, detail: "Download exports from the audit page." }, 403);
  const token = await liveSessionToken();
  if (!token) return json({ type: "https://sibyl.dev/problems/unauthenticated", title: "Sign in required", status: 401 }, 401);
  const auth = { authorization: `Bearer sibyl_sess_${token}` };
  const signal = AbortSignal.any([req.signal, AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)]);
  const meta = await fetch(`${apiBaseUrl()}/api/v1/audit/exports/${exportId}`, { headers: { accept: "application/json", ...auth }, cache: "no-store", signal }).catch(() => null);
  if (!meta) return json({ type: "https://sibyl.dev/problems/upstream_unavailable", title: "Control plane unreachable", status: 502 }, 502);
  const exp = (await meta.json().catch(() => null)) as { state?: string; payload_ref_id?: string | null; from_seq?: number; to_seq?: number; format?: string } | null;
  if (!meta.ok || !exp) return json(exp ?? { type: "https://sibyl.dev/problems/unexpected_response", title: "Unexpected response", status: meta.status }, meta.status);
  if (exp.state !== "done" || !exp.payload_ref_id || !ID_RE.test(exp.payload_ref_id)) return json({ type: "https://sibyl.dev/problems/not_found", title: "Not ready", status: 404 }, 404);
  const from = num(exp.from_seq);
  const to = num(exp.to_seq);
  const reason = `Audit evidence export ${exportId} (seq ${from}-${to}) downloaded from the console`;
  const file = await fetch(`${apiBaseUrl()}/api/v1/payloads/${exp.payload_ref_id}`, { headers: { ...auth, "x-sibyl-reveal-reason": reason }, cache: "no-store", signal }).catch(() => null);
  if (!file) return json({ type: "https://sibyl.dev/problems/upstream_unavailable", title: "Control plane unreachable", status: 502 }, 502);
  if (!file.ok || !file.body) return json(await file.json().catch(() => ({ type: "https://sibyl.dev/problems/unexpected_response", title: "Download refused", status: file.status })), file.status);
  const ext = exp.format === "csv" ? "csv" : "jsonl";
  const upstreamType = (file.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  return new Response(file.body, {
    headers: {
      "content-type": CONTENT_TYPES.has(upstreamType) ? upstreamType : ext === "csv" ? "text/csv" : "application/x-ndjson",
      "content-disposition": `attachment; filename="sibyl-audit-${from}-${to}.${ext}"`,
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
    },
  });
}

export async function GET(req: Request, ctx: Ctx): Promise<Response> {
  const { exportId } = await ctx.params;
  if (!ID_RE.test(exportId)) return json({ type: "https://sibyl.dev/problems/bad_path", title: "Bad export id", status: 400 }, 400);
  if (consoleMode() === "live") return live(req, exportId);
  const p = await currentPrincipal();
  if (!p.scopes.includes("audit:export")) return json({ type: "https://sibyl.dev/problems/forbidden", title: "Not permitted", status: 403 }, 403);
  const exp = getWorld(demoTenantOf(p.tenant)).exports.get(exportId);
  if (!exp?.body) return json({ type: "https://sibyl.dev/problems/not_found", title: "Not ready", status: 404 }, 404);
  return new Response(exp.body, {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "content-disposition": `attachment; filename="sibyl-audit-${p.tenant}-${exp.from_seq}-${exp.to_seq}.jsonl"`,
      "x-sibyl-anchor": JSON.stringify(exp.anchor ?? {}),
      "cache-control": "no-store",
    },
  });
}
