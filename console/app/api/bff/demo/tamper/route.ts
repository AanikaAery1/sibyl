/** Demo-only: verify a copy of the audit chain with one byte changed (shows a break). */
import { json } from "@/lib/bff/http";
import { consoleMode } from "@/lib/bff/mode";
import { currentPrincipal, demoTenantOf } from "@/lib/bff/principal";
import { demoTamperCheck } from "@/lib/demo/handlers";
import { getWorld } from "@/lib/demo/store";

export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  if (consoleMode() !== "demo") return json({ type: "https://sibyl.dev/problems/live_mode", title: "Demo only", status: 409 }, 409);
  const p = await currentPrincipal();
  if (!p.scopes.includes("audit:verify")) return json({ type: "https://sibyl.dev/problems/forbidden", title: "Not permitted", status: 403 }, 403);
  return json(demoTamperCheck(getWorld(demoTenantOf(p.tenant))));
}
