/** Compose health contract: `GET /healthz` → 200 "ok" (deploy/compose/docker-compose.yml). */
export const dynamic = "force-dynamic";

export function GET(): Response {
  return new Response("ok", { status: 200, headers: { "content-type": "text/plain", "cache-control": "no-store" } });
}
