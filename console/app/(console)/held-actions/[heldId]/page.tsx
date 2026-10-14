import type { Metadata } from "next";
import type { ApiHeldAction } from "@/lib/api/action-gate";
import { serverGet } from "@/lib/bff/server";
import { HeldActionDetail } from "@/components/actions/HeldActionDetail";

export const metadata: Metadata = { title: "Held action" };

export default async function HeldActionPage({ params }: { params: Promise<{ heldId: string }> }) {
  const { heldId } = await params;
  const res = await serverGet<ApiHeldAction>(`/held-actions/${encodeURIComponent(heldId)}`);
  return <HeldActionDetail id={heldId} initial={res.data} />;
}
