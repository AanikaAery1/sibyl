import type { Metadata } from "next";
import type { DriftPage } from "@/lib/api/monitor";
import { serverGet } from "@/lib/bff/server";
import { DRIFT_FLEET_PATH } from "@/lib/drift/view";
import { DriftFleetView } from "@/components/drift/DriftFleetView";

export const metadata: Metadata = { title: "Model drift" };

export default async function DriftPageRoute() {
  const res = await serverGet<DriftPage>(DRIFT_FLEET_PATH);
  return <DriftFleetView initial={res.data} />;
}
