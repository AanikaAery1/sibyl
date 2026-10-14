import type { Metadata } from "next";
import type { SentinelConfig } from "@/lib/api/monitor";
import type { Finding, FindingKind } from "@/lib/api/external-monitors";
import type { Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { SENTINEL_CONFIG_PATH } from "@/lib/sentinel/view";
import { FINDING_KIND_LABEL, findingsFeedPath, sourceOf } from "@/lib/monitors/view";
import { FindingsView } from "@/components/sentinel/FindingsView";

export const metadata: Metadata = { title: "Sentinel" };

export default async function SentinelPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const kind = (Object.keys(FINDING_KIND_LABEL) as FindingKind[]).find((k) => k === sp.kind) ?? null;
  const source = sourceOf(typeof sp.source === "string" ? sp.source : null);
  const [findings, config] = await Promise.all([serverGet<Page<Finding>>(findingsFeedPath({ source, kind })), serverGet<SentinelConfig>(SENTINEL_CONFIG_PATH)]);
  return <FindingsView initial={findings.data} initialConfig={config.data} kind={kind} source={source} />;
}
