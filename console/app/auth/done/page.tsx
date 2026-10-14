/** Where a live step-up returns. In the popup it reports to the console tab and closes. */
import type { Metadata } from "next";
import { BrandMark } from "@/components/auth/BrandMark";
import { StepUpDone } from "@/components/auth/StepUpDone";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Confirmed" };

type Search = Promise<Record<string, string | string[] | undefined>>;

export default async function StepUpDonePage({ searchParams }: { searchParams: Search }) {
  const q = await searchParams;
  const status = typeof q.status === "string" ? q.status : "ok";
  const code = typeof q.code === "string" ? q.code : null;
  return (
    <main className="signin">
      <section className="panel signin-card" aria-labelledby="done-title">
        <BrandMark />
        <StepUpDone status={status} code={code} />
      </section>
    </main>
  );
}
