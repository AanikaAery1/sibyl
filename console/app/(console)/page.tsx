import { redirect } from "next/navigation";
import { principalOrReason } from "@/lib/bff/principal";

export default async function Home() {
  const who = await principalOrReason();
  if ("reason" in who) redirect(`/login?error=${who.reason}`);
  redirect(who.principal.tenant === "sandbox" ? "/onboarding" : "/fleet");
}
