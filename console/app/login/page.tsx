/**
 * Live-mode sign-in. Tenant first: the user names their workspace, the BFF starts that
 * workspace's OIDC flow at the API and the identity provider takes it from there (see
 * SignInForm for why it navigates rather than posts). Demo mode has no sign-in and skips ahead.
 */
import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { loginErrorMessage, safeReturnTo, tenantSlugOk } from "@/lib/bff/auth-relay";
import { consoleMode } from "@/lib/bff/mode";
import { principalOrReason } from "@/lib/bff/principal";
import { BrandMark } from "@/components/auth/BrandMark";
import { SignInForm } from "@/components/auth/SignInForm";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Sign in" };

type Search = Promise<Record<string, string | string[] | undefined>>;

const one = (v: string | string[] | undefined): string | null => (typeof v === "string" ? v : null);

export default async function LoginPage({ searchParams }: { searchParams: Search }) {
  const q = await searchParams;
  const returnTo = safeReturnTo(one(q.return_to));
  if (consoleMode() !== "live") redirect(returnTo === "/" ? "/fleet" : returnTo);

  const error = one(q.error);
  const switching = one(q.switch) === "1";
  if (!error && !switching) {
    const who = await principalOrReason();
    if ("principal" in who) redirect(returnTo);
  }
  const fromQuery = one(q.tenant);
  const remembered = (await cookies()).get("sibyl_last_tenant")?.value;
  const tenant = (tenantSlugOk(fromQuery) ? fromQuery : tenantSlugOk(remembered) ? remembered : null) ?? "";
  const message = loginErrorMessage(error);
  const tone = error === "signed_out" ? "info" : "failed";

  return (
    <main className="signin">
      <section className="panel signin-card" aria-labelledby="signin-title">
        <BrandMark caption="AI workforce control plane" />
        <div>
          <h1 id="signin-title" className="large-title">
            Sign in
          </h1>
          <p className="lede" style={{ fontSize: "var(--fs-body)" }}>
            Start with your workspace. Your organisation&apos;s identity provider does the rest.
          </p>
        </div>
        {message ? (
          <div className="banner" data-tone={tone} role={tone === "failed" ? "alert" : "status"} data-testid="signin-message">
            {message}
          </div>
        ) : null}
        <SignInForm tenant={tenant} returnTo={returnTo} invalid={error === "tenant_unknown" || error === "bad_tenant"} />
        <p className="signin-foot">Every sign-in and sign-out is written to your workspace&apos;s audit chain as access.login and access.logout.</p>
      </section>
    </main>
  );
}
