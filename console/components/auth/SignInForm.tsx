"use client";
/**
 * Tenant-first sign-in form. Submitted as a top-level navigation rather than a form submission:
 * the console's CSP has `form-action 'self'`, which browsers apply to the whole redirect chain,
 * so a form post would be blocked at the hop to a cross-origin identity provider (any real
 * enterprise IdP; dex behind Caddy happens to be same-origin). The plain GET form remains the
 * no-JavaScript fallback for same-origin IdPs.
 */
import { useState, type FormEvent } from "react";

const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

export function SignInForm({ tenant, returnTo, invalid }: { tenant: string; returnTo: string; invalid: boolean }) {
  const [value, setValue] = useState(tenant);
  const [hint, setHint] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (e: FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    const slug = value.trim().toLowerCase();
    if (!SLUG_RE.test(slug)) {
      setHint("Workspace names use lowercase letters, numbers and hyphens.");
      return;
    }
    setBusy(true);
    // A full navigation (not router.push): the target is a route handler that redirects to the IdP.
    const start = `/api/bff/auth/login?${new URLSearchParams({ tenant: slug, return_to: returnTo }).toString()}`;
    window.location.assign(new URL(start, window.location.origin).href);
  };

  return (
    <form method="get" action="/api/bff/auth/login" onSubmit={submit} data-testid="signin-form" noValidate>
      <input type="hidden" name="return_to" value={returnTo} />
      <div className="field">
        <label htmlFor="tenant">Workspace</label>
        <input
          id="tenant"
          name="tenant"
          className="input"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setHint(null);
          }}
          required
          autoFocus
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoComplete="organization"
          placeholder="meridian"
          aria-describedby="tenant-hint"
          aria-invalid={invalid || hint ? true : undefined}
          data-testid="signin-tenant"
        />
        {hint ? (
          <span id="tenant-hint" className="error" role="alert">
            {hint}
          </span>
        ) : (
          <span id="tenant-hint" className="hint">
            Lowercase letters, numbers and hyphens, as your administrator gave it to you.
          </span>
        )}
      </div>
      <button type="submit" className="btn btn-primary btn-lg" disabled={busy} data-testid="signin-continue">
        {busy ? <span className="spinner" aria-hidden /> : null}
        {busy ? "Opening your sign-in…" : "Continue"}
      </button>
    </form>
  );
}
