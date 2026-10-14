/** /auth/me → the BFF principal in live mode (lib/bff/live-principal.ts). */
import { expect, test } from "@playwright/test";
import { principalFromMe, type MeBody } from "@/lib/bff/live-principal";

const me: MeBody = {
  user: { id: "u-1", email: "admin@demo.sibyl.example", display_name: "Platform Admin", status: "active", oidc_issuer_id: "i-1", last_login_at: null, created_at: "2026-10-11T00:00:00Z" },
  tenant: { id: "t-1", slug: "meridian", name: "Meridian Logistics" },
  memberships: [
    { id: "m-1", user_id: "u-1", role_name: "owner", scope_kind: "tenant", scope_id: null, expires_at: null, created_at: "2026-10-11T00:00:00Z" },
    { id: "m-2", user_id: "u-1", role_name: "owner", scope_kind: "agent_group", scope_id: "g-1", expires_at: null, created_at: "2026-10-11T00:00:00Z" },
  ],
  scopes: ["agents:read", "audit:read"],
  step_up_valid_until: "2026-10-11T10:05:00Z",
};

test("maps the API principal: scopes are the API's, roles de-duplicated", () => {
  const p = principalFromMe(me);
  expect(p.userId).toBe("u-1");
  expect(p.tenant).toBe("meridian");
  expect(p.tenantName).toBe("Meridian Logistics");
  expect(p.roles).toEqual(["owner"]);
  expect(p.scopes).toEqual(["agents:read", "audit:read"]);
  expect(p.stepUpUntil).toBe(Date.parse("2026-10-11T10:05:00Z"));
  expect(p.name).toBe("Platform Admin");
  expect(p.fullName).toBe("Platform Admin");
  expect(p.email).toBe("admin@demo.sibyl.example");
  expect(p.initials).toBe("PA");
  expect(p.personaId).toBe("admin");
});

test("falls back to the email when there is no display name; unknown users get no persona", () => {
  const p = principalFromMe({ ...me, user: { ...me.user, email: "ops.lead@acme.example", display_name: null }, step_up_valid_until: null });
  expect(p.name).toBe("ops.lead");
  expect(p.fullName).toBe("ops.lead@acme.example");
  expect(p.initials).toBe("O");
  expect(p.personaId).toBeNull();
  expect(p.stepUpUntil).toBeNull();
});

test("a role-word mailbox outside the demo domain is a person, not a persona", () => {
  const p = principalFromMe({ ...me, user: { ...me.user, email: "admin@acme.example", display_name: "Acme Ops" } });
  expect(p.personaId).toBeNull();
  expect(p.name).toBe("Acme");
});

test("scopes the console does not know are dropped rather than trusted blindly", () => {
  const p = principalFromMe({ ...me, scopes: ["agents:read", "not:a_scope"] });
  expect(p.scopes).toEqual(["agents:read"]);
});
