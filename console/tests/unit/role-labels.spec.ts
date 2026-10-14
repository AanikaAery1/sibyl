/** Chair ruling B17: `owner` is shown as "Admin", `admin` as "Workspace admin"; keys unchanged. */
import { expect, test } from "@playwright/test";
import { ROLE_LABEL, roleLabel } from "@/lib/auth/roles";

test("owner reads as Admin and admin as Workspace admin", () => {
  expect(ROLE_LABEL.owner).toBe("Admin");
  expect(ROLE_LABEL.admin).toBe("Workspace admin");
});

test("no two roles share a label", () => {
  const labels = Object.values(ROLE_LABEL);
  expect(new Set(labels).size).toBe(labels.length);
});

test("unknown role keys fall back to the key itself", () => {
  expect(roleLabel("owner")).toBe("Admin");
  expect(roleLabel("made_up")).toBe("made_up");
});
