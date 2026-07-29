import { describe, expect, it } from "vitest";
import { canUseAuthenticatedScanning } from "@/lib/quota";
import type { BackendUser } from "@/lib/api";

function user(plan_id: string): BackendUser {
  return {
    id: "u1",
    email: "a@b.c",
    display_name: "A",
    email_verified: true,
    auth_provider: "password",
    org_id: "o1",
    plan_id,
    max_targets: 3,
    scans_per_month: 30,
  };
}

describe("canUseAuthenticatedScanning", () => {
  it("allows pro and agency", () => {
    expect(canUseAuthenticatedScanning(user("pro")).allowed).toBe(true);
    expect(canUseAuthenticatedScanning(user("agency")).allowed).toBe(true);
  });

  it("locks free and starter", () => {
    expect(canUseAuthenticatedScanning(user("free")).allowed).toBe(false);
    expect(canUseAuthenticatedScanning(user("starter")).allowed).toBe(false);
  });
});
