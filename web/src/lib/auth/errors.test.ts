import { describe, expect, it } from "vitest";
import {
  DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS,
  mapFirebaseAuthCode,
  mapFirebaseAuthError,
} from "@/lib/auth/errors";

describe("mapFirebaseAuthCode", () => {
  it.each([
    ["auth/email-already-in-use", "emailAlreadyInUse"],
    ["auth/weak-password", "weakPassword"],
    ["auth/wrong-password", "wrongPassword"],
    ["auth/user-not-found", "userNotFound"],
    ["auth/invalid-email", "invalidEmail"],
    ["auth/too-many-requests", "tooManyRequests"],
    [
      "auth/account-exists-with-different-credential",
      "accountExistsWithDifferentCredential",
    ],
    ["auth/popup-closed-by-user", "popupClosedByUser"],
    ["auth/popup-blocked", "popupBlocked"],
    ["auth/network-request-failed", "networkRequestFailed"],
    ["auth/invalid-credential", "invalidCredential"],
    ["auth/user-disabled", "userDisabled"],
    ["auth/unauthorized-domain", "unauthorizedDomain"],
    ["auth/internal-error", "authInternalError"],
    ["auth/something-unknown", "generic"],
  ] as const)("maps %s → %s", (code, key) => {
    expect(mapFirebaseAuthCode(code)).toBe(key);
  });
});

describe("mapFirebaseAuthError", () => {
  it("never returns raw Firebase message strings", () => {
    const result = mapFirebaseAuthError({
      code: "auth/wrong-password",
      message:
        "Firebase: Error (auth/wrong-password). [THIS MUST NOT LEAK TO UI]",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errorKey).toBe("wrongPassword");
    expect(JSON.stringify(result)).not.toContain("MUST NOT LEAK");
  });

  it("attaches cooldownSeconds for rate-limit errors", () => {
    const result = mapFirebaseAuthError({
      code: "auth/too-many-requests",
      message: "Firebase: Too many requests",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errorKey).toBe("tooManyRequests");
    expect(result.cooldownSeconds).toBe(DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS);
  });

  it("maps account-exists-with-different-credential clearly", () => {
    const result = mapFirebaseAuthError({
      code: "auth/account-exists-with-different-credential",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errorKey).toBe("accountExistsWithDifferentCredential");
  });
});
