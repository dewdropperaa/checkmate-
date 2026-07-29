import { beforeEach, describe, expect, it, vi } from "vitest";

const createUser = vi.fn();
const signInEmail = vi.fn();
const sendVerify = vi.fn();
const sendReset = vi.fn();
const confirmReset = vi.fn();
const verifyReset = vi.fn();
const signInPopup = vi.fn();
const fetchMethods = vi.fn();
const signOutMock = vi.fn();

vi.mock("@/lib/firebase", () => ({
  getFirebaseAuth: () => ({ name: "mock-auth" }),
}));

vi.mock("firebase/auth", () => ({
  GoogleAuthProvider: class {
    setCustomParameters() {
      /* no-op */
    }
  },
  createUserWithEmailAndPassword: (...args: unknown[]) => createUser(...args),
  signInWithEmailAndPassword: (...args: unknown[]) => signInEmail(...args),
  sendEmailVerification: (...args: unknown[]) => sendVerify(...args),
  sendPasswordResetEmail: (...args: unknown[]) => sendReset(...args),
  confirmPasswordReset: (...args: unknown[]) => confirmReset(...args),
  verifyPasswordResetCode: (...args: unknown[]) => verifyReset(...args),
  fetchSignInMethodsForEmail: (...args: unknown[]) => fetchMethods(...args),
  signInWithPopup: (...args: unknown[]) => signInPopup(...args),
  signOut: (...args: unknown[]) => signOutMock(...args),
}));

describe("auth helpers (mocked Firebase SDK)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("signUpWithEmail sends verification and returns check-inbox state", async () => {
    const { signUpWithEmail } = await import("@/lib/auth/auth");
    createUser.mockResolvedValue({
      user: { uid: "u1", email: "a@b.com", emailVerified: false },
    });
    sendVerify.mockResolvedValue(undefined);

    const result = await signUpWithEmail("a@b.com", "secret12");
    expect(sendVerify).toHaveBeenCalled();
    expect(result).toEqual({
      ok: true,
      uid: "u1",
      email: "a@b.com",
      needsEmailVerification: true,
    });
  });

  it("signInWithEmail blocks unverified users and resends verification", async () => {
    const { signInWithEmail } = await import("@/lib/auth/auth");
    signInEmail.mockResolvedValue({
      user: { uid: "u1", email: "a@b.com", emailVerified: false },
    });
    sendVerify.mockResolvedValue(undefined);
    signOutMock.mockResolvedValue(undefined);

    const result = await signInWithEmail("a@b.com", "secret12");
    expect(sendVerify).toHaveBeenCalled();
    expect(signOutMock).toHaveBeenCalled();
    expect(result).toEqual({
      ok: true,
      uid: "u1",
      email: "a@b.com",
      needsEmailVerification: true,
    });
  });

  it("signInWithEmail allows verified users through", async () => {
    const { signInWithEmail } = await import("@/lib/auth/auth");
    signInEmail.mockResolvedValue({
      user: { uid: "u1", email: "a@b.com", emailVerified: true },
    });

    const result = await signInWithEmail("a@b.com", "secret12");
    expect(sendVerify).not.toHaveBeenCalled();
    expect(signOutMock).not.toHaveBeenCalled();
    expect(result).toEqual({
      ok: true,
      uid: "u1",
      email: "a@b.com",
    });
  });

  it("duplicate email signup maps to emailAlreadyInUse", async () => {
    const { signUpWithEmail } = await import("@/lib/auth/auth");
    createUser.mockRejectedValue({ code: "auth/email-already-in-use" });

    const result = await signUpWithEmail("a@b.com", "secret12");
    expect(result).toMatchObject({
      ok: false,
      errorKey: "emailAlreadyInUse",
    });
  });

  it("Google sign-in success returns uid", async () => {
    const { signInWithGoogle } = await import("@/lib/auth/auth");
    signInPopup.mockResolvedValue({
      user: { uid: "g1", email: "g@b.com", emailVerified: true },
    });

    const result = await signInWithGoogle();
    expect(result).toEqual({
      ok: true,
      uid: "g1",
      email: "g@b.com",
    });
  });

  it("Google account-exists-with-different-credential maps with actionable providers", async () => {
    const { signInWithGoogle } = await import("@/lib/auth/auth");
    signInPopup.mockRejectedValue({
      code: "auth/account-exists-with-different-credential",
      customData: { email: "shared@example.com" },
    });
    fetchMethods.mockResolvedValue(["password"]);

    const result = await signInWithGoogle();
    expect(fetchMethods).toHaveBeenCalled();
    expect(result).toMatchObject({
      ok: false,
      errorKey: "accountExistsWithDifferentCredential",
      conflictEmail: "shared@example.com",
      existingProviders: ["password"],
      suggestedMethod: "password",
    });
  });

  it("password reset confirm + verify complete the end-to-end helpers", async () => {
    const { confirmPasswordReset, verifyPasswordResetCode, sendPasswordResetEmail } =
      await import("@/lib/auth/auth");

    sendReset.mockResolvedValue(undefined);
    verifyReset.mockResolvedValue("user@example.com");
    confirmReset.mockResolvedValue(undefined);

    const sent = await sendPasswordResetEmail("user@example.com");
    expect(sent.ok).toBe(true);
    expect(sendReset).toHaveBeenCalled();

    const verified = await verifyPasswordResetCode("oob-123");
    expect(verified).toEqual({
      ok: true,
      uid: "",
      email: "user@example.com",
    });

    const confirmed = await confirmPasswordReset("oob-123", "NewPass123");
    expect(confirmed.ok).toBe(true);
    expect(confirmReset).toHaveBeenCalledWith(
      { name: "mock-auth" },
      "oob-123",
      "NewPass123",
    );
  });
});
