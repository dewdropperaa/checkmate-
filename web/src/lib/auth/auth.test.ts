import { beforeEach, describe, expect, it, vi } from "vitest";

const createUser = vi.fn();
const signInEmail = vi.fn();
const sendVerify = vi.fn();
const sendReset = vi.fn();
const signInPopup = vi.fn();
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

  it("Google account-exists-with-different-credential maps cleanly", async () => {
    const { signInWithGoogle } = await import("@/lib/auth/auth");
    signInPopup.mockRejectedValue({
      code: "auth/account-exists-with-different-credential",
    });

    const result = await signInWithGoogle();
    expect(result).toMatchObject({
      ok: false,
      errorKey: "accountExistsWithDifferentCredential",
    });
  });
});
