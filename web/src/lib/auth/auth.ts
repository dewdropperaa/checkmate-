/**
 * Firebase Authentication helpers (modular SDK v9+).
 */
import {
  GoogleAuthProvider,
  ActionCodeSettings,
  confirmPasswordReset as firebaseConfirmPasswordReset,
  createUserWithEmailAndPassword,
  fetchSignInMethodsForEmail,
  sendEmailVerification,
  sendPasswordResetEmail as firebaseSendPasswordResetEmail,
  signInWithEmailAndPassword,
  signInWithPopup,
  // signInWithRedirect — fallback when popups are blocked (see signInWithGoogle).
  signOut as firebaseSignOut,
  verifyPasswordResetCode as firebaseVerifyPasswordResetCode,
  type User,
} from "firebase/auth";
import { getFirebaseAuth } from "@/lib/firebase";
import {
  mapFirebaseAuthError,
  type AuthFailure,
  type AuthResult,
  type AuthSuccess,
} from "@/lib/auth/errors";

function toSuccess(
  user: User,
  extras: Partial<AuthSuccess> = {},
): AuthSuccess {
  return {
    ok: true,
    uid: user.uid,
    email: user.email,
    ...extras,
  };
}

function conflictEmailFromError(error: unknown): string | undefined {
  if (
    typeof error === "object" &&
    error !== null &&
    "customData" in error &&
    typeof (error as { customData?: { email?: unknown } }).customData?.email ===
      "string"
  ) {
    return (error as { customData: { email: string } }).customData.email;
  }
  return undefined;
}

function suggestMethodFromProviders(providers: string[]): string | undefined {
  if (providers.includes("password")) return "password";
  if (providers.includes("google.com")) return "google";
  return providers[0];
}

export async function signUpWithEmail(
  email: string,
  password: string,
): Promise<AuthResult> {
  try {
    const cred = await createUserWithEmailAndPassword(
      getFirebaseAuth(),
      email.trim(),
      password,
    );
    await sendEmailVerification(cred.user);
    return toSuccess(cred.user, { needsEmailVerification: true });
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}

export async function signInWithEmail(
  email: string,
  password: string,
): Promise<AuthResult> {
  try {
    const cred = await signInWithEmailAndPassword(
      getFirebaseAuth(),
      email.trim(),
      password,
    );
    if (!cred.user.emailVerified) {
      try {
        await sendEmailVerification(cred.user);
      } catch {
        // Rate-limited or offline — still block sign-in until verified.
      }
      await firebaseSignOut(getFirebaseAuth());
      return toSuccess(cred.user, { needsEmailVerification: true });
    }
    return toSuccess(cred.user);
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}

/**
 * Google sign-in via popup (default).
 *
 * If we see widespread popup-blocking in production browsers (especially
 * embedded WebViews), swap `signInWithPopup` for `signInWithRedirect` +
 * `getRedirectResult` on app load — keep the same error mapping below.
 */
export async function signInWithGoogle(): Promise<AuthResult> {
  try {
    const provider = new GoogleAuthProvider();
    provider.setCustomParameters({ prompt: "select_account" });
    const cred = await signInWithPopup(getFirebaseAuth(), provider);
    // Fallback path (documented, not active):
    //   await signInWithRedirect(getFirebaseAuth(), provider);
    // Then on cold start: const result = await getRedirectResult(getFirebaseAuth());
    if (!cred.user.emailVerified) {
      try {
        await sendEmailVerification(cred.user);
      } catch {
        // Rate-limited or offline — still block sign-in until verified.
      }
      await firebaseSignOut(getFirebaseAuth());
      return toSuccess(cred.user, { needsEmailVerification: true });
    }
    return toSuccess(cred.user);
  } catch (error) {
    const failure = mapFirebaseAuthError(error);
    if (failure.errorKey !== "accountExistsWithDifferentCredential") {
      return failure;
    }
    const conflictEmail = conflictEmailFromError(error);
    let existingProviders: string[] = [];
    if (conflictEmail) {
      try {
        existingProviders = await fetchSignInMethodsForEmail(
          getFirebaseAuth(),
          conflictEmail,
        );
      } catch {
        existingProviders = [];
      }
    }
    const enriched: AuthFailure = {
      ...failure,
      conflictEmail,
      existingProviders,
      suggestedMethod: suggestMethodFromProviders(existingProviders),
    };
    return enriched;
  }
}

function passwordResetActionSettings(): ActionCodeSettings | undefined {
  if (typeof window === "undefined") return undefined;
  // Continue URL after Firebase processes the link — our in-app reset page
  // also accepts oobCode directly when the Console action handler points here.
  const locale =
    window.location.pathname.split("/").filter(Boolean)[0] || "en";
  return {
    url: `${window.location.origin}/${locale}/reset-password`,
    handleCodeInApp: false,
  };
}

export async function sendPasswordResetEmail(
  email: string,
): Promise<AuthResult> {
  try {
    await firebaseSendPasswordResetEmail(
      getFirebaseAuth(),
      email.trim(),
      passwordResetActionSettings(),
    );
    return { ok: true, uid: "", email: email.trim() };
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}

/** Validate a password-reset oobCode from the email link (before showing the form). */
export async function verifyPasswordResetCode(
  oobCode: string,
): Promise<AuthResult & { email?: string }> {
  try {
    const email = await firebaseVerifyPasswordResetCode(
      getFirebaseAuth(),
      oobCode,
    );
    return { ok: true, uid: "", email };
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}

/** Complete password reset with the oobCode from the email link. */
export async function confirmPasswordReset(
  oobCode: string,
  newPassword: string,
): Promise<AuthResult> {
  try {
    await firebaseConfirmPasswordReset(
      getFirebaseAuth(),
      oobCode,
      newPassword,
    );
    return { ok: true, uid: "", email: null };
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}

/** @deprecated Prefer sendPasswordResetEmail — kept for existing call sites. */
export const resetPassword = sendPasswordResetEmail;

export async function signOut(): Promise<AuthResult> {
  try {
    await firebaseSignOut(getFirebaseAuth());
    return { ok: true, uid: "", email: null };
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}
