/**
 * Firebase Authentication helpers (modular SDK v9+).
 */
import {
  GoogleAuthProvider,
  createUserWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail as firebaseSendPasswordResetEmail,
  signInWithEmailAndPassword,
  signInWithPopup,
  // signInWithRedirect — fallback when popups are blocked (see signInWithGoogle).
  signOut as firebaseSignOut,
  type User,
} from "firebase/auth";
import { getFirebaseAuth } from "@/lib/firebase";
import {
  mapFirebaseAuthError,
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
    return toSuccess(cred.user, {
      needsEmailVerification: !cred.user.emailVerified,
    });
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
    return toSuccess(cred.user);
  } catch (error) {
    return mapFirebaseAuthError(error);
  }
}

export async function sendPasswordResetEmail(
  email: string,
): Promise<AuthResult> {
  try {
    await firebaseSendPasswordResetEmail(getFirebaseAuth(), email.trim());
    return { ok: true, uid: "", email: email.trim() };
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
