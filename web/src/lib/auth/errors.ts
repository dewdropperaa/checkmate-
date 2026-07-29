/**
 * Maps Firebase Auth error codes to i18n message keys under `auth.errors.*`.
 * Never surface raw Firebase messages to the UI.
 */

export type AuthMessageKey =
  | "emailAlreadyInUse"
  | "weakPassword"
  | "wrongPassword"
  | "userNotFound"
  | "invalidEmail"
  | "tooManyRequests"
  | "accountExistsWithDifferentCredential"
  | "popupClosedByUser"
  | "popupBlocked"
  | "networkRequestFailed"
  | "requiresRecentLogin"
  | "invalidCredential"
  | "operationNotAllowed"
  | "userDisabled"
  | "unauthorizedDomain"
  | "authInternalError"
  | "generic";

/** Stable result shape returned by all auth helpers. */
export type AuthSuccess = {
  ok: true;
  /** True after email/password signup — UI should show "check your inbox". */
  needsEmailVerification?: boolean;
  uid: string;
  email: string | null;
};

export type AuthFailure = {
  ok: false;
  errorKey: AuthMessageKey;
  /** Suggested wait before retrying when Firebase rate-limits the client. */
  cooldownSeconds?: number;
  /** Original Firebase code for logging only — never display. */
  firebaseCode?: string;
  /** Email that already has an account under a different provider. */
  conflictEmail?: string;
  /** Firebase provider ids for the existing account (e.g. ["password"]). */
  existingProviders?: string[];
  /** Best guess for how the user should sign in instead (password | google | …). */
  suggestedMethod?: string;
};

export type AuthResult = AuthSuccess | AuthFailure;

const CODE_TO_KEY: Record<string, AuthMessageKey> = {
  "auth/email-already-in-use": "emailAlreadyInUse",
  "auth/weak-password": "weakPassword",
  "auth/wrong-password": "wrongPassword",
  "auth/user-not-found": "userNotFound",
  "auth/invalid-email": "invalidEmail",
  "auth/too-many-requests": "tooManyRequests",
  "auth/account-exists-with-different-credential":
    "accountExistsWithDifferentCredential",
  "auth/popup-closed-by-user": "popupClosedByUser",
  "auth/popup-blocked": "popupBlocked",
  "auth/cancelled-popup-request": "popupClosedByUser",
  "auth/network-request-failed": "networkRequestFailed",
  "auth/requires-recent-login": "requiresRecentLogin",
  "auth/invalid-credential": "invalidCredential",
  "auth/invalid-login-credentials": "invalidCredential",
  "auth/operation-not-allowed": "operationNotAllowed",
  "auth/user-disabled": "userDisabled",
  "auth/unauthorized-domain": "unauthorizedDomain",
  "auth/internal-error": "authInternalError",
};

/** Default cooldown shown when Firebase returns auth/too-many-requests. */
export const DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS = 60;

export function mapFirebaseAuthError(error: unknown): AuthFailure {
  const firebaseCode =
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof (error as { code: unknown }).code === "string"
      ? (error as { code: string }).code
      : undefined;

  const errorKey =
    (firebaseCode && CODE_TO_KEY[firebaseCode]) || ("generic" as AuthMessageKey);

  // Dev-only: the UI never shows raw Firebase strings; the console does.
  if (process.env.NODE_ENV === "development") {
    console.error("[auth] Firebase Auth failure", {
      firebaseCode: firebaseCode ?? "(none)",
      errorKey,
      error,
    });
  }

  const failure: AuthFailure = {
    ok: false,
    errorKey,
    firebaseCode,
  };

  if (errorKey === "tooManyRequests") {
    failure.cooldownSeconds = DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS;
  }

  return failure;
}

/** Exported for unit tests — pure mapping without Firebase SDK. */
export function mapFirebaseAuthCode(code: string): AuthMessageKey {
  return CODE_TO_KEY[code] ?? "generic";
}
