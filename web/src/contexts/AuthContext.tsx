"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { onAuthStateChanged, type User } from "firebase/auth";
import { getFirebaseAuth } from "@/lib/firebase";
import { syncBackendUser, type BackendUser } from "@/lib/api";
import { formatApiConnectionError } from "@/lib/apiBaseUrl";
import {
  sendPasswordResetEmail as sendPasswordResetEmailFn,
  signInWithEmail as signInWithEmailFn,
  signInWithGoogle as signInWithGoogleFn,
  signOut as signOutFn,
  signUpWithEmail as signUpWithEmailFn,
} from "@/lib/auth/auth";
import type { AuthResult } from "@/lib/auth/errors";
import {
  TERMS_VERSION,
  takePendingTermsAcceptance,
} from "@/lib/terms";

type AuthContextValue = {
  currentUser: User | null;
  backendUser: BackendUser | null;
  isLoading: boolean;
  isSyncing: boolean;
  syncError: string | null;
  signUpWithEmail: (email: string, password: string) => Promise<AuthResult>;
  signInWithEmail: (email: string, password: string) => Promise<AuthResult>;
  signInWithGoogle: () => Promise<AuthResult>;
  sendPasswordResetEmail: (email: string) => Promise<AuthResult>;
  /** @deprecated Prefer sendPasswordResetEmail */
  resetPassword: (email: string) => Promise<AuthResult>;
  signOut: () => Promise<AuthResult>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

async function syncProfile(user: User): Promise<BackendUser> {
  const idToken = await user.getIdToken();
  const pendingTerms = takePendingTermsAcceptance();
  // Sign-in and sign-up flows record clickwrap acceptance in sessionStorage,
  // but session restore must still send terms for first-time backend provisioning.
  const result = await syncBackendUser(idToken, {
    termsAccepted: true,
    termsVersion: pendingTerms?.version ?? TERMS_VERSION,
  });
  return result.user;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [backendUser, setBackendUser] = useState<BackendUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let unsubscribe: (() => void) | undefined;

    try {
      const auth = getFirebaseAuth();
      unsubscribe = onAuthStateChanged(auth, async (user) => {
        if (cancelled) return;
        setCurrentUser(user);
        setSyncError(null);

        if (!user) {
          setBackendUser(null);
          setIsLoading(false);
          return;
        }

        if (!user.emailVerified) {
          setBackendUser(null);
          setIsLoading(false);
          return;
        }

        // Unblock navigation as soon as Firebase resolves; sync profile in background.
        setIsLoading(false);
        setIsSyncing(true);
        try {
          const profile = await syncProfile(user);
          if (!cancelled) {
            setBackendUser(profile);
          }
        } catch (err) {
          if (!cancelled) {
            setBackendUser(null);
            setSyncError(formatApiConnectionError(err));
          }
        } finally {
          if (!cancelled) {
            setIsSyncing(false);
          }
        }
      });
    } catch (err) {
      setIsLoading(false);
      setSyncError(
        err instanceof Error
          ? err.message
          : "Firebase Auth is not configured",
      );
    }

    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, []);

  const wrapAuth = useCallback(
    async (action: () => Promise<AuthResult>): Promise<AuthResult> => {
      const result = await action();
      // onAuthStateChanged handles user + backend sync after success.
      return result;
    },
    [],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      currentUser,
      backendUser,
      isLoading,
      isSyncing,
      syncError,
      signUpWithEmail: (email, password) =>
        wrapAuth(() => signUpWithEmailFn(email, password)),
      signInWithEmail: (email, password) =>
        wrapAuth(() => signInWithEmailFn(email, password)),
      signInWithGoogle: () => wrapAuth(() => signInWithGoogleFn()),
      sendPasswordResetEmail: (email) =>
        wrapAuth(() => sendPasswordResetEmailFn(email)),
      resetPassword: (email) => wrapAuth(() => sendPasswordResetEmailFn(email)),
      signOut: () => wrapAuth(() => signOutFn()),
    }),
    [currentUser, backendUser, isLoading, isSyncing, syncError, wrapAuth],
  );

  return (
    <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
