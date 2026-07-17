"use client";

import { useEffect, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { useAuth } from "@/contexts/AuthContext";
import { useRouter } from "@/i18n/navigation";
import styles from "@/components/auth/auth.module.css";

export const DASHBOARD_PATH = "/dashboard";
export const SIGNIN_PATH = "/signin";

type Mode = "protected" | "guest";

type Props = {
  mode: Mode;
  children: ReactNode;
  /** When true (protected only), require emailVerified before rendering children. */
  requireEmailVerified?: boolean;
};

/**
 * Client-side auth gate. Shows a loading shell until Firebase auth state
 * resolves so protected/guest routes never flash the wrong screen.
 */
export function AuthGuard({
  mode,
  children,
  requireEmailVerified = true,
}: Props) {
  const { currentUser, isLoading } = useAuth();
  const router = useRouter();
  const t = useTranslations("auth");

  const isAuthenticated = Boolean(currentUser);
  const isVerified = Boolean(currentUser?.emailVerified);
  const canAccessProtected =
    isAuthenticated && (!requireEmailVerified || isVerified);
  const shouldRedirectGuest = isAuthenticated && isVerified;

  useEffect(() => {
    if (isLoading) return;

    if (mode === "protected" && !isAuthenticated) {
      router.replace(SIGNIN_PATH);
      return;
    }

    if (mode === "guest" && shouldRedirectGuest) {
      router.replace(DASHBOARD_PATH);
    }
  }, [
    isLoading,
    mode,
    isAuthenticated,
    shouldRedirectGuest,
    router,
  ]);

  if (isLoading) {
    return (
      <div
        className={styles.authLoading}
        role="status"
        aria-live="polite"
        aria-busy="true"
      >
        <span className={styles.spinner} aria-hidden="true" />
        <span>{t("checkingSession")}</span>
      </div>
    );
  }

  if (mode === "protected" && !isAuthenticated) {
    return (
      <div
        className={styles.authLoading}
        role="status"
        aria-live="polite"
      >
        <span className={styles.spinner} aria-hidden="true" />
        <span>{t("redirecting")}</span>
      </div>
    );
  }

  if (mode === "protected" && isAuthenticated && !canAccessProtected) {
    return (
      <div className={styles.verifyPanel} role="status" aria-live="polite">
        <h2 className={styles.verifyTitle}>{t("verifyEmailTitle")}</h2>
        <p className={styles.verifyBody}>{t("verifyEmailBody")}</p>
      </div>
    );
  }

  if (mode === "guest" && shouldRedirectGuest) {
    return (
      <div
        className={styles.authLoading}
        role="status"
        aria-live="polite"
      >
        <span className={styles.spinner} aria-hidden="true" />
        <span>{t("redirecting")}</span>
      </div>
    );
  }

  return <>{children}</>;
}
