"use client";

import { useEffect, useLayoutEffect, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { useAuth } from "@/contexts/AuthContext";
import { usePathname, useRouter } from "@/i18n/navigation";
import {
  isSafeNextPath,
  readAuthRedirectFromSearch,
} from "@/lib/authRedirect";
import styles from "@/components/auth/auth.module.css";

export const DASHBOARD_PATH = "/dashboard";
export const SIGNIN_PATH = "/signin";

const useAuthRedirectEffect =
  typeof window !== "undefined" ? useLayoutEffect : useEffect;

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
  const pathname = usePathname();
  const t = useTranslations("auth");

  const isAuthenticated = Boolean(currentUser);
  const isVerified = Boolean(currentUser?.emailVerified);
  const canAccessProtected =
    isAuthenticated && (!requireEmailVerified || isVerified);
  const shouldRedirectGuest = isAuthenticated && isVerified;

  useAuthRedirectEffect(() => {
    if (isLoading) return;

    if (mode === "protected" && !isAuthenticated) {
      const search =
        typeof window !== "undefined" ? window.location.search : "";
      const params = new URLSearchParams();
      const fromPage = isSafeNextPath(pathname) ? pathname : null;
      const { extensionId } = readAuthRedirectFromSearch(search);
      if (fromPage && fromPage !== DASHBOARD_PATH) {
        params.set("next", fromPage);
      }
      if (extensionId) {
        params.set("extensionId", extensionId);
        params.set("from", "extension");
      } else if (fromPage === "/connect-extension") {
        params.set("from", "extension");
      }
      const qs = params.toString();
      router.replace(qs ? `${SIGNIN_PATH}?${qs}` : SIGNIN_PATH);
      return;
    }

    if (mode === "guest" && shouldRedirectGuest) {
      const search =
        typeof window !== "undefined" ? window.location.search : "";
      const { next } = readAuthRedirectFromSearch(search);
      router.replace(next);
    }
  }, [
    isLoading,
    mode,
    isAuthenticated,
    shouldRedirectGuest,
    router,
    pathname,
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
        <p className={styles.verifyBody}>{t("checkSpam")}</p>
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
