"use client";

import { FormEvent, useEffect, useId, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { Link, useRouter } from "@/i18n/navigation";
import {
  confirmPasswordReset,
  signInWithEmail,
  verifyPasswordResetCode,
} from "@/lib/auth/auth";
import type { AuthMessageKey } from "@/lib/auth/errors";
import {
  getPasswordStrength,
  type PasswordStrength,
} from "@/lib/auth/validation";
import styles from "@/components/auth/auth.module.css";

export function ResetPasswordForm() {
  const t = useTranslations("auth");
  const te = useTranslations("auth.errors");
  const router = useRouter();
  const searchParams = useSearchParams();
  const oobCode = searchParams.get("oobCode")?.trim() ?? "";
  const mode = searchParams.get("mode");

  const passwordId = useId();
  const confirmId = useId();

  const [email, setEmail] = useState<string | null>(null);
  const [checking, setChecking] = useState(Boolean(oobCode));
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [strength, setStrength] = useState<PasswordStrength>("empty");
  const [errorKey, setErrorKey] = useState<
    AuthMessageKey | "missingCode" | null
  >(null);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!oobCode || (mode && mode !== "resetPassword")) {
      setChecking(false);
      setErrorKey("missingCode");
      return;
    }
    let cancelled = false;
    void (async () => {
      const result = await verifyPasswordResetCode(oobCode);
      if (cancelled) return;
      setChecking(false);
      if (!result.ok) {
        setErrorKey(result.errorKey);
        return;
      }
      setEmail(result.email);
    })();
    return () => {
      cancelled = true;
    };
  }, [oobCode, mode]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setFieldError(null);
    setErrorKey(null);
    if (password.length < 8) {
      setFieldError("weakPassword");
      return;
    }
    if (password !== confirmPassword) {
      setFieldError("passwordMismatch");
      return;
    }
    setBusy(true);
    try {
      const result = await confirmPasswordReset(oobCode, password);
      if (!result.ok) {
        setErrorKey(result.errorKey);
        return;
      }
      if (email) {
        const signedIn = await signInWithEmail(email, password);
        if (signedIn.ok && !signedIn.needsEmailVerification) {
          router.replace("/dashboard");
          return;
        }
      }
      setDone(true);
    } finally {
      setBusy(false);
    }
  }

  if (checking) {
    return <p className={styles.authLoading}>{t("checkingSession")}</p>;
  }

  if (done) {
    return (
      <div className={styles.verifyPanel} role="status">
        <h2 className={styles.verifyTitle}>{t("resetPasswordSuccessTitle")}</h2>
        <p className={styles.verifyBody}>{t("resetPasswordSuccess")}</p>
        <p className={styles.switch}>
          <Link href="/signin">{t("goToSignIn")}</Link>
        </p>
      </div>
    );
  }

  if (errorKey === "missingCode" || !oobCode) {
    return (
      <div className={styles.verifyPanel} role="alert">
        <p className={styles.verifyBody}>{t("resetPasswordMissingCode")}</p>
        <p className={styles.switch}>
          <Link href="/signin">{t("goToSignIn")}</Link>
        </p>
      </div>
    );
  }

  if (errorKey && errorKey !== "weakPassword") {
    return (
      <div className={styles.verifyPanel} role="alert">
        <p className={styles.verifyBody}>
          {errorKey === "invalidCredential" || errorKey === "generic"
            ? t("resetPasswordInvalidCode")
            : te(errorKey)}
        </p>
        <p className={styles.switch}>
          <Link href="/signin">{t("goToSignIn")}</Link>
        </p>
      </div>
    );
  }

  return (
    <form className={styles.form} onSubmit={onSubmit} noValidate>
      {email ? <p className={styles.authSubtitle}>{email}</p> : null}
      <div className={styles.field}>
        <label className={styles.label} htmlFor={passwordId}>
          {t("newPassword")}
        </label>
        <input
          id={passwordId}
          className={styles.input}
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setStrength(getPasswordStrength(e.target.value));
          }}
          disabled={busy}
        />
        <p className={styles.hint}>{t(`passwordStrength.${strength}`)}</p>
      </div>
      <div className={styles.field}>
        <label className={styles.label} htmlFor={confirmId}>
          {t("confirmNewPassword")}
        </label>
        <input
          id={confirmId}
          className={styles.input}
          type="password"
          autoComplete="new-password"
          required
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          disabled={busy}
        />
      </div>
      {fieldError ? (
        <p className={styles.formAlert} role="alert">
          {te(fieldError as AuthMessageKey)}
        </p>
      ) : null}
      <button
        type="submit"
        className={`btn btn-primary ${styles.submit}`}
        disabled={busy}
      >
        {busy ? t("submitting") : t("resetPasswordSubmit")}
      </button>
    </form>
  );
}
