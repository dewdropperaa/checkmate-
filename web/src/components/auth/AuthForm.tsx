"use client";

import {
  FormEvent,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { Link, useRouter } from "@/i18n/navigation";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";
import { useAuth } from "@/contexts/AuthContext";
import type { AuthMessageKey } from "@/lib/auth/errors";
import {
  getPasswordStrength,
  hasFieldErrors,
  type FieldErrors,
  type PasswordStrength,
  validateSignInFields,
  validateSignUpFields,
} from "@/lib/auth/validation";
import { readAuthRedirectFromSearch } from "@/lib/authRedirect";
import { markTermsAccepted } from "@/lib/terms";
import styles from "@/components/auth/auth.module.css";

type Mode = "signin" | "signup";

type Props = {
  mode: Mode;
};

type FormErrorTarget = "email" | "password" | "form";

const FIREBASE_FIELD_MAP: Partial<Record<AuthMessageKey, FormErrorTarget>> = {
  invalidEmail: "email",
  emailAlreadyInUse: "email",
  userNotFound: "email",
  weakPassword: "password",
  wrongPassword: "password",
  invalidCredential: "password",
};

export function AuthForm({ mode }: Props) {
  const t = useTranslations("auth");
  const te = useTranslations("auth.errors");
  const router = useRouter();
  const searchParams = useSearchParams();
  const authQuery = useMemo(() => {
    const qs = searchParams.toString();
    return qs ? `?${qs}` : "";
  }, [searchParams]);
  const {
    signInWithEmail,
    signUpWithEmail,
    signInWithGoogle,
    sendPasswordResetEmail,
    signOut,
    isLoading,
  } = useAuth();

  const emailId = useId();
  const passwordId = useId();
  const confirmId = useId();
  const termsId = useId();
  const emailRef = useRef<HTMLInputElement>(null);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  /** Firebase error key shown next to a specific field (inline). */
  const [inlineServerError, setInlineServerError] = useState<{
    field: FormErrorTarget;
    key: AuthMessageKey;
  } | null>(null);
  const [formErrorKey, setFormErrorKey] = useState<AuthMessageKey | null>(
    null,
  );
  const [cooldownSeconds, setCooldownSeconds] = useState<number | null>(null);
  const [checkInbox, setCheckInbox] = useState(false);
  const [resetSent, setResetSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [strength, setStrength] = useState<PasswordStrength>("empty");

  useEffect(() => {
    emailRef.current?.focus();
  }, [mode]);

  useEffect(() => {
    if (cooldownSeconds === null || cooldownSeconds <= 0) return;
    const timer = window.setTimeout(() => {
      setCooldownSeconds((prev) =>
        prev === null || prev <= 1 ? null : prev - 1,
      );
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [cooldownSeconds]);

  function clearFeedback() {
    setFieldErrors({});
    setInlineServerError(null);
    setFormErrorKey(null);
    setCheckInbox(false);
    setResetSent(false);
  }

  function applyFailure(result: {
    ok: false;
    errorKey: AuthMessageKey;
    cooldownSeconds?: number;
  }) {
    const target = FIREBASE_FIELD_MAP[result.errorKey] ?? "form";
    if (target === "form") {
      setFormErrorKey(result.errorKey);
      setInlineServerError(null);
    } else {
      setInlineServerError({ field: target, key: result.errorKey });
      setFormErrorKey(null);
    }
    if (result.errorKey === "tooManyRequests") {
      setCooldownSeconds(result.cooldownSeconds ?? 60);
    }
  }

  function runClientValidation(): boolean {
    const errors =
      mode === "signup"
        ? validateSignUpFields(email, password, confirmPassword, termsAccepted)
        : validateSignInFields(email, password);
    setFieldErrors(errors);
    return !hasFieldErrors(errors);
  }

  function requireTermsForSignup(): boolean {
    if (mode !== "signup") return true;
    if (termsAccepted) return true;
    setFieldErrors({ terms: "agreeRequired" });
    return false;
  }

  function postAuthDestination(): string {
    return readAuthRedirectFromSearch(
      authQuery.startsWith("?") ? authQuery.slice(1) : authQuery,
    ).next;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    clearFeedback();
    if (!runClientValidation()) return;
    if (cooldownSeconds && cooldownSeconds > 0) return;

    markTermsAccepted();
    setBusy(true);
    try {
      const result =
        mode === "signup"
          ? await signUpWithEmail(email, password)
          : await signInWithEmail(email, password);

      if (!result.ok) {
        applyFailure(result);
        return;
      }

      if (mode === "signup" || result.needsEmailVerification) {
        setCheckInbox(true);
        // Stay off the dashboard until the inbox link is confirmed.
        await signOut();
        return;
      }

      router.replace(postAuthDestination());
    } finally {
      setBusy(false);
    }
  }

  async function onGoogle() {
    clearFeedback();
    if (!requireTermsForSignup()) return;
    if (cooldownSeconds && cooldownSeconds > 0) return;

    markTermsAccepted();
    setBusy(true);
    try {
      const result = await signInWithGoogle();
      if (!result.ok) {
        applyFailure(result);
        return;
      }
      router.replace(postAuthDestination());
    } finally {
      setBusy(false);
    }
  }

  async function onForgotPassword() {
    clearFeedback();
    if (!isValidEmailLocal(email)) {
      setFieldErrors({ email: "invalidEmail" });
      return;
    }
    setBusy(true);
    try {
      const result = await sendPasswordResetEmail(email);
      if (!result.ok) {
        applyFailure(result);
        return;
      }
      setResetSent(true);
    } finally {
      setBusy(false);
    }
  }

  const disabled =
    busy || isLoading || Boolean(cooldownSeconds && cooldownSeconds > 0);

  if (checkInbox) {
    return (
      <div className={styles.formWrap}>
        <div className={styles.verifyPanel} role="status" aria-live="polite">
          <h2 className={styles.verifyTitle}>{t("verifyEmailTitle")}</h2>
          <p className={styles.verifyBody}>{t("checkInbox")}</p>
          <p className={styles.switch}>
            <Link href="/signin">{t("goToSignIn")}</Link>
          </p>
        </div>
      </div>
    );
  }

  if (resetSent) {
    return (
      <div className={styles.formWrap}>
        <div className={styles.verifyPanel} role="status" aria-live="polite">
          <h2 className={styles.verifyTitle}>{t("resetSentTitle")}</h2>
          <p className={styles.verifyBody}>{t("resetSent")}</p>
          <button
            type="button"
            className={`btn btn-secondary ${styles.submit}`}
            onClick={() => setResetSent(false)}
          >
            {t("backToSignIn")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.formWrap}>
      {mode === "signup" && (
        <div className={styles.field}>
          <div className={styles.termsRow}>
            <input
              id={termsId}
              className={styles.termsCheckbox}
              type="checkbox"
              checked={termsAccepted}
              onChange={(e) => {
                setTermsAccepted(e.target.checked);
                if (fieldErrors.terms) {
                  setFieldErrors((prev) => ({ ...prev, terms: undefined }));
                }
              }}
              disabled={disabled}
              aria-invalid={Boolean(fieldErrors.terms)}
              aria-describedby={
                fieldErrors.terms ? `${termsId}-error` : undefined
              }
            />
            <label className={styles.termsLabel} htmlFor={termsId}>
              {t.rich("agreeToTerms", {
                terms: (chunks) => <Link href="/terms">{chunks}</Link>,
                privacy: (chunks) => <Link href="/privacy">{chunks}</Link>,
              })}
            </label>
          </div>
          <p
            id={`${termsId}-error`}
            className={styles.fieldError}
            role="alert"
            aria-live="assertive"
          >
            {fieldErrors.terms ? te("agreeRequired") : null}
          </p>
        </div>
      )}

      <GoogleSignInButton
        label={t("continueWithGoogle")}
        onClick={onGoogle}
        disabled={disabled}
      />

      <div className={styles.divider}>
        <span>{t("or")}</span>
      </div>

      <form className={styles.form} onSubmit={onSubmit} noValidate>
        <div className={styles.field}>
          <label className={styles.label} htmlFor={emailId}>
            {t("email")}
          </label>
          <input
            ref={emailRef}
            id={emailId}
            className={styles.input}
            type="email"
            name="email"
            autoComplete="email"
            inputMode="email"
            required
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              if (fieldErrors.email || inlineServerError?.field === "email") {
                setFieldErrors((prev) => ({ ...prev, email: undefined }));
                if (inlineServerError?.field === "email") {
                  setInlineServerError(null);
                }
              }
            }}
            disabled={disabled}
            aria-invalid={Boolean(
              fieldErrors.email || inlineServerError?.field === "email",
            )}
            aria-describedby={
              fieldErrors.email || inlineServerError?.field === "email"
                ? `${emailId}-error`
                : undefined
            }
          />
          <p
            id={`${emailId}-error`}
            className={styles.fieldError}
            role="alert"
            aria-live="assertive"
          >
            {fieldErrors.email
              ? te(fieldErrors.email)
              : inlineServerError?.field === "email"
                ? te(inlineServerError.key)
                : null}
          </p>
        </div>

        <div className={styles.field}>
          <label className={styles.label} htmlFor={passwordId}>
            {t("password")}
          </label>
          <input
            id={passwordId}
            className={styles.input}
            type="password"
            name="password"
            autoComplete={
              mode === "signup" ? "new-password" : "current-password"
            }
            required
            minLength={mode === "signup" ? 8 : 1}
            value={password}
            onChange={(e) => {
              const next = e.target.value;
              setPassword(next);
              if (mode === "signup") {
                setStrength(getPasswordStrength(next));
              }
              if (fieldErrors.password || inlineServerError?.field === "password") {
                setFieldErrors((prev) => ({ ...prev, password: undefined }));
                if (inlineServerError?.field === "password") {
                  setInlineServerError(null);
                }
              }
            }}
            disabled={disabled}
            aria-invalid={Boolean(
              fieldErrors.password || inlineServerError?.field === "password",
            )}
            aria-describedby={
              [
                fieldErrors.password || inlineServerError?.field === "password"
                  ? `${passwordId}-error`
                  : null,
                mode === "signup" ? `${passwordId}-strength` : null,
              ]
                .filter(Boolean)
                .join(" ") || undefined
            }
          />
          {mode === "signup" && (
            <PasswordStrengthMeter
              id={`${passwordId}-strength`}
              strength={strength}
              label={t("passwordStrength")}
              valueLabel={t(`strength.${strength}`)}
            />
          )}
          <p
            id={`${passwordId}-error`}
            className={styles.fieldError}
            role="alert"
            aria-live="assertive"
          >
            {fieldErrors.password
              ? fieldErrors.password === "passwordRequired"
                ? te("passwordRequired")
                : te("weakPassword")
              : inlineServerError?.field === "password"
                ? te(inlineServerError.key)
                : null}
          </p>
        </div>

        {mode === "signup" && (
          <div className={styles.field}>
            <label className={styles.label} htmlFor={confirmId}>
              {t("confirmPassword")}
            </label>
            <input
              id={confirmId}
              className={styles.input}
              type="password"
              name="confirmPassword"
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => {
                setConfirmPassword(e.target.value);
                if (fieldErrors.confirmPassword) {
                  setFieldErrors((prev) => ({
                    ...prev,
                    confirmPassword: undefined,
                  }));
                }
              }}
              disabled={disabled}
              aria-invalid={Boolean(fieldErrors.confirmPassword)}
              aria-describedby={
                fieldErrors.confirmPassword
                  ? `${confirmId}-error`
                  : undefined
              }
            />
            <p
              id={`${confirmId}-error`}
              className={styles.fieldError}
              role="alert"
              aria-live="assertive"
            >
              {fieldErrors.confirmPassword
                ? te("passwordMismatch")
                : null}
            </p>
          </div>
        )}

        {mode === "signin" && (
          <button
            type="button"
            className={styles.linkButton}
            onClick={onForgotPassword}
            disabled={disabled}
          >
            {t("forgotPassword")}
          </button>
        )}

        <div className={styles.formAlert} aria-live="assertive" role="alert">
          {formErrorKey
            ? formErrorKey === "tooManyRequests" && cooldownSeconds
              ? te("tooManyRequests", { seconds: cooldownSeconds })
              : te(formErrorKey)
            : null}
        </div>

        <button
          type="submit"
          className={`btn btn-primary ${styles.submit}`}
          disabled={disabled}
          aria-busy={busy}
        >
          {busy ? (
            <>
              <span className={styles.spinner} aria-hidden="true" />
              {t("submitting")}
            </>
          ) : mode === "signup" ? (
            t("submitSignUp")
          ) : (
            t("submitSignIn")
          )}
        </button>
      </form>

      {mode === "signin" && (
        <p className={styles.signInAgree}>
          {t.rich("signInAgree", {
            terms: (chunks) => <Link href="/terms">{chunks}</Link>,
            privacy: (chunks) => <Link href="/privacy">{chunks}</Link>,
          })}
        </p>
      )}

      <p className={styles.switch}>
        {mode === "signin" ? (
          <>
            {t("noAccount")}{" "}
            <Link href={`/signup${authQuery}`}>{t("goToSignUp")}</Link>
          </>
        ) : (
          <>
            {t("hasAccount")}{" "}
            <Link href={`/signin${authQuery}`}>{t("goToSignIn")}</Link>
          </>
        )}
      </p>
    </div>
  );
}

function isValidEmailLocal(email: string): boolean {
  return validateSignInFields(email, "x").email === undefined;
}

function PasswordStrengthMeter({
  id,
  strength,
  label,
  valueLabel,
}: {
  id: string;
  strength: PasswordStrength;
  label: string;
  valueLabel: string;
}) {
  const level =
    strength === "empty"
      ? 0
      : strength === "weak"
        ? 1
        : strength === "fair"
          ? 2
          : strength === "good"
            ? 3
            : 4;

  return (
    <div
      id={id}
      className={styles.strength}
      data-strength={strength}
      aria-label={`${label}: ${valueLabel}`}
    >
      <div className={styles.strengthTrack} aria-hidden="true">
        <span
          className={styles.strengthFill}
          style={{ width: `${(level / 4) * 100}%` }}
        />
      </div>
      <span className={styles.strengthLabel}>
        {label}: {valueLabel}
      </span>
    </div>
  );
}
