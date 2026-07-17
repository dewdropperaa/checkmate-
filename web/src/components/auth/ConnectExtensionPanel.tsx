"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";
import { useAuth } from "@/contexts/AuthContext";
import {
  ApiError,
  mintExtensionToken,
} from "@/lib/api";
import { EXTENSION_ID_QUERY_KEY } from "@/lib/authRedirect";
import styles from "@/components/auth/auth.module.css";

type ConnectState =
  | { phase: "connecting" }
  | { phase: "connected"; via: "extension" | "manual" }
  | { phase: "manual"; token: string }
  | { phase: "error"; message: string };

declare global {
  interface Window {
    chrome?: {
      runtime?: {
        sendMessage: (
          extensionId: string,
          message: unknown,
          responseCallback?: (response: unknown) => void,
        ) => void;
        lastError?: { message?: string };
      };
    };
  }
}

function backendBaseFromEnv(): string {
  return (
    process.env.NEXT_PUBLIC_API_BASE_URL?.trim().replace(/\/$/, "") ||
    "http://127.0.0.1:8000"
  );
}

function sendTokenToExtension(
  extensionId: string,
  payload: { authToken: string; backendBaseUrl: string },
): Promise<boolean> {
  return new Promise((resolve) => {
    const runtime = window.chrome?.runtime;
    if (!runtime?.sendMessage) {
      resolve(false);
      return;
    }
    try {
      runtime.sendMessage(
        extensionId,
        {
          type: "CHECKMATE_CONNECT",
          authToken: payload.authToken,
          backendBaseUrl: payload.backendBaseUrl,
        },
        (response) => {
          if (runtime.lastError) {
            resolve(false);
            return;
          }
          const ok =
            response &&
            typeof response === "object" &&
            (response as { ok?: boolean }).ok === true;
          resolve(Boolean(ok));
        },
      );
    } catch {
      resolve(false);
    }
  });
}

export function ConnectExtensionPanel() {
  const t = useTranslations("connectExtension");
  const { currentUser } = useAuth();
  const [state, setState] = useState<ConnectState>({ phase: "connecting" });
  const [copied, setCopied] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current || !currentUser) return;
    started.current = true;

    void (async () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const extensionId = params.get(EXTENSION_ID_QUERY_KEY)?.trim() || "";
        const idToken = await currentUser.getIdToken();
        const { token } = await mintExtensionToken(idToken);
        const backendBaseUrl = backendBaseFromEnv();

        if (extensionId) {
          const delivered = await sendTokenToExtension(extensionId, {
            authToken: token,
            backendBaseUrl,
          });
          if (delivered) {
            setState({ phase: "connected", via: "extension" });
            return;
          }
        }

        setState({ phase: "manual", token });
      } catch (cause) {
        const message =
          cause instanceof ApiError
            ? cause.message
            : cause instanceof Error
              ? cause.message
              : t("errorGeneric");
        setState({ phase: "error", message });
      }
    })();
  }, [currentUser, t]);

  async function copyToken(token: string) {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  if (state.phase === "connecting") {
    return (
      <div className={styles.verifyPanel} role="status" aria-live="polite">
        <span className={styles.spinner} aria-hidden="true" />
        <h2 className={styles.verifyTitle}>{t("connectingTitle")}</h2>
        <p className={styles.verifyBody}>{t("connectingBody")}</p>
      </div>
    );
  }

  if (state.phase === "error") {
    return (
      <div className={styles.verifyPanel} role="alert">
        <h2 className={styles.verifyTitle}>{t("errorTitle")}</h2>
        <p className={styles.verifyBody}>{state.message}</p>
        <p className={styles.switch}>
          <Link href="/dashboard">{t("backDashboard")}</Link>
        </p>
      </div>
    );
  }

  if (state.phase === "connected") {
    return (
      <div className={styles.verifyPanel} role="status" aria-live="polite">
        <h2 className={styles.verifyTitle}>{t("connectedTitle")}</h2>
        <p className={styles.verifyBody}>{t("connectedBody")}</p>
        <p className={styles.switch}>
          <Link href="/dashboard">{t("backDashboard")}</Link>
        </p>
      </div>
    );
  }

  return (
    <div className={styles.formWrap}>
      <div className={styles.verifyPanel} role="status" aria-live="polite">
        <h2 className={styles.verifyTitle}>{t("manualTitle")}</h2>
        <p className={styles.verifyBody}>{t("manualBody")}</p>
        <label className={styles.label} htmlFor="extension-token">
          {t("tokenLabel")}
        </label>
        <textarea
          id="extension-token"
          className={styles.input}
          readOnly
          rows={3}
          value={state.token}
          onFocus={(event) => event.currentTarget.select()}
        />
        <button
          type="button"
          className={`btn btn-primary ${styles.submit}`}
          onClick={() => void copyToken(state.token)}
        >
          {copied ? t("copied") : t("copyToken")}
        </button>
        <p className={styles.switch}>
          <Link href="/dashboard">{t("backDashboard")}</Link>
        </p>
      </div>
    </div>
  );
}
