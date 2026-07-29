"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import styles from "@/components/dashboard/dashboard.module.css";

export const AUTO_APPROVE_SECONDS = 8;

type AuthScanContext = {
  enabled?: boolean;
  username_hint?: string;
  excluded_paths?: string[];
  message?: string;
};

type Props = {
  target: string;
  plannedTools: string[];
  authContext?: AuthScanContext | null;
  loading: boolean;
  error: string | null;
  onApprove: (approvedTools: string[]) => Promise<void>;
  onReject: () => Promise<void>;
};

export function ApprovalGate({
  target,
  plannedTools,
  authContext,
  loading,
  error,
  onApprove,
  onReject,
}: Props) {
  const t = useTranslations("dashboard");
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(plannedTools),
  );
  const [remaining, setRemaining] = useState(AUTO_APPROVE_SECONDS);
  const [autoEnabled, setAutoEnabled] = useState(true);
  const firedRef = useRef(false);
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  useEffect(() => {
    setSelected(new Set(plannedTools));
    setRemaining(AUTO_APPROVE_SECONDS);
    setAutoEnabled(true);
    firedRef.current = false;
  }, [plannedTools.join("|")]);

  useEffect(() => {
    if (!autoEnabled || loading) return;
    if (remaining <= 0) {
      if (firedRef.current) return;
      firedRef.current = true;
      void onApprove(Array.from(selectedRef.current)).catch(() => {
        // Parent surfaces the error; keep the gate visible (no silent proceed).
        firedRef.current = false;
        setAutoEnabled(false);
      });
      return;
    }
    const timer = window.setTimeout(() => {
      setRemaining((prev) => prev - 1);
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [autoEnabled, remaining, loading, onApprove]);

  function toggleTool(tool: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(tool)) next.delete(tool);
      else next.add(tool);
      return next;
    });
  }

  return (
    <div className={styles.approval}>
      <div>
        <strong>{t("approvalTitle")}</strong>
        <p>{t("approvalHelp")}</p>
        {autoEnabled ? (
          <p className={styles.approvalCountdown} aria-live="polite">
            {t("approvalCountdown", { seconds: remaining })}{" "}
            <button
              type="button"
              className={styles.linkish}
              disabled={loading}
              onClick={() => setAutoEnabled(false)}
            >
              {t("approvalCancelAuto")}
            </button>
          </p>
        ) : null}
        {authContext?.enabled ? (
          <p className={styles.authScanContext}>
            <strong>
              {t("authScan.approvalAs", {
                username: authContext.username_hint ?? "—",
              })}
            </strong>
            <br />
            {t("authScan.approvalExcluded", {
              paths: (authContext.excluded_paths ?? []).join(", ") || "(none)",
            })}
          </p>
        ) : authContext?.message ? (
          <p className={styles.authScanContext}>{authContext.message}</p>
        ) : null}
        {plannedTools.length > 0 ? (
          <fieldset className={styles.toolChecklist} disabled={loading}>
            <legend>{t("approvalToolsLabel")}</legend>
            {plannedTools.map((tool) => (
              <label key={tool} className={styles.toolOption}>
                <input
                  type="checkbox"
                  checked={selected.has(tool)}
                  onChange={() => toggleTool(tool)}
                />
                {tool}
              </label>
            ))}
          </fieldset>
        ) : (
          <p className={styles.authScanContext}>
            Active tests for {target}
          </p>
        )}
      </div>
      <div className={styles.rowActions}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={loading || selected.size === 0}
          onClick={() => {
            setAutoEnabled(false);
            void onApprove(Array.from(selected));
          }}
        >
          {loading ? t("saving") : t("approveActiveTests")}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={loading}
          onClick={() => {
            setAutoEnabled(false);
            void onReject();
          }}
        >
          {t("skipActiveTests")}
        </button>
      </div>
      {error ? (
        <p className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
