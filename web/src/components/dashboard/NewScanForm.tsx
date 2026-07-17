"use client";

import { useEffect, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import type { User } from "firebase/auth";
import { Link } from "@/i18n/navigation";
import {
  ApiError,
  createScan,
  type BackendUser,
  type ScanCreateResponse,
  type ScanHistoryResponse,
} from "@/lib/api";
import { canAddSite, canRunScan } from "@/lib/quota";
import styles from "./dashboard.module.css";

type Props = {
  currentUser: User;
  backendUser: BackendUser;
  usage: ScanHistoryResponse;
  requestedTarget?: string;
  onCreated: (scan: ScanCreateResponse) => void;
};

export function NewScanForm({
  currentUser,
  backendUser,
  usage,
  requestedTarget,
  onCreated,
}: Props) {
  const t = useTranslations("dashboard");
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [quotaReason, setQuotaReason] = useState<
    "target_limit" | "scan_limit" | null
  >(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (requestedTarget) {
      setTarget(requestedTarget);
      setAuthorized(false);
      setQuotaReason(null);
      setError(null);
    }
  }, [requestedTarget]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setQuotaReason(null);
    if (!authorized || !target.trim()) return;

    const addSite = canAddSite(backendUser, usage, target);
    if (!addSite.allowed) {
      setQuotaReason(addSite.reason);
      return;
    }
    const runScan = canRunScan(backendUser, usage);
    if (!runScan.allowed) {
      setQuotaReason(runScan.reason);
      return;
    }

    setSubmitting(true);
    try {
      const token = await currentUser.getIdToken();
      const scan = await createScan(token, target.trim());
      onCreated(scan);
      setAuthorized(false);
    } catch (cause) {
      if (
        cause instanceof ApiError &&
        ["target_quota_exceeded", "scan_quota_exceeded"].includes(
          cause.code ?? "",
        )
      ) {
        setQuotaReason(
          cause.code === "target_quota_exceeded"
            ? "target_limit"
            : "scan_limit",
        );
      } else {
        setError(cause instanceof Error ? cause.message : t("scanError"));
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className={styles.panel} aria-labelledby="new-scan-title">
      <div className={styles.panelHeading}>
        <div>
          <h2 id="new-scan-title" className={styles.panelTitle}>
            {t("newScan")}
          </h2>
          <p className={styles.panelDescription}>{t("newScanHelp")}</p>
        </div>
        <span className={styles.usage}>
          {t("usage", {
            used: usage.scans_this_month,
            limit: backendUser.scans_per_month ?? "∞",
          })}
        </span>
      </div>
      <form onSubmit={(event) => void submit(event)}>
        <label className={styles.fieldLabel} htmlFor="scan-target">
          {t("targetLabel")}
        </label>
        <div className={styles.scanForm}>
          <input
            id="scan-target"
            className={styles.input}
            type="text"
            inputMode="url"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={t("targetPlaceholder")}
            aria-label={t("targetLabel")}
            required
          />
          <button
            className="btn btn-primary"
            type="submit"
            disabled={!authorized || submitting}
          >
            {submitting ? t("starting") : t("startScan")}
          </button>
        </div>
        <label className={styles.authorization}>
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
          />
          <span>{t("authorization")}</span>
        </label>
        {!authorized ? (
          <p className={styles.formHint}>{t("authorizationHelp")}</p>
        ) : null}
      </form>
      {quotaReason ? (
        <p className={styles.warning} role="alert">
          [ {t(`quota.${quotaReason}`)}{" "}
          <Link href="/#pricing">{t("quota.pricingLink")}</Link> ]
        </p>
      ) : null}
      {error ? (
        <p className={styles.error} role="alert">
          [ {error} ]
        </p>
      ) : null}
    </section>
  );
}
