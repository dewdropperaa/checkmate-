"use client";

import { useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import type { User } from "firebase/auth";
import {
  ApiError,
  verifyFindingFix,
  type ScanFinding,
  type VerifyFixResult,
} from "@/lib/api";
import styles from "./dashboard.module.css";

type Summary = {
  result?: string;
  evidence?: string | null;
  checked_at?: string;
  attempt_count?: number;
};

type Props = {
  currentUser: User;
  scanId: string;
  finding: ScanFinding;
  findingId: string;
  initialSummary?: Summary | null;
  highlight?: boolean;
};

function resultLabel(
  t: ReturnType<typeof useTranslations>,
  result: string | undefined,
): string {
  if (result === "fixed") return t("verifyFix.results.fixed");
  if (result === "still_present") return t("verifyFix.results.stillPresent");
  if (result === "changed") return t("verifyFix.results.changed");
  return result ?? "";
}

export function FindingCard({
  currentUser,
  scanId,
  finding,
  findingId,
  initialSummary,
  highlight,
}: Props) {
  const t = useTranslations("dashboard");
  const locale = useLocale();
  const [summary, setSummary] = useState<Summary | null>(initialSummary ?? null);
  const [history, setHistory] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const severity = String(finding.severity || "info");
  const buttonLabel =
    locale.startsWith("fr")
      ? t("verifyFix.actionFr")
      : t("verifyFix.action");

  async function handleVerify() {
    setLoading(true);
    setError(null);
    try {
      const token = await currentUser.getIdToken();
      const result = await verifyFindingFix(token, scanId, findingId);
      setSummary({
        result: result.result,
        evidence: result.evidence,
        checked_at: result.checked_at,
        attempt_count: result.attempt_count,
      });
      setHistory(result.history);
    } catch (cause) {
      if (cause instanceof ApiError && cause.code === "verify_fix_rate_limited") {
        setError(t("verifyFix.rateLimited"));
      } else {
        setError(cause instanceof Error ? cause.message : t("verifyFix.error"));
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <article
      id={`finding-${findingId}`}
      className={styles.findingCard}
      data-severity={severity}
      data-highlighted={highlight ? "true" : undefined}
    >
      <div className={styles.findingHeader}>
        <span className={styles.severity} data-severity={severity}>
          {severity}
        </span>
        <h3 className={styles.findingTitle}>
          {String(finding.type || finding.description || findingId)}
        </h3>
      </div>
      <p className={styles.findingMeta}>
        <code>{String(finding.url || "—")}</code>
        {finding.tool ? (
          <span className={styles.muted}> · {String(finding.tool)}</span>
        ) : null}
      </p>
      {finding.description ? (
        <p className={styles.findingDesc}>{String(finding.description)}</p>
      ) : null}

      <div className={styles.findingActions}>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={loading}
          onClick={() => void handleVerify()}
        >
          {loading ? t("verifyFix.checking") : `[ ${buttonLabel} ]`}
        </button>
        {summary?.result ? (
          <span
            className={styles.verifyBadge}
            data-result={summary.result as VerifyFixResult}
          >
            {resultLabel(t, summary.result)}
            {summary.attempt_count && summary.attempt_count > 1
              ? ` · ${t("verifyFix.attempts", { count: summary.attempt_count })}`
              : null}
          </span>
        ) : null}
      </div>

      {summary?.evidence ? (
        <p className={styles.verifyEvidence}>{summary.evidence}</p>
      ) : null}
      {error ? (
        <p className={styles.error} role="alert">
          [ {error} ]
        </p>
      ) : null}

      {history.length > 1 ? (
        <details className={styles.verifyHistory}>
          <summary>{t("verifyFix.history")}</summary>
          <ul>
            {history.map((entry) => (
              <li key={String(entry.id ?? entry.checked_at)}>
                <strong>{resultLabel(t, String(entry.result))}</strong>
                {" · "}
                {String(entry.checked_at ?? "")}
                {entry.evidence ? (
                  <div className={styles.muted}>{String(entry.evidence)}</div>
                ) : null}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </article>
  );
}
