"use client";

import { Fragment } from "react";
import { useLocale, useTranslations } from "next-intl";
import type { ScanHistoryItem } from "@/lib/api";
import styles from "./dashboard.module.css";

const PIPELINE = [
  "recon",
  "passive_detection",
  "human_approval_gate",
  "active_detection",
  "verification",
  "scoring",
  "reporting",
] as const;

const ACTIVE_STATUSES = new Set([
  "pending",
  "running",
  "detecting",
  "scored",
  "reported",
]);

export function PipelineProgress({
  currentNode,
}: {
  currentNode: string | null;
}) {
  const t = useTranslations("dashboard.pipeline");
  const normalized =
    currentNode === "plan_active_tests" ? "human_approval_gate" : currentNode;
  const activeIndex = PIPELINE.findIndex((step) => step === normalized);
  return (
    <div className={styles.progress} aria-label={t("label")}>
      {PIPELINE.map((step, index) => (
        <Fragment key={step}>
          {index > 0 ? (
            <span className={styles.progressLine} aria-hidden="true" />
          ) : null}
          <span
            className={styles.progressStep}
            data-state={
              index === activeIndex
                ? "active"
                : activeIndex >= 0 && index < activeIndex
                  ? "complete"
                  : "pending"
            }
            aria-current={step === normalized ? "step" : undefined}
          >
            <span className={styles.stepMarker} aria-hidden="true">
              {activeIndex >= 0 && index < activeIndex ? "✓" : index + 1}
            </span>
            {t(step)}
          </span>
        </Fragment>
      ))}
    </div>
  );
}

type Props = {
  scans: ScanHistoryItem[];
  loading?: boolean;
  page: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  onView: (scan: ScanHistoryItem) => void;
  onRescan: (target: string) => void;
};

export function ScanHistoryTable({
  scans,
  loading = false,
  page,
  totalPages,
  onPageChange,
  onView,
  onRescan,
}: Props) {
  const t = useTranslations("dashboard");
  const locale = useLocale();

  if (loading) {
    return <p className={styles.loading}>&gt; {t("historyLoading")}</p>;
  }
  if (scans.length === 0) {
    return <p className={styles.empty}>&gt; {t("emptyHistory")}</p>;
  }

  return (
    <>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>{t("columns.target")}</th>
              <th>{t("columns.date")}</th>
              <th>{t("columns.risk")}</th>
              <th>{t("columns.status")}</th>
              <th>{t("columns.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => {
              const inProgress = ACTIVE_STATUSES.has(scan.status);
              return (
                <Fragment key={scan.id}>
                  <tr>
                    <td
                      className={styles.target}
                      title={scan.target}
                      data-label={t("columns.target")}
                    >
                      {scan.target}
                    </td>
                    <td data-label={t("columns.date")}>
                      {new Intl.DateTimeFormat(locale, {
                        dateStyle: "short",
                        timeStyle: "short",
                      }).format(new Date(scan.created_at))}
                    </td>
                    <td data-label={t("columns.risk")}>
                      <span
                        className={styles.severity}
                        data-severity={scan.severity ?? "info"}
                      >
                        {scan.overall_risk_score === null
                          ? "—"
                          : `${scan.overall_risk_score.toFixed(1)} / 10`}
                      </span>
                    </td>
                    <td data-label={t("columns.status")}>
                      <span className={styles.statusBadge}>
                        {t(`statuses.${scan.status}`)}
                      </span>
                    </td>
                    <td data-label={t("columns.actions")}>
                      <div className={styles.rowActions}>
                        <button
                          type="button"
                          className={`btn ${styles.smallButton}`}
                          onClick={() => onView(scan)}
                        >
                          {t("view")}
                        </button>
                        <button
                          type="button"
                          className={`btn ${styles.smallButton}`}
                          onClick={() => onRescan(scan.target)}
                        >
                          {t("rescan")}
                        </button>
                      </div>
                    </td>
                  </tr>
                  {inProgress ? (
                    <tr>
                      <td colSpan={5}>
                        <PipelineProgress currentNode={scan.current_node} />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      {totalPages > 1 ? (
        <nav className={styles.pagination} aria-label={t("pagination.label")}>
          <button
            type="button"
            className={`btn ${styles.smallButton}`}
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
          >
            {t("pagination.previous")}
          </button>
          <span>{t("pagination.page", { page, total: totalPages })}</span>
          <button
            type="button"
            className={`btn ${styles.smallButton}`}
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
          >
            {t("pagination.next")}
          </button>
        </nav>
      ) : null}
    </>
  );
}
