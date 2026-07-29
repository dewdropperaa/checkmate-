"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import type { User } from "firebase/auth";
import { ApprovalGate } from "@/components/dashboard/ApprovalGate";
import { FindingCard } from "@/components/dashboard/FindingCard";
import { ScanCoverageSection } from "@/components/dashboard/ScanCoverageSection";
import { PipelineProgress } from "@/components/dashboard/ScanHistoryTable";
import {
  ApiError,
  approveScan,
  fetchScanReportPdf,
  getScanReport,
  getScanStatus,
  type ScanCoverage,
  type ScanFinding,
  type ScanReportResponse,
  type ScanStatus,
} from "@/lib/api";
import styles from "./dashboard.module.css";

type InterruptPayload = {
  value?: {
    planned_active_tests?: string[];
    authenticated_scanning?: {
      enabled?: boolean;
      username_hint?: string;
      excluded_paths?: string[];
      message?: string;
    };
  };
  authenticated_scanning?: {
    enabled?: boolean;
    username_hint?: string;
    excluded_paths?: string[];
    message?: string;
  };
} | null;

function isCompletedStatus(status: ScanStatus | null): boolean {
  return Boolean(status?.is_complete && status.status !== "failed");
}

function plannedToolsFromInterrupt(interrupt: InterruptPayload): string[] {
  return interrupt?.value?.planned_active_tests ?? [];
}

function authContextFromInterrupt(interrupt: InterruptPayload) {
  return (
    interrupt?.value?.authenticated_scanning ??
    interrupt?.authenticated_scanning ??
    null
  );
}

function findingId(finding: ScanFinding, index: number): string {
  if (finding.id) return String(finding.id);
  return `${finding.tool || "finding"}-${index}`;
}

type Props = {
  currentUser: User;
  scanId: string;
  initialTarget?: string;
};

export function LiveScanPanel({ currentUser, scanId, initialTarget }: Props) {
  const t = useTranslations("dashboard");
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [approvalLoading, setApprovalLoading] = useState(false);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReportResponse | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [focusFinding, setFocusFinding] = useState<string | null>(null);
  const pdfRequestId = useRef(0);
  const loadedPdfScanId = useRef<string | null>(null);
  const loadedReportScanId = useRef<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const fid = params.get("finding");
    if (fid) setFocusFinding(fid);
  }, []);

  const clearPdf = useCallback(() => {
    pdfRequestId.current += 1;
    loadedPdfScanId.current = null;
    setPdfUrl(null);
    setPdfLoading(false);
    setPdfError(null);
  }, []);

  const loadPdfReport = useCallback(
    async (id: string) => {
      const requestId = ++pdfRequestId.current;
      loadedPdfScanId.current = null;
      setPdfUrl(null);
      setPdfError(null);
      setPdfLoading(true);
      try {
        const token = await currentUser.getIdToken();
        const blob = await fetchScanReportPdf(token, id);
        if (requestId !== pdfRequestId.current) return;
        setPdfUrl(URL.createObjectURL(blob));
        loadedPdfScanId.current = id;
      } catch (cause) {
        if (requestId !== pdfRequestId.current) return;
        if (cause instanceof ApiError && cause.code === "report_not_ready") {
          setPdfError(t("reportUnavailable"));
        } else {
          setPdfError(t("reportError"));
        }
      } finally {
        if (requestId === pdfRequestId.current) {
          setPdfLoading(false);
        }
      }
    },
    [currentUser, t],
  );

  const loadJsonReport = useCallback(
    async (id: string) => {
      try {
        const token = await currentUser.getIdToken();
        const data = await getScanReport(token, id);
        setReport(data);
        loadedReportScanId.current = id;
        setReportError(null);
      } catch {
        setReportError(t("findingsError"));
      }
    },
    [currentUser, t],
  );

  const refreshStatus = useCallback(async () => {
    try {
      const token = await currentUser.getIdToken();
      const next = await getScanStatus(token, scanId);
      setStatus(next);
      setLoadError(null);
      if (
        next.is_complete &&
        next.status !== "failed" &&
        loadedPdfScanId.current !== scanId
      ) {
        void loadPdfReport(scanId);
      }
      if (
        next.is_complete &&
        next.status !== "failed" &&
        loadedReportScanId.current !== scanId
      ) {
        void loadJsonReport(scanId);
      }
      return next;
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 404) {
        setLoadError(t("liveScanPage.notFound"));
      } else {
        setLoadError(t("statusError"));
      }
      return null;
    } finally {
      setLoading(false);
    }
  }, [currentUser, loadJsonReport, loadPdfReport, scanId, t]);

  useEffect(() => {
    setLoading(true);
    setStatus(null);
    setLoadError(null);
    setReport(null);
    loadedReportScanId.current = null;
    clearPdf();
    void refreshStatus();
  }, [clearPdf, refreshStatus, scanId]);

  useEffect(() => {
    if (status?.is_complete) return;
    let cancelled = false;

    const poll = async () => {
      if (cancelled) return;
      await refreshStatus();
    };

    const timer = window.setInterval(() => void poll(), 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [refreshStatus, status?.is_complete]);

  useEffect(() => {
    if (!pdfUrl) return;
    return () => {
      URL.revokeObjectURL(pdfUrl);
    };
  }, [pdfUrl]);

  useEffect(() => {
    if (!focusFinding || !report) return;
    const el = document.getElementById(`finding-${focusFinding}`);
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [focusFinding, report]);

  async function handleApproval(approved: boolean, approvedTools?: string[]) {
    setApprovalLoading(true);
    setApprovalError(null);
    try {
      const token = await currentUser.getIdToken();
      await approveScan(
        token,
        scanId,
        approved,
        approved ? approvedTools : [],
      );
      await refreshStatus();
    } catch (cause) {
      setApprovalError(
        cause instanceof Error ? cause.message : t("approvalError"),
      );
      throw cause;
    } finally {
      setApprovalLoading(false);
    }
  }

  function downloadPdf() {
    if (!pdfUrl) return;
    const link = document.createElement("a");
    link.href = pdfUrl;
    link.download = `checkmate-${scanId}.pdf`;
    link.click();
  }

  const findings = useMemo(() => report?.findings ?? [], [report]);
  const coverage: ScanCoverage | null = report?.coverage ?? null;
  const summaries = report?.verify_fix_summaries ?? {};

  if (loading && !status) {
    return (
      <p className={styles.loading} aria-busy="true">
        &gt; {t("liveScanPage.loading")}
      </p>
    );
  }

  if (loadError) {
    return (
      <p className={styles.error} role="alert">
        [ {loadError} ]
      </p>
    );
  }

  const target = status?.target ?? initialTarget ?? "";
  const displayStatus = status?.status ?? "pending";
  const completed = isCompletedStatus(status);
  const awaitingApproval =
    Boolean(status?.pending_interrupt) ||
    Boolean(
      status?.human_approval_needed &&
        !status.human_approved &&
        !status.is_complete,
    );
  const interrupt = status?.pending_interrupt as InterruptPayload;

  return (
    <section className={styles.liveScan} aria-live="polite">
      <div className={styles.panelHeading}>
        <div>
          <div className={styles.liveHeading}>
            {!completed ? (
              <span className={styles.liveIndicator} aria-hidden="true">
                <span className={styles.liveDot} />
                {t("liveScanPage.live")}
              </span>
            ) : null}
            <h1 className={styles.liveTitle}>
              {completed ? t("report") : t("liveScan")}
            </h1>
          </div>
          <p className={styles.scanTarget}>{target}</p>
        </div>
        <span className={styles.statusBadge}>{t(`statuses.${displayStatus}`)}</span>
      </div>

      {completed ? (
        <>
          <div className={styles.reportActions}>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!pdfUrl || pdfLoading}
              onClick={downloadPdf}
            >
              {t("downloadPdf")}
            </button>
          </div>

          {coverage ? <ScanCoverageSection coverage={coverage} /> : null}

          <section
            className={styles.findingsSection}
            aria-labelledby="findings-title"
          >
            <h2 id="findings-title" className={styles.panelTitle}>
              {t("findingsTitle")}
            </h2>
            {reportError ? (
              <p className={styles.error} role="alert">
                [ {reportError} ]
              </p>
            ) : null}
            {findings.length === 0 && !reportError ? (
              <p className={styles.muted}>{t("findingsEmpty")}</p>
            ) : (
              <div className={styles.findingsList}>
                {findings.map((finding, index) => {
                  const id = findingId(finding, index);
                  return (
                    <FindingCard
                      key={id}
                      currentUser={currentUser}
                      scanId={scanId}
                      finding={finding}
                      findingId={id}
                      initialSummary={summaries[id] ?? null}
                      highlight={focusFinding === id}
                    />
                  );
                })}
              </div>
            )}
          </section>

          {pdfLoading ? (
            <p className={styles.reportLoading}>&gt; {t("reportLoading")}</p>
          ) : null}
          {pdfError ? (
            <p className={styles.error} role="alert">
              [ {pdfError} ]
            </p>
          ) : null}
          {pdfUrl ? (
            <iframe
              className={styles.reportFrame}
              src={pdfUrl}
              title={t("report")}
            />
          ) : null}
        </>
      ) : (
        <>
          <PipelineProgress currentNode={status?.current_node ?? null} />
          {awaitingApproval ? (
            <ApprovalGate
              target={target}
              plannedTools={plannedToolsFromInterrupt(interrupt)}
              authContext={authContextFromInterrupt(interrupt)}
              loading={approvalLoading}
              error={approvalError}
              onApprove={async (tools) => {
                await handleApproval(true, tools);
              }}
              onReject={async () => {
                await handleApproval(false, []);
              }}
            />
          ) : null}
        </>
      )}
    </section>
  );
}
