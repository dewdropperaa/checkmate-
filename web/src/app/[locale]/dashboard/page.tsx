"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { NewScanForm } from "@/components/dashboard/NewScanForm";
import {
  PipelineProgress,
  ScanHistoryTable,
} from "@/components/dashboard/ScanHistoryTable";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { useAuth } from "@/contexts/AuthContext";
import { Link } from "@/i18n/navigation";
import {
  ApiError,
  approveScan,
  fetchScanReportPdf,
  getScanHistory,
  getScanStatus,
  type ScanCreateResponse,
  type ScanHistoryItem,
  type ScanHistoryResponse,
  type ScanStatus,
} from "@/lib/api";
import { takePendingTarget } from "@/lib/pendingTarget";
import styles from "@/components/dashboard/dashboard.module.css";

function isCompletedScan(
  scan: ScanHistoryItem | null,
  status: ScanStatus | null,
): boolean {
  if (status?.is_complete && status.status !== "failed") return true;
  return scan?.status === "completed";
}

function DashboardContent() {
  const authT = useTranslations("auth");
  const t = useTranslations("dashboard");
  const { currentUser, backendUser, signOut } = useAuth();
  const [history, setHistory] = useState<ScanHistoryResponse | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<ScanHistoryItem | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<ScanStatus | null>(null);
  const [rescanTarget, setRescanTarget] = useState<string>();
  const [approvalLoading, setApprovalLoading] = useState(false);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const pdfRequestId = useRef(0);
  const loadedPdfScanId = useRef<string | null>(null);
  const pendingTargetApplied = useRef(false);

  useEffect(() => {
    if (pendingTargetApplied.current) return;
    const fromQuery = new URLSearchParams(window.location.search)
      .get("target")
      ?.trim();
    const fromStorage = takePendingTarget();
    const pending = fromQuery || fromStorage;
    if (!pending) return;
    pendingTargetApplied.current = true;
    setRescanTarget(pending);
  }, []);

  const clearPdf = useCallback(() => {
    pdfRequestId.current += 1;
    loadedPdfScanId.current = null;
    setPdfUrl(null);
    setPdfLoading(false);
    setPdfError(null);
  }, []);

  const loadPdfReport = useCallback(
    async (scanId: string) => {
      if (!currentUser) return;
      const requestId = ++pdfRequestId.current;
      loadedPdfScanId.current = null;
      setPdfUrl(null);
      setPdfError(null);
      setPdfLoading(true);
      try {
        const token = await currentUser.getIdToken();
        const blob = await fetchScanReportPdf(token, scanId);
        if (requestId !== pdfRequestId.current) return;
        const url = URL.createObjectURL(blob);
        loadedPdfScanId.current = scanId;
        setPdfUrl(url);
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

  const loadHistory = useCallback(async () => {
    if (!currentUser) return;
    try {
      const token = await currentUser.getIdToken();
      setHistory(await getScanHistory(token, page));
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : t("historyError"));
      setHistory((current) =>
        current ?? {
          scans: [],
          page,
          page_size: 10,
          total: 0,
          total_pages: 1,
          target_count: 0,
          scans_this_month: 0,
          targets: [],
        },
      );
    } finally {
      setLoading(false);
    }
  }, [currentUser, page, t]);

  useEffect(() => {
    setLoading(true);
    void loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    if (!pdfUrl) return;
    return () => {
      URL.revokeObjectURL(pdfUrl);
    };
  }, [pdfUrl]);

  const pollableIds = useMemo(
    () =>
      (history?.scans ?? [])
        .filter(
          (scan) =>
            !["completed", "failed", "awaiting_approval"].includes(scan.status),
        )
        .map((scan) => scan.id),
    [history?.scans],
  );
  const pollKey = pollableIds.join(",");

  useEffect(() => {
    if (!currentUser || !pollKey) return;
    let cancelled = false;

    const poll = async () => {
      const token = await currentUser.getIdToken();
      const scanIds = pollKey.split(",").filter(Boolean);
      const statuses = await Promise.all(
        scanIds.map((id) =>
          getScanStatus(token, id).catch(() => null),
        ),
      );
      if (cancelled) return;
      const validStatuses = statuses.filter(
        (status): status is ScanStatus => status !== null,
      );
      const reachedStopState = validStatuses.some(
        (status) =>
          status.is_complete ||
          Boolean(status.pending_interrupt) ||
          (status.human_approval_needed && !status.human_approved),
      );
      const selectedUpdate = validStatuses.find(
        (status) => status.scan_id === selected?.id,
      );
      if (selectedUpdate) {
        setSelectedStatus(selectedUpdate);
        if (
          selectedUpdate.is_complete &&
          selectedUpdate.status !== "failed" &&
          loadedPdfScanId.current !== selectedUpdate.scan_id
        ) {
          void loadPdfReport(selectedUpdate.scan_id);
        }
      }
      setHistory((current) => {
        if (!current) return current;
        const byId = new Map(
          validStatuses.map((status) => [status.scan_id, status]),
        );
        return {
          ...current,
          scans: current.scans.map((scan) => {
            const status = byId.get(scan.id);
            if (!status) return scan;
            const awaitingApproval =
              Boolean(status.pending_interrupt) ||
              (status.human_approval_needed && !status.human_approved);
            return {
              ...scan,
              status: awaitingApproval
                ? "awaiting_approval"
                : status.is_complete
                  ? status.status === "failed"
                    ? "failed"
                    : "completed"
                  : status.status,
              current_node: status.current_node,
              updated_at: status.updated_at,
            };
          }),
        };
      });
      if (reachedStopState) void loadHistory();
    };

    void poll();
    const timer = window.setInterval(() => void poll(), 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [currentUser, loadHistory, loadPdfReport, pollKey, selected?.id]);

  if (!currentUser || !backendUser || !history) {
    return (
      <div className={styles.dashboard}>
        <h1>{authT("dashboardTitle")}</h1>
        <p className={styles.loading}>&gt; {t("historyLoading")}</p>
      </div>
    );
  }

  function handleCreated(scan: ScanCreateResponse) {
    const item: ScanHistoryItem = {
      id: scan.scan_id,
      target: scan.target,
      status: scan.status,
      current_node: null,
      overall_risk_score: null,
      severity: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    clearPdf();
    setSelected(item);
    setSelectedStatus(null);
    setHistory((current) =>
      current
        ? {
            ...current,
            scans: [item, ...current.scans].slice(0, current.page_size),
            total: current.total + 1,
            scans_this_month: current.scans_this_month + 1,
          }
        : current,
    );
    void loadHistory();
  }

  async function selectScan(scan: ScanHistoryItem) {
    if (!currentUser) return;
    setSelected(scan);
    setSelectedStatus(null);
    setApprovalError(null);
    clearPdf();
    try {
      const token = await currentUser.getIdToken();
      const status = await getScanStatus(token, scan.id);
      setSelectedStatus(status);
      if (isCompletedScan(scan, status)) {
        await loadPdfReport(scan.id);
      }
    } catch {
      setApprovalError(t("statusError"));
    }
  }

  function downloadPdf() {
    if (!pdfUrl || !selected) return;
    const link = document.createElement("a");
    link.href = pdfUrl;
    link.download = `checkmate-${selected.id}.pdf`;
    link.click();
  }

  async function handleApproval(approved: boolean) {
    if (!selected || !currentUser) return;
    setApprovalLoading(true);
    setApprovalError(null);
    try {
      const token = await currentUser.getIdToken();
      await approveScan(token, selected.id, approved);
      const status = await getScanStatus(token, selected.id);
      setSelectedStatus(status);
      await loadHistory();
    } catch (cause) {
      setApprovalError(
        cause instanceof Error ? cause.message : t("approvalError"),
      );
    } finally {
      setApprovalLoading(false);
    }
  }

  const selectedAwaitingApproval =
    selected?.status === "awaiting_approval" ||
    Boolean(selectedStatus?.pending_interrupt) ||
    Boolean(
      selectedStatus?.human_approval_needed &&
        !selectedStatus.human_approved &&
        !selectedStatus.is_complete,
    );
  const selectedCompleted = isCompletedScan(selected, selectedStatus);

  return (
    <div className={styles.dashboard}>
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>{t("securityOverview")}</p>
          <h1>{authT("dashboardTitle")}</h1>
          <p className={styles.welcome}>
            {t("welcome", { email: currentUser.email ?? "" })}
          </p>
        </div>
        <div className={styles.topActions}>
          <Link href="/connect-extension" className="btn btn-ghost">
            {t("connectExtension")}
          </Link>
          <Link href="/" className="btn btn-ghost">
            ← {authT("backHome")}
          </Link>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void signOut()}
          >
            {authT("signOut")}
          </button>
        </div>
      </header>

      <div className={styles.stats} aria-label={t("accountSummary")}>
        <div className={styles.stat}>
          <span>{t("plan")}</span>
          <strong>{backendUser.plan_id}</strong>
        </div>
        <div className={styles.stat}>
          <span>{t("sitesMonitored")}</span>
          <strong>
            {history.target_count}
            {backendUser.max_targets !== null
              ? ` / ${backendUser.max_targets}`
              : ""}
          </strong>
        </div>
        <div className={styles.stat}>
          <span>{t("scansThisMonth")}</span>
          <strong>
            {history.scans_this_month}
            {backendUser.scans_per_month !== null
              ? ` / ${backendUser.scans_per_month}`
              : ""}
          </strong>
        </div>
      </div>

      <NewScanForm
        currentUser={currentUser}
        backendUser={backendUser}
        usage={history}
        requestedTarget={rescanTarget}
        onCreated={handleCreated}
      />

      {selected ? (
        <section className={styles.panel} aria-live="polite">
          <div className={styles.panelHeading}>
            <div>
              <h2 className={styles.panelTitle}>
                {selectedCompleted ? t("report") : t("liveScan")}
              </h2>
              <p className={styles.scanTarget}>{selected.target}</p>
            </div>
            <span className={styles.statusBadge}>
              {t(`statuses.${selectedStatus?.status ?? selected.status}`)}
            </span>
          </div>
          {selectedCompleted ? (
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
              <PipelineProgress
                currentNode={
                  selectedStatus?.current_node ?? selected.current_node
                }
              />
              {selectedAwaitingApproval ? (
                <div className={styles.approval}>
                  <div>
                    <strong>{t("approvalTitle")}</strong>
                    <p>{t("approvalHelp")}</p>
                  </div>
                  <div className={styles.rowActions}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={approvalLoading}
                      onClick={() => void handleApproval(true)}
                    >
                      {approvalLoading ? t("saving") : t("approveActiveTests")}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={approvalLoading}
                      onClick={() => void handleApproval(false)}
                    >
                      {t("skipActiveTests")}
                    </button>
                  </div>
                </div>
              ) : null}
            </>
          )}
          {approvalError ? (
            <p className={styles.error} role="alert">
              {approvalError}
            </p>
          ) : null}
        </section>
      ) : null}

      <section className={styles.history} aria-labelledby="history-title">
        <h2 id="history-title" className={styles.panelTitle}>
          {t("history")}
        </h2>
        {error ? (
          <p className={styles.error} role="alert">
            [ {error} ]
          </p>
        ) : null}
        <ScanHistoryTable
          scans={history.scans}
          loading={loading}
          page={page}
          totalPages={history.total_pages}
          onPageChange={setPage}
          onView={(scan) => void selectScan(scan)}
          onRescan={(target) => {
            setRescanTarget(target);
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
        />
      </section>
      <div className={styles.cornerControls}>
        <ThemeToggle compact />
        <div className={styles.avatar} aria-hidden="true">
          {(currentUser.email?.[0] ?? "?").toUpperCase()}
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <main id="main" className="container">
      <AuthGuard mode="protected">
        <DashboardContent />
      </AuthGuard>
    </main>
  );
}
