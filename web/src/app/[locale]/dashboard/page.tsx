"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { NewScanForm } from "@/components/dashboard/NewScanForm";
import { RiskTrendChart } from "@/components/dashboard/RiskTrendChart";
import { SiteAuthPanel } from "@/components/dashboard/SiteAuthPanel";
import { ScanHistoryTable } from "@/components/dashboard/ScanHistoryTable";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { useAuth } from "@/contexts/AuthContext";
import { Link, useRouter } from "@/i18n/navigation";
import {
  getRiskTrend,
  getScanHistory,
  getScanStatus,
  type RiskTrendPoint,
  type ScanCreateResponse,
  type ScanHistoryResponse,
  type ScanStatus,
} from "@/lib/api";
import { takePendingTarget } from "@/lib/pendingTarget";
import styles from "@/components/dashboard/dashboard.module.css";

const EMPTY_HISTORY: ScanHistoryResponse = {
  scans: [],
  page: 1,
  page_size: 10,
  total: 0,
  total_pages: 1,
  target_count: 0,
  scans_this_month: 0,
  targets: [],
};

function DashboardContent() {
  const authT = useTranslations("auth");
  const t = useTranslations("dashboard");
  const router = useRouter();
  const { currentUser, backendUser, signOut, isSyncing, syncError } = useAuth();
  const [history, setHistory] = useState<ScanHistoryResponse | null>(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rescanTarget, setRescanTarget] = useState<string>();
  const [trendTarget, setTrendTarget] = useState<string>("");
  const [trendPoints, setTrendPoints] = useState<RiskTrendPoint[]>([]);
  const [trendLoading, setTrendLoading] = useState(false);
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

  const loadHistory = useCallback(async () => {
    if (!currentUser || !backendUser) return;
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
  }, [backendUser, currentUser, page, t]);

  useEffect(() => {
    if (!backendUser) {
      setLoading(Boolean(currentUser));
      return;
    }
    setLoading(true);
    void loadHistory();
  }, [backendUser, currentUser, loadHistory]);

  const targets = history?.targets ?? [];

  useEffect(() => {
    if (!trendTarget && targets.length > 0) {
      setTrendTarget(targets[0]);
    }
  }, [targets, trendTarget]);

  const loadTrend = useCallback(async () => {
    if (!currentUser || !backendUser || !trendTarget) {
      setTrendPoints([]);
      return;
    }
    setTrendLoading(true);
    try {
      const token = await currentUser.getIdToken();
      const data = await getRiskTrend(token, trendTarget);
      setTrendPoints(data.points);
    } catch {
      setTrendPoints([]);
    } finally {
      setTrendLoading(false);
    }
  }, [backendUser, currentUser, trendTarget]);

  useEffect(() => {
    void loadTrend();
  }, [loadTrend]);

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
      if (reachedStopState) {
        void loadHistory();
        void loadTrend();
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [currentUser, loadHistory, loadTrend, pollKey]);

  if (!currentUser) {
    return null;
  }

  const usage = history ?? EMPTY_HISTORY;

  if (!backendUser) {
    return (
      <div className={styles.dashboard}>
        <header className={styles.header}>
          <div>
            <p className={styles.eyebrow}>{t("securityOverview")}</p>
            <h1>{authT("dashboardTitle")}</h1>
          </div>
        </header>
        {syncError ? (
          <p className={styles.error} role="alert">
            [ {syncError} ]
          </p>
        ) : (
          <p className={styles.loading} aria-busy={isSyncing}>
            &gt; {isSyncing ? authT("checkingSession") : t("historyLoading")}
          </p>
        )}
      </div>
    );
  }

  function handleCreated(scan: ScanCreateResponse) {
    void loadHistory();
    router.push(`/dashboard/scan/${scan.scan_id}`);
  }

  function viewScan(scanId: string) {
    router.push(`/dashboard/scan/${scanId}`);
  }

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
            {usage.target_count}
            {backendUser.max_targets !== null
              ? ` / ${backendUser.max_targets}`
              : ""}
          </strong>
        </div>
        <div className={styles.stat}>
          <span>{t("scansThisMonth")}</span>
          <strong>
            {usage.scans_this_month}
            {backendUser.scans_per_month !== null
              ? ` / ${backendUser.scans_per_month}`
              : ""}
          </strong>
        </div>
      </div>

      <NewScanForm
        currentUser={currentUser}
        backendUser={backendUser}
        usage={usage}
        requestedTarget={rescanTarget}
        onCreated={handleCreated}
      />

      {targets.length > 0 ? (
        <div className={styles.trendSiteSelect}>
          <label>
            {t("riskTrend.selectSite")}
            <select
              value={trendTarget}
              onChange={(e) => setTrendTarget(e.target.value)}
            >
              {targets.map((site) => (
                <option key={site} value={site}>
                  {site}
                </option>
              ))}
            </select>
          </label>
        </div>
      ) : null}

      <RiskTrendChart
        points={trendPoints}
        target={trendTarget || null}
        loading={trendLoading}
      />

      <SiteAuthPanel
        currentUser={currentUser}
        backendUser={backendUser}
        refreshKey={usage.scans.length}
      />

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
          scans={usage.scans}
          loading={loading}
          page={page}
          totalPages={usage.total_pages}
          onPageChange={setPage}
          onView={(scan) => viewScan(scan.id)}
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
