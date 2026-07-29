"use client";

import { use } from "react";
import { useTranslations } from "next-intl";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { LiveScanPanel } from "@/components/dashboard/LiveScanPanel";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { useAuth } from "@/contexts/AuthContext";
import { Link } from "@/i18n/navigation";
import styles from "@/components/dashboard/dashboard.module.css";

type Props = {
  params: Promise<{ scanId: string }>;
};

function ScanLiveContent({ scanId }: { scanId: string }) {
  const t = useTranslations("dashboard");
  const authT = useTranslations("auth");
  const { currentUser } = useAuth();

  if (!currentUser) {
    return null;
  }

  return (
    <div className={styles.dashboard}>
      <header className={styles.header}>
        <div>
          <p className={styles.eyebrow}>{t("securityOverview")}</p>
          <Link href="/dashboard" className={styles.backLink}>
            ← {t("liveScanPage.backDashboard")}
          </Link>
        </div>
        <div className={styles.topActions}>
          <Link href="/" className="btn btn-ghost">
            ← {authT("backHome")}
          </Link>
        </div>
      </header>

      <LiveScanPanel currentUser={currentUser} scanId={scanId} />

      <div className={styles.cornerControls}>
        <ThemeToggle compact />
        <div className={styles.avatar} aria-hidden="true">
          {(currentUser.email?.[0] ?? "?").toUpperCase()}
        </div>
      </div>
    </div>
  );
}

export default function ScanLivePage({ params }: Props) {
  const { scanId } = use(params);

  return (
    <main id="main" className="container">
      <AuthGuard mode="protected">
        <ScanLiveContent scanId={scanId} />
      </AuthGuard>
    </main>
  );
}
