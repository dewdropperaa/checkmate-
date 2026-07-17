"use client";

import { useTranslations } from "next-intl";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { useAuth } from "@/contexts/AuthContext";
import { Link } from "@/i18n/navigation";
import styles from "@/components/auth/auth.module.css";

function DashboardContent() {
  const t = useTranslations("auth");
  const { currentUser, backendUser, signOut } = useAuth();

  return (
    <div className={styles.authPage}>
      <h1>{t("dashboardTitle")}</h1>
      <p className={styles.authSubtitle}>
        {t("dashboardWelcome")}
        {currentUser?.email ? ` (${currentUser.email})` : null}
        {backendUser?.plan_id ? ` · ${backendUser.plan_id}` : null}
      </p>
      <div style={{ display: "flex", gap: "0.75rem", marginTop: "1.5rem" }}>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void signOut()}
        >
          {t("signOut")}
        </button>
        <Link href="/" className="btn btn-ghost">
          ← {t("backHome")}
        </Link>
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
