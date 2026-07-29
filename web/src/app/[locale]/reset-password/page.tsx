import { Suspense } from "react";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { ResetPasswordForm } from "@/components/auth/ResetPasswordForm";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SiteHeader } from "@/components/landing/SiteHeader";
import styles from "@/components/auth/auth.module.css";

type Props = {
  params: Promise<{ locale: string }>;
};

export default async function ResetPasswordPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations("auth");

  return (
    <>
      <SiteHeader />
      <main id="main" className={`container ${styles.authPage}`}>
        <AuthGuard mode="guest">
          <h1>{t("resetPasswordTitle")}</h1>
          <p className={styles.authSubtitle}>{t("resetPasswordSubtitle")}</p>
          <div className={styles.formWrap}>
            <Suspense
              fallback={<p className={styles.authLoading}>{t("checkingSession")}</p>}
            >
              <ResetPasswordForm />
            </Suspense>
          </div>
          <p className={styles.authBack}>
            <Link href="/signin" className="btn btn-ghost">
              ← {t("backToSignIn")}
            </Link>
          </p>
        </AuthGuard>
      </main>
      <SiteFooter />
    </>
  );
}
