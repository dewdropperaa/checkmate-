import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { AuthForm } from "@/components/auth/AuthForm";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SiteHeader } from "@/components/landing/SiteHeader";
import styles from "@/components/auth/auth.module.css";

type Props = {
  params: Promise<{ locale: string }>;
};

export default async function SignupPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations("auth");

  return (
    <>
      <SiteHeader />
      <main id="main" className={`container ${styles.authPage}`}>
        <AuthGuard mode="guest">
          <h1>{t("signupTitle")}</h1>
          <p className={styles.authSubtitle}>{t("signupSubtitle")}</p>
          <AuthForm mode="signup" />
          <p className={styles.authBack}>
            <Link href="/" className="btn btn-ghost">
              ← {t("backHome")}
            </Link>
          </p>
        </AuthGuard>
      </main>
      <SiteFooter />
    </>
  );
}
