import { getTranslations, setRequestLocale } from "next-intl/server";
import { AuthGuard } from "@/components/auth/AuthGuard";
import { ConnectExtensionPanel } from "@/components/auth/ConnectExtensionPanel";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SiteHeader } from "@/components/landing/SiteHeader";
import styles from "@/components/auth/auth.module.css";

type Props = {
  params: Promise<{ locale: string }>;
};

export default async function ConnectExtensionPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations("connectExtension");

  return (
    <>
      <SiteHeader />
      <main id="main" className={`container ${styles.authPage}`}>
        <AuthGuard mode="protected">
          <h1>{t("title")}</h1>
          <p className={styles.authSubtitle}>{t("subtitle")}</p>
          <ConnectExtensionPanel />
        </AuthGuard>
      </main>
      <SiteFooter />
    </>
  );
}
