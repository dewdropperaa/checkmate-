import { getTranslations, setRequestLocale } from "next-intl/server";
import { Link } from "@/i18n/navigation";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SiteHeader } from "@/components/landing/SiteHeader";
import styles from "@/components/landing/landing.module.css";

type Props = {
  params: Promise<{ locale: string }>;
};

export default async function TermsPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations("legal");

  return (
    <>
      <SiteHeader />
      <main id="main" className={`container ${styles.stubPage}`}>
        <h1>{t("termsTitle")}</h1>
        <p>{t("placeholder")}</p>
        <p>
          <Link href="/" className="btn btn-secondary">
            ← checkmate
          </Link>
        </p>
      </main>
      <SiteFooter />
    </>
  );
}
