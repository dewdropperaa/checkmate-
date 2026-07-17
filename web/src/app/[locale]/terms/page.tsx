import { getTranslations, setRequestLocale } from "next-intl/server";
import { SiteFooter } from "@/components/landing/SiteFooter";
import { SiteHeader } from "@/components/landing/SiteHeader";
import {
  LegalDocument,
  type LegalSection,
} from "@/components/legal/LegalDocument";

type Props = {
  params: Promise<{ locale: string }>;
};

export default async function TermsPage({ params }: Props) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations("legal");
  const sections = t.raw("termsSections") as LegalSection[];

  return (
    <>
      <SiteHeader />
      <main id="main" className="container">
        <LegalDocument
          title={t("termsTitle")}
          lastUpdated={t("lastUpdated")}
          sections={sections}
          backLabel={t("backHome")}
        />
      </main>
      <SiteFooter />
    </>
  );
}
