import { useTranslations } from "next-intl";
import styles from "./landing.module.css";

const FEATURE_ITEMS = [
  "headerChecks",
  "tlsChecks",
  "exposedFiles",
  "subdomains",
  "aiSummary",
  "agencyReports",
] as const;

export function Features() {
  const t = useTranslations("features");

  return (
    <section id="features" className="section" aria-labelledby="features-heading">
      <div className="container">
        <p className="section-label">capabilities</p>
        <h2 id="features-heading" className="section-title">
          {t("title")}
        </h2>
        <p className="section-sub">{t("subtitle")}</p>
        <div className={styles.featureGrid}>
          {FEATURE_ITEMS.map((key) => (
            <article key={key} className={styles.featureCard}>
              <h3>{t(`items.${key}.title`)}</h3>
              <p>{t(`items.${key}.body`)}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
