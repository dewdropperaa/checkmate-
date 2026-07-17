"use client";

import { useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";
import styles from "./landing.module.css";

export function CTA() {
  const t = useTranslations("cta");

  return (
    <section className={styles.ctaSection}>
      <div className={styles.ctaGlow} />
      <div className="container">
        <div className={styles.ctaContent}>
          <h2 className={styles.ctaTitle}>{t("title")}</h2>
          <p className={styles.ctaText}>{t("text")}</p>
          <div className={styles.ctaButtons}>
            <Link href="/signup" className="btn btn-primary btn-large">
              {t("primary")}
            </Link>
            <a href="mailto:hello@checkmate.ma" className="btn btn-secondary">
              {t("secondary")}
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
