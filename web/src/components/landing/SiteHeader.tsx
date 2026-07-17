"use client";

import Image from "next/image";
import { useLocale, useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";
import styles from "./landing.module.css";

export function SiteHeader() {
  const t = useTranslations("nav");
  const locale = useLocale();

  return (
    <header className={styles.header}>
      <div className="container">
        <div className={styles.titlebar} aria-hidden="true">
          <span className={`${styles.dot} ${styles.dotRed}`} />
          <span className={`${styles.dot} ${styles.dotAmber}`} />
          <span className={`${styles.dot} ${styles.dotGreen}`} />
          <span className={styles.titlebarLabel}>checkmate — zsh</span>
        </div>
        <div className={styles.navRow}>
          <Link href="/" className={styles.brandLink}>
            <Image
              src="/logo.png"
              alt=""
              width={28}
              height={28}
              className={styles.brandMark}
              priority
            />
            checkmate
          </Link>
          <nav aria-label="Primary">
            <ul className={styles.navLinks}>
              <li>
                <a href="#how">{t("how")}</a>
              </li>
              <li>
                <a href="#features">{t("features")}</a>
              </li>
              <li>
                <a href="#pricing">{t("pricing")}</a>
              </li>
              <li>
                <a href="#faq">{t("faq")}</a>
              </li>
            </ul>
          </nav>
          <div className={styles.navActions}>
            <div className={styles.langSwitch} aria-label={t("lang")}>
              <Link
                href="/"
                locale="fr"
                className={locale === "fr" ? styles.langActive : undefined}
                hrefLang="fr"
              >
                FR
              </Link>
              <Link
                href="/"
                locale="en"
                className={locale === "en" ? styles.langActive : undefined}
                hrefLang="en"
              >
                EN
              </Link>
            </div>
            <Link href="/signin" className="btn btn-ghost">
              {t("signIn")}
            </Link>
            <Link href="/signup" className="btn btn-primary">
              {t("getStarted")}
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}
