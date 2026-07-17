"use client";

import Image from "next/image";
import { useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";
import styles from "./landing.module.css";

export function SiteFooter() {
  const t = useTranslations("footer");

  return (
    <footer className={styles.footer}>
      <div className="container">
        <div className={styles.footerGrid}>
          <div>
            <div className={styles.footerBrand}>
              <Image
                src="/logo.png"
                alt=""
                width={22}
                height={22}
                className={styles.footerMark}
              />
              checkmate
            </div>
            <p className={styles.footerTag}>{t("tagline")}</p>
          </div>
          <ul className={styles.footerLinks}>
            <li>
              <Link href="/terms">{t("terms")}</Link>
            </li>
            <li>
              <Link href="/privacy">{t("privacy")}</Link>
            </li>
            <li>
              {/* TODO: confirm public contact address before launch */}
              <a href="mailto:hello@checkmate.ma">{t("contact")}</a>
            </li>
          </ul>
        </div>
        <div className={styles.footerBottom}>
          <p className={styles.footerRights}>{t("rights")}</p>
          <Link href="/signup" className="btn btn-primary">
            {t("cta")}
          </Link>
        </div>
      </div>
    </footer>
  );
}
