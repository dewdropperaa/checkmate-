"use client";

import Image from "next/image";
import { useCallback, useEffect, useId, useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import { Link, usePathname } from "@/i18n/navigation";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import styles from "./landing.module.css";

const SECTION_LINKS = [
  { href: "#how", key: "how" as const },
  { href: "#features", key: "features" as const },
  { href: "#pricing", key: "pricing" as const },
  { href: "#faq", key: "faq" as const },
];

export function SiteHeader() {
  const t = useTranslations("nav");
  const locale = useLocale();
  const pathname = usePathname();
  const menuId = useId();
  const [menuOpen, setMenuOpen] = useState(false);

  const closeMenu = useCallback(() => setMenuOpen(false), []);

  const sectionHref = useCallback(
    (hash: string) => (pathname === "/" ? hash : `/${locale}${hash}`),
    [locale, pathname],
  );

  useEffect(() => {
    if (!menuOpen) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeMenu();
    };

    const onResize = () => {
      if (window.matchMedia("(min-width: 900px)").matches) closeMenu();
    };

    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onResize);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onResize);
      document.body.style.overflow = previousOverflow;
    };
  }, [menuOpen, closeMenu]);

  return (
    <header>
      <div className={styles.header}>
        <div className="container">
          <div className={styles.titlebar} aria-hidden="true">
            <span className={`${styles.dot} ${styles.dotRed}`} />
            <span className={`${styles.dot} ${styles.dotAmber}`} />
            <span className={`${styles.dot} ${styles.dotGreen}`} />
            <span className={styles.titlebarLabel}>checkmate — zsh</span>
          </div>
          <div className={styles.navRow}>
            <Link href="/" className={styles.brandLink} onClick={closeMenu}>
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
            <nav className={styles.desktopNav} aria-label={t("primary")}>
              <ul className={styles.navLinks}>
                {SECTION_LINKS.map((link) => (
                  <li key={link.key}>
                    <a href={sectionHref(link.href)}>{t(link.key)}</a>
                  </li>
                ))}
              </ul>
            </nav>
            <div className={styles.navActions}>
              <ThemeToggle compact />
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
              <Link
                href="/signin"
                className={`btn btn-ghost ${styles.desktopAuth}`}
              >
                {t("signIn")}
              </Link>
              <Link
                href="/signup"
                className={`btn btn-primary ${styles.desktopAuth}`}
              >
                {t("getStarted")}
              </Link>
              <button
                type="button"
                className={styles.menuToggle}
                aria-expanded={menuOpen}
                aria-controls={menuId}
                aria-label={menuOpen ? t("closeMenu") : t("openMenu")}
                onClick={() => setMenuOpen((open) => !open)}
              >
                <span className={styles.menuToggleBars} data-open={menuOpen} />
              </button>
            </div>
          </div>
          <div
            id={menuId}
            className={styles.mobilePanel}
            data-open={menuOpen}
            hidden={!menuOpen}
          >
            <nav aria-label={t("primary")}>
              <ul className={styles.mobileLinks}>
                {SECTION_LINKS.map((link) => (
                  <li key={link.key}>
                    <a href={sectionHref(link.href)} onClick={closeMenu}>
                      {t(link.key)}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
            <div className={styles.mobileAuth}>
              <Link
                href="/signin"
                className="btn btn-ghost"
                onClick={closeMenu}
              >
                {t("signIn")}
              </Link>
              <Link
                href="/signup"
                className="btn btn-primary"
                onClick={closeMenu}
              >
                {t("getStarted")}
              </Link>
            </div>
          </div>
        </div>
      </div>
      {menuOpen ? (
        <button
          type="button"
          className={styles.menuBackdrop}
          aria-label={t("closeMenu")}
          onClick={closeMenu}
        />
      ) : null}
    </header>
  );
}
