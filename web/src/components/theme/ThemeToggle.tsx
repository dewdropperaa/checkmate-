"use client";

import { useTranslations } from "next-intl";
import { useTheme } from "./ThemeProvider";
import type { ThemePreference } from "@/lib/theme";
import styles from "./theme.module.css";

function SunIcon() {
  return (
    <svg
      className={styles.icon}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="square"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg
      className={styles.icon}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="square"
      aria-hidden="true"
    >
      <path d="M21 14.5A8.5 8.5 0 0 1 9.5 3 7 7 0 1 0 21 14.5z" />
    </svg>
  );
}

function SystemIcon() {
  return (
    <svg
      className={styles.icon}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="square"
      aria-hidden="true"
    >
      <rect x="3" y="4" width="18" height="12" rx="0" />
      <path d="M8 20h8M12 16v4" />
    </svg>
  );
}

function PreferenceIcon({ preference }: { preference: ThemePreference }) {
  if (preference === "light") return <SunIcon />;
  if (preference === "dark") return <MoonIcon />;
  return <SystemIcon />;
}

type ThemeToggleProps = {
  className?: string;
  /** Compact control for sticky headers / avatar corner. */
  compact?: boolean;
};

export function ThemeToggle({ className, compact = false }: ThemeToggleProps) {
  const t = useTranslations("theme");
  const { preference, cyclePreference } = useTheme();

  return (
    <button
      type="button"
      className={[styles.toggle, compact ? styles.compact : "", className]
        .filter(Boolean)
        .join(" ")}
      onClick={cyclePreference}
      aria-label={t("toggleAria", { mode: t(`modes.${preference}`) })}
      title={t("toggleTitle", { mode: t(`modes.${preference}`) })}
      data-preference={preference}
    >
      <PreferenceIcon preference={preference} />
      {compact ? null : (
        <span className={styles.label}>{t(`modes.${preference}`)}</span>
      )}
    </button>
  );
}
