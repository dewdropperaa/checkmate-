"use client";

import { useTranslations } from "next-intl";
import type { ScanCoverage } from "@/lib/api";
import styles from "./dashboard.module.css";

type Props = {
  coverage: ScanCoverage;
};

function ModuleList({
  label,
  items,
  empty,
}: {
  label: string;
  items: string[];
  empty: string;
}) {
  return (
    <li>
      <strong>{label}:</strong>{" "}
      {items.length === 0 ? (
        <span className={styles.muted}>{empty}</span>
      ) : (
        items.map((m) => (
          <code key={m} className={styles.moduleChip}>
            {m}
          </code>
        ))
      )}
    </li>
  );
}

export function ScanCoverageSection({ coverage }: Props) {
  const t = useTranslations("dashboard.coverage");

  return (
    <section className={styles.coverage} aria-labelledby="coverage-title">
      <h2 id="coverage-title" className={styles.panelTitle}>
        {t("title")}
      </h2>
      <ul className={styles.coverageList}>
        <ModuleList
          label={t("modulesRun")}
          items={coverage.modules_run}
          empty={t("none")}
        />
        <ModuleList
          label={t("modulesFailed")}
          items={coverage.modules_failed}
          empty={t("none")}
        />
        <ModuleList
          label={t("modulesSkipped")}
          items={coverage.modules_skipped}
          empty={t("none")}
        />
        <ModuleList
          label={t("modulesNotApplicable")}
          items={coverage.modules_not_applicable}
          empty={t("none")}
        />
        {coverage.modules_rejected.length > 0 ? (
          <ModuleList
            label={t("modulesRejected")}
            items={coverage.modules_rejected}
            empty={t("none")}
          />
        ) : null}
      </ul>
      <div className={styles.coverageDisclaimer} role="note">
        <h3>{t("limitationsHeading")}</h3>
        <p>{coverage.disclaimer || t("disclaimer")}</p>
      </div>
    </section>
  );
}
