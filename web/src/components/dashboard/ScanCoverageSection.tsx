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
        {coverage.modules_failed_detail &&
        Object.keys(coverage.modules_failed_detail).length > 0 ? (
          <li>
            <strong>{t("modulesFailed")}:</strong>
            <ul className={styles.coverageList}>
              {Object.entries(coverage.modules_failed_detail)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([name, err]) => (
                  <li key={name}>
                    <code className={styles.moduleChip}>{name}</code>{" "}
                    <span className={styles.muted}>{err}</span>
                  </li>
                ))}
            </ul>
          </li>
        ) : (
          <ModuleList
            label={t("modulesFailed")}
            items={coverage.modules_failed}
            empty={t("none")}
          />
        )}
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
        {coverage.owasp_top10?.categories_covered &&
        coverage.owasp_top10.categories_covered.length > 0 ? (
          <li>
            <strong>OWASP Top 10:</strong>{" "}
            {coverage.owasp_top10.categories_covered.map((id) => (
              <code key={id} className={styles.moduleChip}>
                {id}
                {coverage.owasp_top10?.labels?.[id]
                  ? ` ${coverage.owasp_top10.labels[id]}`
                  : ""}
              </code>
            ))}
            {coverage.owasp_top10.note ? (
              <p className={styles.muted}>{coverage.owasp_top10.note}</p>
            ) : null}
          </li>
        ) : null}
      </ul>
      <div className={styles.coverageDisclaimer} role="note">
        <h3>{t("limitationsHeading")}</h3>
        <p>{coverage.disclaimer || t("disclaimer")}</p>
      </div>
    </section>
  );
}
