import { useTranslations } from "next-intl";
import styles from "./landing.module.css";

/** Badge labels echo PDF report severity/status chips (pdf_design.py). */
const STEPS = [
  { key: "scan", badge: "SCAN", className: styles.stepScan },
  { key: "findings", badge: "HIGH", className: styles.stepFindings },
  { key: "summary", badge: "AI", className: styles.stepSummary },
  { key: "fix", badge: "FIX", className: styles.stepFix },
] as const;

export function HowItWorks() {
  const t = useTranslations("how");

  return (
    <section id="how" className="section" aria-labelledby="how-heading">
      <div className="container">
        <p className="section-label">pipeline</p>
        <h2 id="how-heading" className="section-title">
          {t("title")}
        </h2>
        <p className="section-sub">{t("subtitle")}</p>
        <ol className={styles.steps}>
          {STEPS.map((step) => (
            <li key={step.key} className={`${styles.step} ${step.className}`}>
              <span className={styles.stepIcon} aria-hidden="true">
                {step.badge}
              </span>
              <h3 className={styles.stepTitle}>{t(`steps.${step.key}.title`)}</h3>
              <p className={styles.stepBody}>{t(`steps.${step.key}.body`)}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
