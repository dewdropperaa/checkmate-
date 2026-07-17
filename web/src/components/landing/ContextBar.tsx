import { useTranslations } from "next-intl";
import styles from "./landing.module.css";

export function ContextBar() {
  const t = useTranslations("context");

  return (
    <aside className={styles.contextBar} aria-label={t("label")}>
      <div className={`container ${styles.contextInner}`}>
        <p className="section-label">{t("label")}</p>
        <p className={styles.contextText}>{t("text")}</p>
      </div>
    </aside>
  );
}
