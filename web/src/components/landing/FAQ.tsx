import { useTranslations } from "next-intl";
import styles from "./landing.module.css";

export function FAQ() {
  const t = useTranslations("faq");
  const items = t.raw("items") as Array<{ q: string; a: string }>;

  return (
    <section id="faq" className="section" aria-labelledby="faq-heading">
      <div className="container">
        <p className="section-label">faq</p>
        <h2 id="faq-heading" className="section-title">
          {t("title")}
        </h2>
        <div className={styles.faqList}>
          {items.map((item) => (
            <details key={item.q} className={styles.faqItem}>
              <summary>{item.q}</summary>
              <p>{item.a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
