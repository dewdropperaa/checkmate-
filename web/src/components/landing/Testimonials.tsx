"use client";

import { useTranslations } from "next-intl";
import styles from "./landing.module.css";

const TESTIMONIALS = [
  { id: "testimonial1" },
  { id: "testimonial2" },
  { id: "testimonial3" },
];

export function Testimonials() {
  const t = useTranslations("testimonials");

  return (
    <section className={`section ${styles.testimonials}`}>
      <div className="container">
        <p className="section-label">{t("label")}</p>
        <h2 className="section-title">{t("title")}</h2>
        <div className={styles.testimonialGrid}>
          {TESTIMONIALS.map((item) => (
            <article key={item.id} className={styles.testimonialCard}>
              <blockquote className={styles.testimonialQuote}>
                &ldquo;{t(`${item.id}.quote`)}&rdquo;
              </blockquote>
              <div className={styles.testimonialAuthor}>
                <div className={styles.testimonialAvatar}>
                  {t(`${item.id}.name`).charAt(0)}
                </div>
                <div>
                  <div className={styles.testimonialName}>{t(`${item.id}.name`)}</div>
                  <div className={styles.testimonialRole}>
                    {t(`${item.id}.role`)} @ {t(`${item.id}.company`)}
                  </div>
                </div>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
