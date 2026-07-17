import { Link } from "@/i18n/navigation";
import styles from "@/components/legal/legal.module.css";

export type LegalSection = {
  title: string;
  paragraphs: string[];
};

type Props = {
  title: string;
  lastUpdated: string;
  sections: LegalSection[];
  backLabel: string;
};

export function LegalDocument({
  title,
  lastUpdated,
  sections,
  backLabel,
}: Props) {
  return (
    <article className={styles.doc}>
      <header className={styles.header}>
        <h1>{title}</h1>
        <p className={styles.updated}>{lastUpdated}</p>
      </header>

      {sections.map((section, sectionIndex) => (
        <section key={`${sectionIndex}-${section.title}`} className={styles.section}>
          <h2>{section.title}</h2>
          {section.paragraphs.map((paragraph, paragraphIndex) => (
            <p key={paragraphIndex}>{paragraph}</p>
          ))}
        </section>
      ))}

      <p className={styles.back}>
        <Link href="/" className="btn btn-secondary">
          ← {backLabel}
        </Link>
      </p>
    </article>
  );
}
