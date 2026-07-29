import styles from "@/components/auth/auth.module.css";

/** Instant feedback while a new route is loading (client bundle + auth gate). */
export default function LocaleLoading() {
  return (
    <div
      className={styles.authLoading}
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label="Loading page"
    >
      <span className={styles.spinner} aria-hidden="true" />
    </div>
  );
}
