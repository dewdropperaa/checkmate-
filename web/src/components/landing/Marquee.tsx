"use client";

import styles from "./landing.module.css";

const ITEMS = [
  "SQL Injection",
  "XSS Detection",
  "CSRF Protection",
  "Header Analysis",
  "TLS/SSL Audit",
  "Subdomain Discovery",
  "CORS Misconfig",
  "Open Redirects",
  "Sensitive Data Exposure",
  "Security Headers",
  "Cookie Security",
  "HSTS Validation",
  "CSP Analysis",
  "Nuclei Scanning",
  "AI Summary",
  "PDF Reports",
];

export function Marquee() {
  const items = [...ITEMS, ...ITEMS];

  return (
    <div className={styles.marqueeWrapper}>
      <div className={styles.marqueeTrack}>
        {items.map((item, i) => (
          <span key={i} className={styles.marqueeItem}>
            {item}
            <span className={styles.marqueeDivider}>/</span>
          </span>
        ))}
      </div>
    </div>
  );
}
