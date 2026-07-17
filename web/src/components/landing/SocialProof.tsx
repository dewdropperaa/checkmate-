"use client";

import { useEffect, useState, useRef } from "react";
import { useTranslations } from "next-intl";
import styles from "./landing.module.css";

function useInView(ref: React.RefObject<HTMLElement | null>) {
  const [inView, setInView] = useState(false);

  useEffect(() => {
    if (!ref.current) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setInView(true);
          observer.disconnect();
        }
      },
      { threshold: 0.2 }
    );
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, [ref]);

  return inView;
}

function useCountUp(target: number, duration: number, start: boolean) {
  const [value, setValue] = useState(0);

  useEffect(() => {
    if (!start) return;
    const startTime = performance.now();
    let raf: number;

    const tick = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 4);
      setValue(Math.floor(target * eased));
      if (progress < 1) raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [start, target, duration]);

  return value;
}

function StatItem({ 
  value, 
  suffix, 
  labelKey, 
  duration, 
  inView,
  t
}: { 
  value: number; 
  suffix: string; 
  labelKey: string; 
  duration: number;
  inView: boolean;
  t: (key: string) => string;
}) {
  const count = useCountUp(value, duration, inView);
  const isDecimal = value % 1 !== 0;
  
  return (
    <div className={styles.socialProofStat}>
      <span className={styles.socialProofValue}>
        {isDecimal ? count.toFixed(1) : count.toLocaleString()}
        {suffix}
      </span>
      <span className={styles.socialProofStatLabel}>{t(labelKey)}</span>
    </div>
  );
}

const STATS = [
  { value: 50, suffix: "+", key: "companies", duration: 2000 },
  { value: 2500, suffix: "+", key: "scans", duration: 2200 },
  { value: 12000, suffix: "+", key: "vulns", duration: 2400 },
  { value: 99.9, suffix: "%", key: "uptime", duration: 2600 },
];

export function SocialProof() {
  const t = useTranslations("socialProof");
  const ref = useRef<HTMLElement>(null);
  const inView = useInView(ref);

  return (
    <section ref={ref} className={styles.socialProof}>
      <div className="container">
        <p className={styles.socialProofLabel}>{t("label")}</p>
        <div className={styles.socialProofGrid}>
          {STATS.map((stat) => (
            <StatItem
              key={stat.key}
              value={stat.value}
              suffix={stat.suffix}
              labelKey={stat.key}
              duration={stat.duration}
              inView={inView}
              t={t}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
