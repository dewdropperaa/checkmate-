"use client";

import Image from "next/image";
import { useEffect, useState, useRef } from "react";
import { useTranslations } from "next-intl";
import { Link } from "@/i18n/navigation";
import styles from "./landing.module.css";

function useCountUp(target: number, duration = 2000, delay = 0) {
  const [value, setValue] = useState(0);
  const [started, setStarted] = useState(false);

  useEffect(() => {
    const timeout = setTimeout(() => setStarted(true), delay);
    return () => clearTimeout(timeout);
  }, [delay]);

  useEffect(() => {
    if (!started) return;
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
  }, [started, target, duration]);

  return value;
}

const TERMINAL_LINES = [
  { text: "$ checkmate scan --target example.com --authorized", delay: 0, type: "cmd" },
  { text: "[RECON] Discovering subdomains...", delay: 800, type: "info" },
  { text: "[+] Found: api.example.com", delay: 1400, type: "success" },
  { text: "[+] Found: admin.example.com", delay: 1800, type: "success" },
  { text: "[+] Found: staging.example.com", delay: 2200, type: "success" },
  { text: "[SCAN] Running security checks...", delay: 2800, type: "info" },
  { text: "[HIGH] Missing HSTS header on admin.example.com", delay: 3400, type: "high" },
  { text: "[MEDIUM] Weak TLS configuration detected", delay: 4000, type: "medium" },
  { text: "[LOW] X-Frame-Options not set", delay: 4500, type: "low" },
  { text: "[AI] Generating executive summary...", delay: 5200, type: "info" },
  { text: "[DONE] Report ready → PDF exported", delay: 6000, type: "done" },
];

function TerminalSimulation() {
  const [visibleLines, setVisibleLines] = useState<number>(0);
  const [cursorVisible, setCursorVisible] = useState(true);
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const timers: NodeJS.Timeout[] = [];
    TERMINAL_LINES.forEach((line, i) => {
      timers.push(setTimeout(() => setVisibleLines(i + 1), line.delay));
    });
    return () => timers.forEach(clearTimeout);
  }, []);

  useEffect(() => {
    const interval = setInterval(() => setCursorVisible((v) => !v), 530);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [visibleLines]);

  return (
    <div className={styles.terminal}>
      <div className={styles.terminalHeader}>
        <span className={styles.terminalDot} data-color="red" />
        <span className={styles.terminalDot} data-color="yellow" />
        <span className={styles.terminalDot} data-color="green" />
        <span className={styles.terminalTitle}>checkmate — scan</span>
      </div>
      <div className={styles.terminalBody} ref={terminalRef}>
        {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
          <div key={i} className={styles.terminalLine} data-type={line.type}>
            {line.text}
          </div>
        ))}
        <span className={styles.terminalCursor} style={{ opacity: cursorVisible ? 1 : 0 }}>
          █
        </span>
      </div>
      <div className={styles.terminalGlow} />
    </div>
  );
}

function StatCard({ value, label, suffix = "", delay = 0 }: { value: number; label: string; suffix?: string; delay?: number }) {
  const count = useCountUp(value, 2000, delay);
  return (
    <div className={styles.statCard}>
      <span className={styles.statValue}>
        {count.toLocaleString()}{suffix}
      </span>
      <span className={styles.statLabel}>{label}</span>
    </div>
  );
}

export function Hero() {
  const t = useTranslations("hero");

  return (
    <section className={styles.hero} aria-labelledby="hero-heading">
      <div className={styles.heroGlow} />
      <div className={styles.heroGrid} />
      
      <div className={`container ${styles.heroInner}`}>
        <div className={styles.heroCopy}>
          <div className={styles.heroBadge}>
            <span className={styles.heroBadgeDot} />
            {t("badge")}
          </div>
          
          <h1 id="hero-heading" className={styles.heroTitle}>
            {t("headline")}
            <span className={styles.heroHighlight}>{t("headlineHighlight")}</span>
          </h1>
          
          <p className={styles.heroTagline}>{t("tagline")}</p>
          
          <div className={styles.ctaRow}>
            <Link href="/signup" className={`btn btn-primary btn-large ${styles.heroCta}`}>
              {t("ctaPrimary")}
            </Link>
            <Link href="#how" className={`btn btn-ghost ${styles.heroCtaSecondary}`}>
              {t("ctaSecondary")}
            </Link>
          </div>

          <div className={styles.heroStats}>
            <StatCard value={2847} label={t("stat1Label")} delay={500} />
            <StatCard value={156} label={t("stat2Label")} suffix="K" delay={700} />
            <StatCard value={99} label={t("stat3Label")} suffix="%" delay={900} />
          </div>
        </div>

        <div className={styles.heroVisual}>
          <TerminalSimulation />
          <div className={styles.heroLogoFloat}>
            <Image
              src="/logo.png"
              alt="checkmate"
              width={80}
              height={80}
              className={styles.heroLogo}
              priority
            />
          </div>
        </div>
      </div>
    </section>
  );
}
