"use client";

import { useMemo } from "react";
import { useTranslations } from "next-intl";
import type { RiskTrendPoint } from "@/lib/api";
import styles from "./dashboard.module.css";

type Props = {
  points: RiskTrendPoint[];
  target?: string | null;
  loading?: boolean;
};

const W = 640;
const H = 220;
const PAD = { top: 24, right: 56, bottom: 36, left: 40 };

/** Severity bands on the 0–10 risk axis (matches backend scoring bands). */
const BANDS = [
  { max: 10, min: 9, key: "critical" as const },
  { max: 9, min: 7, key: "high" as const },
  { max: 7, min: 4, key: "medium" as const },
  { max: 4, min: 0, key: "low" as const },
];

function xFor(i: number, n: number): number {
  if (n <= 1) return PAD.left + (W - PAD.left - PAD.right) / 2;
  return PAD.left + (i / (n - 1)) * (W - PAD.left - PAD.right);
}

function yFor(score: number): number {
  const clamped = Math.max(0, Math.min(10, score));
  const usable = H - PAD.top - PAD.bottom;
  return PAD.top + usable * (1 - clamped / 10);
}

function polyline(
  values: Array<number | null>,
  n: number,
): string {
  return values
    .map((v, i) => (v == null ? null : `${xFor(i, n)},${yFor(v)}`))
    .filter(Boolean)
    .join(" ");
}

export function RiskTrendChart({ points, target, loading }: Props) {
  const t = useTranslations("dashboard.riskTrend");

  const series = useMemo(() => {
    const scores = points.map((p) => p.overall_risk_score);
    const totals = points.map((p) =>
      p.findings_count == null ? null : Math.min(10, p.findings_count / 5),
    );
    const critHigh = points.map((p) =>
      p.critical_high_count == null
        ? null
        : Math.min(10, p.critical_high_count),
    );
    return { scores, totals, critHigh };
  }, [points]);

  if (loading) {
    return (
      <section className={styles.trendPanel} aria-busy="true">
        <h2 className={styles.panelTitle}>{t("title")}</h2>
        <p className={styles.loading}>&gt; {t("loading")}</p>
      </section>
    );
  }

  if (points.length === 0) {
    return (
      <section className={styles.trendPanel}>
        <h2 className={styles.panelTitle}>{t("title")}</h2>
        <p className={styles.muted}>{t("empty")}</p>
      </section>
    );
  }

  const n = points.length;
  const scorePath = polyline(series.scores, n);
  const areaPath =
    n === 1
      ? ""
      : `M ${xFor(0, n)},${yFor(0)} L ${scorePath.split(" ").join(" L ")} L ${xFor(n - 1, n)},${yFor(0)} Z`;

  const latest = points[points.length - 1];

  return (
    <section
      className={styles.trendPanel}
      aria-labelledby="risk-trend-title"
      data-points={n}
      data-single={n === 1 ? "true" : "false"}
    >
      <div className={styles.panelHeading}>
        <div>
          <h2 id="risk-trend-title" className={styles.panelTitle}>
            {t("title")}
          </h2>
          <p className={styles.panelDescription}>
            {target ? t("forTarget", { target }) : t("allSites")}
            {n === 1 ? ` · ${t("singleScan")}` : ` · ${t("scans", { count: n })}`}
          </p>
        </div>
        <div className={styles.trendLegend} aria-hidden="true">
          <span className={styles.legendScore}>{t("riskScore")}</span>
          <span className={styles.legendFindings}>{t("findings")}</span>
          <span className={styles.legendCrit}>{t("criticalHigh")}</span>
        </div>
      </div>

      <svg
        className={styles.trendChart}
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={t("ariaLabel", {
          score: latest.overall_risk_score.toFixed(1),
          count: n,
        })}
      >
        {BANDS.map((band) => {
          const y1 = yFor(band.max);
          const y2 = yFor(band.min);
          return (
            <rect
              key={band.key}
              className={styles.trendBand}
              data-severity={band.key}
              x={PAD.left}
              y={y1}
              width={W - PAD.left - PAD.right}
              height={Math.max(0, y2 - y1)}
            />
          );
        })}

        {[0, 2.5, 5, 7.5, 10].map((tick) => (
          <g key={tick}>
            <line
              className={styles.trendGrid}
              x1={PAD.left}
              x2={W - PAD.right}
              y1={yFor(tick)}
              y2={yFor(tick)}
            />
            <text
              className={styles.trendAxis}
              x={PAD.left - 8}
              y={yFor(tick) + 3}
              textAnchor="end"
            >
              {tick}
            </text>
          </g>
        ))}

        {areaPath ? (
          <path className={styles.trendArea} data-testid="trend-area" d={areaPath} />
        ) : null}
        <polyline
          className={styles.trendLine}
          data-testid="trend-line"
          points={scorePath}
        />

        {series.totals.some((v) => v != null) ? (
          <polyline
            className={styles.trendLineSecondary}
            points={polyline(series.totals, n)}
          />
        ) : null}
        {series.critHigh.some((v) => v != null) ? (
          <polyline
            className={styles.trendLineCrit}
            points={polyline(series.critHigh, n)}
          />
        ) : null}

        {points.map((p, i) => (
          <circle
            key={p.scan_id}
            className={styles.trendPoint}
            data-testid="trend-point"
            cx={xFor(i, n)}
            cy={yFor(p.overall_risk_score)}
            r={n === 1 ? 6 : 4}
          >
            <title>
              {`${p.created_at.slice(0, 10)} · ${p.overall_risk_score.toFixed(1)}`}
            </title>
          </circle>
        ))}
      </svg>
    </section>
  );
}
