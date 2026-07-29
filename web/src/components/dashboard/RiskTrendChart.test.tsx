import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { RiskTrendChart } from "@/components/dashboard/RiskTrendChart";
import type { RiskTrendPoint } from "@/lib/api";

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string, values?: Record<string, unknown>) => {
    const copy: Record<string, string> = {
      title: "Risk score over time",
      loading: "Loading trend…",
      empty: "Run vulnerability scans to see risk trends for your sites.",
      forTarget: `Site: ${values?.target ?? ""}`,
      allSites: "All monitored sites",
      singleScan: "Single scan — trend appears after a second scan",
      scans: `${values?.count ?? 0} scans`,
      riskScore: "Risk score",
      findings: "Findings (scaled)",
      criticalHigh: "Critical + high",
      ariaLabel: `Risk trend chart, latest score ${values?.score}, ${values?.count} scans`,
    };
    return copy[key] ?? key;
  },
}));

function point(
  overrides: Partial<RiskTrendPoint> & Pick<RiskTrendPoint, "scan_id" | "overall_risk_score">,
): RiskTrendPoint {
  return {
    target: "https://example.com",
    created_at: "2026-07-01T00:00:00+00:00",
    severity: "medium",
    findings_count: 3,
    critical_high_count: 1,
    ...overrides,
  };
}

describe("RiskTrendChart", () => {
  it("renders a single-point state without a multi-scan trend message", () => {
    const { container } = render(
      <RiskTrendChart
        points={[
          point({
            scan_id: "s1",
            overall_risk_score: 4.5,
            created_at: "2026-07-01T12:00:00+00:00",
          }),
        ]}
        target="https://example.com"
      />,
    );

    expect(screen.getByText("Risk score over time")).toBeInTheDocument();
    expect(
      screen.getByText(/Single scan — trend appears after a second scan/),
    ).toBeInTheDocument();
    const panel = container.querySelector("[data-single='true']");
    expect(panel).toBeTruthy();
    expect(panel?.getAttribute("data-points")).toBe("1");
    expect(container.querySelectorAll('[data-testid="trend-point"]').length).toBe(1);
  });

  it("renders a multi-scan trend with score points", () => {
    const { container } = render(
      <RiskTrendChart
        points={[
          point({
            scan_id: "s1",
            overall_risk_score: 7.2,
            created_at: "2026-07-01T12:00:00+00:00",
            critical_high_count: 3,
          }),
          point({
            scan_id: "s2",
            overall_risk_score: 5.0,
            created_at: "2026-07-08T12:00:00+00:00",
            critical_high_count: 1,
          }),
          point({
            scan_id: "s3",
            overall_risk_score: 3.1,
            created_at: "2026-07-15T12:00:00+00:00",
            critical_high_count: 0,
          }),
        ]}
        target="https://example.com"
      />,
    );

    expect(screen.getByText(/3 scans/)).toBeInTheDocument();
    const panel = container.querySelector("[data-single='false']");
    expect(panel).toBeTruthy();
    expect(panel?.getAttribute("data-points")).toBe("3");
    expect(container.querySelector('[data-testid="trend-line"]')).toBeTruthy();
    expect(container.querySelector('[data-testid="trend-area"]')).toBeTruthy();
    expect(container.querySelectorAll('[data-testid="trend-point"]').length).toBe(3);
  });

  it("shows empty state when there are no scans", () => {
    render(<RiskTrendChart points={[]} />);
    expect(
      screen.getByText(/Run vulnerability scans to see risk trends/),
    ).toBeInTheDocument();
  });
});
