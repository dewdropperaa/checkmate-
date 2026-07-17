import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import en from "../../../messages/en.json";
import { ScanHistoryTable } from "@/components/dashboard/ScanHistoryTable";
import type { ScanHistoryItem } from "@/lib/api";
import dashboardStyles from "@/components/dashboard/dashboard.module.css";

const sampleScans: ScanHistoryItem[] = [
  {
    id: "scan-1",
    target: "https://example.com",
    status: "completed",
    current_node: null,
    overall_risk_score: 8.2,
    severity: "critical",
    created_at: "2026-07-01T12:00:00.000Z",
    updated_at: "2026-07-01T12:05:00.000Z",
  },
  {
    id: "scan-2",
    target: "https://safe.example",
    status: "awaiting_approval",
    current_node: "human_approval_gate",
    overall_risk_score: 3.1,
    severity: "low",
    created_at: "2026-07-02T12:00:00.000Z",
    updated_at: "2026-07-02T12:05:00.000Z",
  },
];

function renderHistory(theme: "light" | "dark") {
  document.documentElement.setAttribute("data-theme", theme);
  return render(
    <NextIntlClientProvider locale="en" messages={en}>
      <div data-testid="dashboard-shell" className={dashboardStyles.dashboard}>
        <section className={dashboardStyles.panel}>
          <h2 className={dashboardStyles.panelTitle}>Report</h2>
          <div className={dashboardStyles.approval}>
            <strong>Approval needed</strong>
            <p>Active tests require confirmation.</p>
          </div>
        </section>
        <ScanHistoryTable
          scans={sampleScans}
          page={1}
          totalPages={1}
          onPageChange={() => undefined}
          onView={() => undefined}
          onRescan={() => undefined}
        />
      </div>
    </NextIntlClientProvider>,
  );
}

describe("theme visual snapshots", () => {
  it("dashboard + scan detail chrome in dark theme", () => {
    const { container } = renderHistory("dark");
    expect(container.firstChild).toMatchSnapshot();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("dashboard + scan detail chrome in light theme", () => {
    const { container } = renderHistory("light");
    expect(container.firstChild).toMatchSnapshot();
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });
});
