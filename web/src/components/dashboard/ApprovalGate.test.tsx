import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApprovalGate,
  AUTO_APPROVE_SECONDS,
} from "@/components/dashboard/ApprovalGate";

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string, values?: Record<string, unknown>) => {
    if (key === "approvalCountdown" && values?.seconds != null) {
      return `Auto-approving the checked tools in ${values.seconds}s unless you cancel or reject.`;
    }
    const copy: Record<string, string> = {
      approvalTitle: "Your decision is required",
      approvalHelp: "Passive checks are complete.",
      approvalCancelAuto: "Cancel auto-approve",
      approveActiveTests: "Approve active tests",
      skipActiveTests: "Skip active tests",
      saving: "Saving…",
      approvalToolsLabel: "Active tools to allow",
      "authScan.approvalAs": "Scanning as user",
      "authScan.approvalExcluded": "Excluded paths",
      "authScan.approvalFallback": "Fallback",
    };
    return copy[key] ?? key;
  },
}));

describe("ApprovalGate countdown", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it("auto-approves selected tools after the countdown", async () => {
    const onApprove = vi.fn().mockResolvedValue(undefined);
    const onReject = vi.fn().mockResolvedValue(undefined);

    render(
      <ApprovalGate
        target="https://example.com"
        plannedTools={["zap", "sqlmap"]}
        loading={false}
        error={null}
        onApprove={onApprove}
        onReject={onReject}
      />,
    );

    expect(
      screen.getByText(/Auto-approving the checked tools in 8s/),
    ).toBeInTheDocument();

    for (let i = 0; i < AUTO_APPROVE_SECONDS; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
    }

    expect(onApprove).toHaveBeenCalledWith(["zap", "sqlmap"]);
    expect(onReject).not.toHaveBeenCalled();
  });

  it("does not silently proceed when auto-approve fails", async () => {
    const onApprove = vi.fn().mockRejectedValue(new Error("network"));
    const onReject = vi.fn().mockResolvedValue(undefined);

    render(
      <ApprovalGate
        target="https://example.com"
        plannedTools={["zap"]}
        loading={false}
        error="Unable to save your decision."
        onApprove={onApprove}
        onReject={onReject}
      />,
    );

    for (let i = 0; i < AUTO_APPROVE_SECONDS; i += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
    }

    expect(onApprove).toHaveBeenCalledTimes(1);
    expect(
      screen.getByText("Unable to save your decision."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve active tests" })).toBeEnabled();
  });

  it("cancel stops the countdown", async () => {
    vi.useRealTimers();
    const user = userEvent.setup();
    const onApprove = vi.fn().mockResolvedValue(undefined);

    render(
      <ApprovalGate
        target="https://example.com"
        plannedTools={["zap"]}
        loading={false}
        error={null}
        onApprove={onApprove}
        onReject={vi.fn()}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Cancel auto-approve" }));
    expect(
      screen.queryByText(/Auto-approving the checked tools/),
    ).not.toBeInTheDocument();
    expect(onApprove).not.toHaveBeenCalled();
  });
});
