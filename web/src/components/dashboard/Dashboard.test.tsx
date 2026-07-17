import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NextIntlClientProvider } from "next-intl";
import type { User } from "firebase/auth";
import fr from "../../../messages/fr.json";
import { NewScanForm } from "./NewScanForm";
import { ScanHistoryTable } from "./ScanHistoryTable";
import type {
  BackendUser,
  ScanHistoryResponse,
} from "@/lib/api";

const canRunScan = vi.fn(() => ({
  allowed: false as const,
  reason: "scan_limit" as const,
}));

vi.mock("@/lib/quota", () => ({
  canAddSite: () => ({ allowed: true }),
  canRunScan: (...args: unknown[]) => canRunScan(...args),
}));

vi.mock("@/i18n/navigation", () => ({
  Link: ({
    href,
    children,
  }: {
    href: string;
    children: React.ReactNode;
  }) => <a href={href}>{children}</a>,
}));

const history: ScanHistoryResponse = {
  scans: [],
  page: 1,
  page_size: 10,
  total: 0,
  total_pages: 1,
  target_count: 0,
  scans_this_month: 5,
  targets: [],
};

const backendUser: BackendUser = {
  id: "user-1",
  email: "test@example.com",
  display_name: null,
  email_verified: true,
  auth_provider: "password",
  org_id: "org-1",
  plan_id: "free",
  max_targets: 1,
  scans_per_month: 5,
};

function withI18n(node: React.ReactNode) {
  return render(
    <NextIntlClientProvider locale="fr" messages={fr}>
      {node}
    </NextIntlClientProvider>,
  );
}

describe("dashboard", () => {
  it("renders the calm terminal empty state", () => {
    withI18n(
      <ScanHistoryTable
        scans={[]}
        page={1}
        totalPages={1}
        onPageChange={vi.fn()}
        onView={vi.fn()}
        onRescan={vi.fn()}
      />,
    );

    expect(
      screen.getByText(/Aucun scan pour le moment/),
    ).toBeInTheDocument();
  });

  it("shows the quota warning and does not submit a scan", async () => {
    const user = userEvent.setup();
    const getIdToken = vi.fn();
    withI18n(
      <NewScanForm
        currentUser={{ getIdToken } as unknown as User}
        backendUser={backendUser}
        usage={history}
        onCreated={vi.fn()}
      />,
    );

    await user.type(
      screen.getByRole("textbox", { name: /URL ou domaine cible/i }),
      "https://example.com",
    );
    await user.click(
      screen.getByRole("checkbox", { name: /autorisé à scanner/i }),
    );
    await user.click(
      screen.getByRole("button", { name: /Lancer le scan/i }),
    );

    expect(canRunScan).toHaveBeenCalled();
    expect(
      screen.getByRole("alert"),
    ).toHaveTextContent(/limite mensuelle de scans/i);
    expect(getIdToken).not.toHaveBeenCalled();
  });
});
