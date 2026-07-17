import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { AuthGuard } from "@/components/auth/AuthGuard";
import en from "../../../messages/en.json";

const replace = vi.fn();
let authState: {
  currentUser: { emailVerified: boolean; email: string } | null;
  isLoading: boolean;
};

vi.mock("@/i18n/navigation", () => ({
  useRouter: () => ({ replace, push: replace }),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => authState,
}));

function renderGuard(
  mode: "protected" | "guest",
  state: typeof authState,
) {
  authState = state;
  return render(
    <NextIntlClientProvider locale="en" messages={en}>
      <AuthGuard mode={mode}>
        <div>Protected content</div>
      </AuthGuard>
    </NextIntlClientProvider>,
  );
}

describe("AuthGuard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading state while auth is resolving", () => {
    renderGuard("protected", { currentUser: null, isLoading: true });
    expect(screen.getByText(/checking session/i)).toBeInTheDocument();
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument();
  });

  it("redirects unauthenticated users from protected routes to /signin", async () => {
    renderGuard("protected", { currentUser: null, isLoading: false });
    expect(replace).toHaveBeenCalledWith("/signin");
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument();
  });

  it("redirects authenticated verified users away from /signin to dashboard", () => {
    renderGuard("guest", {
      currentUser: { emailVerified: true, email: "a@b.com" },
      isLoading: false,
    });
    expect(replace).toHaveBeenCalledWith("/dashboard");
    expect(screen.queryByText("Protected content")).not.toBeInTheDocument();
  });

  it("renders protected content for verified users", () => {
    renderGuard("protected", {
      currentUser: { emailVerified: true, email: "a@b.com" },
      isLoading: false,
    });
    expect(screen.getByText("Protected content")).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });
});
