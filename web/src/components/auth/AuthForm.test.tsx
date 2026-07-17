import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NextIntlClientProvider } from "next-intl";
import { AuthForm } from "@/components/auth/AuthForm";
import en from "../../../messages/en.json";

const replace = vi.fn();
const signInWithEmail = vi.fn();
const signUpWithEmail = vi.fn();
const signInWithGoogle = vi.fn();
const sendPasswordResetEmail = vi.fn();
const signOut = vi.fn();

vi.mock("@/i18n/navigation", () => ({
  Link: ({
    href,
    children,
  }: {
    href: string;
    children: React.ReactNode;
  }) => <a href={href}>{children}</a>,
  useRouter: () => ({ replace, push: replace }),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    currentUser: null,
    isLoading: false,
    signInWithEmail,
    signUpWithEmail,
    signInWithGoogle,
    sendPasswordResetEmail,
    resetPassword: sendPasswordResetEmail,
    signOut,
  }),
}));

function renderForm(mode: "signin" | "signup") {
  return render(
    <NextIntlClientProvider locale="en" messages={en}>
      <AuthForm mode={mode} />
    </NextIntlClientProvider>,
  );
}

describe("AuthForm validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    signOut.mockResolvedValue({ ok: true, uid: "", email: null });
  });

  it("blocks invalid email before calling signup", async () => {
    const user = userEvent.setup();
    renderForm("signup");

    await user.type(screen.getByRole("textbox", { name: /^email$/i }), "not-an-email");
    await user.type(screen.getByLabelText(/^password$/i), "GoodPass1");
    await user.type(
      screen.getByLabelText(/confirm password/i),
      "GoodPass1",
    );
    await user.click(screen.getByRole("button", { name: /create account/i }));

    expect(await screen.findByText(/valid email/i)).toBeInTheDocument();
    expect(signUpWithEmail).not.toHaveBeenCalled();
  });

  it("blocks weak password before calling signup", async () => {
    const user = userEvent.setup();
    renderForm("signup");

    await user.type(
      screen.getByRole("textbox", { name: /^email$/i }),
      "user@example.com",
    );
    await user.type(screen.getByLabelText(/^password$/i), "weak");
    await user.type(screen.getByLabelText(/confirm password/i), "weak");
    await user.click(screen.getByRole("button", { name: /create account/i }));

    expect(
      await screen.findByText(/at least 8 characters/i),
    ).toBeInTheDocument();
    expect(signUpWithEmail).not.toHaveBeenCalled();
  });

  it("blocks mismatched confirm password before calling signup", async () => {
    const user = userEvent.setup();
    renderForm("signup");

    await user.type(
      screen.getByRole("textbox", { name: /^email$/i }),
      "user@example.com",
    );
    await user.type(screen.getByLabelText(/^password$/i), "GoodPass1");
    await user.type(
      screen.getByLabelText(/confirm password/i),
      "GoodPass2",
    );
    await user.click(screen.getByRole("button", { name: /create account/i }));

    expect(
      await screen.findByText(/passwords do not match/i),
    ).toBeInTheDocument();
    expect(signUpWithEmail).not.toHaveBeenCalled();
  });

  it("redirects to dashboard after successful email sign-in", async () => {
    const user = userEvent.setup();
    signInWithEmail.mockResolvedValue({
      ok: true,
      uid: "u1",
      email: "user@example.com",
      needsEmailVerification: false,
    });
    renderForm("signin");

    await user.type(
      screen.getByRole("textbox", { name: /^email$/i }),
      "user@example.com",
    );
    await user.type(screen.getByLabelText(/^password$/i), "GoodPass1");
    await user.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() => {
      expect(signInWithEmail).toHaveBeenCalledWith(
        "user@example.com",
        "GoodPass1",
      );
      expect(replace).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("redirects to dashboard after successful Google sign-in", async () => {
    const user = userEvent.setup();
    signInWithGoogle.mockResolvedValue({
      ok: true,
      uid: "g1",
      email: "g@example.com",
    });
    renderForm("signin");

    await user.click(
      screen.getByRole("button", { name: /continue with google/i }),
    );

    await waitFor(() => {
      expect(signInWithGoogle).toHaveBeenCalled();
      expect(replace).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("shows verify-email success state after signup instead of dashboard", async () => {
    const user = userEvent.setup();
    signUpWithEmail.mockResolvedValue({
      ok: true,
      uid: "u1",
      email: "user@example.com",
      needsEmailVerification: true,
    });
    renderForm("signup");

    await user.type(
      screen.getByRole("textbox", { name: /^email$/i }),
      "user@example.com",
    );
    await user.type(screen.getByLabelText(/^password$/i), "GoodPass1");
    await user.type(
      screen.getByLabelText(/confirm password/i),
      "GoodPass1",
    );
    await user.click(screen.getByRole("button", { name: /create account/i }));

    expect(
      await screen.findByRole("heading", { name: /verify your email/i }),
    ).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
    expect(signOut).toHaveBeenCalled();
  });
});
