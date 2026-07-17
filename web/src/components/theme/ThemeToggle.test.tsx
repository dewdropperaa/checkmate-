import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NextIntlClientProvider } from "next-intl";
import en from "../../../messages/en.json";
import { ThemeProvider } from "./ThemeProvider";
import { ThemeToggle } from "./ThemeToggle";
import {
  THEME_STORAGE_KEY,
  applyResolvedTheme,
  getSystemTheme,
  isThemePreference,
  readStoredPreference,
  resolveTheme,
  writeStoredPreference,
} from "@/lib/theme";

function renderToggle() {
  return render(
    <NextIntlClientProvider locale="en" messages={en}>
      <ThemeProvider>
        <ThemeToggle />
      </ThemeProvider>
    </NextIntlClientProvider>,
  );
}

describe("theme helpers", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  it("defaults to system when storage is empty", () => {
    expect(readStoredPreference()).toBe("system");
    expect(isThemePreference("system")).toBe(true);
    expect(isThemePreference("neon")).toBe(false);
  });

  it("persists an explicit preference and applies resolved theme", () => {
    writeStoredPreference("light");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(readStoredPreference()).toBe("light");
    expect(resolveTheme("light")).toBe("light");
    applyResolvedTheme("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });

  it("resolves system preference from matchMedia", () => {
    const matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: query.includes("dark"),
      media: query,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
      onchange: null,
    }));
    vi.stubGlobal("matchMedia", matchMedia);
    expect(getSystemTheme()).toBe("dark");
    expect(resolveTheme("system")).toBe("dark");
    vi.unstubAllGlobals();
  });
});

describe("ThemeToggle", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    vi.stubGlobal(
      "matchMedia",
      vi.fn().mockImplementation((query: string) => ({
        matches: query.includes("prefers-color-scheme: dark") ? true : false,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
        onchange: null,
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("cycles preference, updates data-theme, and persists across reload", async () => {
    const user = userEvent.setup();
    const view = renderToggle();

    const toggle = await screen.findByRole("button", { name: /Theme:/i });

    await user.click(toggle);
    await waitFor(() => {
      expect(document.documentElement.getAttribute("data-theme")).toBe("light");
      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    });

    await user.click(toggle);
    await waitFor(() => {
      expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    });

    view.unmount();
    renderToggle();

    await waitFor(() => {
      expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
      expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    });
  });

  it("follows prefers-color-scheme changes while preference is system", async () => {
    const listeners = new Set<(event: MediaQueryListEvent) => void>();
    let prefersDark = true;

    vi.stubGlobal(
      "matchMedia",
      vi.fn().mockImplementation((query: string) => ({
        get matches() {
          return query.includes("prefers-color-scheme: dark")
            ? prefersDark
            : !prefersDark;
        },
        media: query,
        addEventListener: (
          _type: string,
          listener: (event: MediaQueryListEvent) => void,
        ) => {
          listeners.add(listener);
        },
        removeEventListener: (
          _type: string,
          listener: (event: MediaQueryListEvent) => void,
        ) => {
          listeners.delete(listener);
        },
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
        onchange: null,
      })),
    );

    writeStoredPreference("system");
    renderToggle();

    await waitFor(() => {
      expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    });

    prefersDark = false;
    act(() => {
      listeners.forEach((listener) =>
        listener({ matches: false } as MediaQueryListEvent),
      );
    });

    await waitFor(() => {
      expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    });
  });
});
