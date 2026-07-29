import { describe, expect, it } from "vitest";
import {
  isThemePreference,
  resolveTheme,
  THEME_STORAGE_KEY,
} from "./theme";

describe("extension theme", () => {
  it("validates preferences", () => {
    expect(isThemePreference("light")).toBe(true);
    expect(isThemePreference("dark")).toBe(true);
    expect(isThemePreference("system")).toBe(true);
    expect(isThemePreference("neon")).toBe(false);
  });

  it("resolves system preference via matchMedia", () => {
    const light = resolveTheme("system", () => ({ matches: false }));
    const dark = resolveTheme("system", () => ({ matches: true }));
    expect(light).toBe("light");
    expect(dark).toBe("dark");
  });

  it("keeps explicit preference", () => {
    expect(resolveTheme("light")).toBe("light");
    expect(resolveTheme("dark")).toBe("dark");
  });

  it("shares the web dashboard storage key", () => {
    expect(THEME_STORAGE_KEY).toBe("checkmate-theme");
  });
});
