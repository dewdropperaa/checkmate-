/**
 * Extension theme preference — mirrors web `checkmate-theme` key so dashboard
 * and extension stay in sync when both run on the same machine profile.
 */

export const THEME_STORAGE_KEY = "checkmate-theme";

export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

export const THEME_PREFERENCES: ThemePreference[] = ["light", "dark", "system"];

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === "light" || value === "dark" || value === "system";
}

export function getSystemTheme(
  matchMedia?: (query: string) => { matches: boolean },
): ResolvedTheme {
  const mm =
    matchMedia ??
    (typeof window !== "undefined"
      ? window.matchMedia.bind(window)
      : undefined);
  if (!mm) return "dark";
  return mm("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function resolveTheme(
  preference: ThemePreference,
  matchMedia?: (query: string) => { matches: boolean },
): ResolvedTheme {
  if (preference !== "system") return preference;
  if (matchMedia) return getSystemTheme(matchMedia);
  if (typeof window !== "undefined") return getSystemTheme();
  return "dark";
}

export function applyResolvedTheme(theme: ResolvedTheme): void {
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.style.colorScheme = theme;
}

export async function readThemePreference(): Promise<ThemePreference> {
  try {
    if (typeof chrome !== "undefined" && chrome.storage?.sync) {
      const fromSync = await chrome.storage.sync.get(THEME_STORAGE_KEY);
      if (isThemePreference(fromSync[THEME_STORAGE_KEY])) {
        return fromSync[THEME_STORAGE_KEY];
      }
    }
  } catch {
    /* ignore */
  }
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (isThemePreference(raw)) return raw;
  } catch {
    /* ignore */
  }
  return "system";
}

export async function writeThemePreference(
  preference: ThemePreference,
): Promise<void> {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    /* ignore */
  }
  try {
    if (typeof chrome !== "undefined" && chrome.storage?.sync) {
      await chrome.storage.sync.set({ [THEME_STORAGE_KEY]: preference });
    }
  } catch {
    /* ignore */
  }
}

export async function initExtensionTheme(): Promise<ThemePreference> {
  const preference = await readThemePreference();
  applyResolvedTheme(resolveTheme(preference));
  return preference;
}
