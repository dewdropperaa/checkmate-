import { THEME_INIT_SCRIPT } from "@/lib/theme";

/** Blocking inline script — must run before first paint to avoid theme FOUC. */
export function ThemeScript() {
  return (
    <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
  );
}
