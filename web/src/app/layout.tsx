import type { ReactNode } from "react";

/** Root layout — locale-specific chrome lives under `[locale]`. */
export default function RootLayout({ children }: { children: ReactNode }) {
  return children;
}
