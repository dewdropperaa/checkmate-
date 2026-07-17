import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * Contrast helpers for theme token WCAG checks.
 * axe-core is not in the project test stack — treat full-page axe as a
 * manual TODO once playwright/axe is available.
 */

function relativeLuminance(hex: string): number {
  const n = hex.replace("#", "");
  const channels = [0, 2, 4].map((i) => {
    const c = parseInt(n.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(a: string, b: string): number {
  const L1 = relativeLuminance(a);
  const L2 = relativeLuminance(b);
  const [hi, lo] = L1 > L2 ? [L1, L2] : [L2, L1];
  return (hi + 0.05) / (lo + 0.05);
}

function extractThemeBlock(css: string, theme: "dark" | "light"): string {
  const re =
    theme === "dark"
      ? /\[data-theme="dark"\][^{]*\{([\s\S]*?)\n\}/
      : /\[data-theme="light"\][^{]*\{([\s\S]*?)\n\}/;
  const match = css.match(re);
  expect(match, `missing ${theme} theme block`).toBeTruthy();
  return match![1];
}

function token(block: string, name: string): string {
  const match = block.match(new RegExp(`${name}:\\s*(#[0-9a-fA-F]{3,8})`));
  expect(match, `missing token ${name}`).toBeTruthy();
  return match![1];
}

const tokensPath = path.resolve(__dirname, "../styles/tokens.css");
const css = readFileSync(tokensPath, "utf8");

describe("theme token contrast (WCAG AA)", () => {
  it("light theme text and accent meet AA against background", () => {
    const light = extractThemeBlock(css, "light");
    const bg = token(light, "--bg-primary");
    const text = token(light, "--text-primary");
    const accent = token(light, "--accent");
    const secondary = token(light, "--text-secondary");

    expect(contrastRatio(text, bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(accent, bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(secondary, bg)).toBeGreaterThanOrEqual(4.5);
  });

  it("light severity colors meet AA and stay distinguishable by lightness", () => {
    const light = extractThemeBlock(css, "light");
    const bg = token(light, "--bg-primary");
    const severities = [
      "--severity-critical",
      "--severity-high",
      "--severity-medium",
      "--severity-low",
      "--severity-info",
    ].map((name) => token(light, name));

    for (const color of severities) {
      expect(contrastRatio(color, bg)).toBeGreaterThanOrEqual(4.5);
    }

    // Pairwise: at least one channel differs enough that labels aren't the only signal,
    // but colors themselves should not all collapse to the same luminance.
    const luminances = severities.map(relativeLuminance);
    const unique = new Set(luminances.map((l) => l.toFixed(3)));
    expect(unique.size).toBeGreaterThanOrEqual(4);
  });

  it("dark theme text and accent meet AA against background", () => {
    const dark = extractThemeBlock(css, "dark");
    const bg = token(dark, "--bg-primary");
    const text = token(dark, "--text-primary");
    const accent = token(dark, "--accent");

    expect(contrastRatio(text, bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(accent, bg)).toBeGreaterThanOrEqual(4.5);
  });
});
