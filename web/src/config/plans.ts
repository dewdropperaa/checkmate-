/**
 * SaaS plan catalog — single source of truth for pricing UI.
 *
 * Feature keys map to capabilities that exist in the checkmate scanner
 * (header-checks, testssl, subfinder, nuclei, retire.js, AI synthesis,
 * report exports). Do not invent product claims here without backing code.
 *
 * TODO: Confirm currency (MAD vs EUR) and final prices with product before launch.
 * Numbers below are placeholders for UI wiring only.
 */

export type PlanId = "free" | "starter" | "pro" | "agency";

export type BillingInterval = "monthly" | "yearly";

/** Feature keys — resolve display copy via i18n (`features.<key>`). */
export type FeatureKey =
  | "headerChecks"
  | "tlsChecks"
  | "subdomainDiscovery"
  | "nucleiMisconfig"
  | "jsDependencyCve"
  | "aiExecutiveSummary"
  | "pdfHtmlReports"
  | "chromeExtension"
  | "activeTesting"
  | "authorizedTargets"
  | "whiteLabelReports"
  | "multiClientWorkspace"
  | "prioritySupport";

export interface PlanPrice {
  /** Amount in minor units of `currency` (e.g. centimes for MAD). 0 = free. */
  amount: number;
  currency: "MAD";
}

export interface Plan {
  id: PlanId;
  /** i18n key under `plans.<id>.name` */
  nameKey: string;
  /** i18n key under `plans.<id>.blurb` */
  blurbKey: string;
  /** Highlight as recommended on the pricing grid */
  highlighted?: boolean;
  /** CTA style */
  cta: "signup" | "contact";
  prices: Record<BillingInterval, PlanPrice>;
  /** Max authorized targets; null = custom / unlimited (confirm before claiming) */
  maxTargets: number | null;
  /** Approximate scans/month; null = custom */
  scansPerMonth: number | null;
  /**
   * Watch Agent cadence for automated background re-checks.
   * free = manual only; starter = weekly; pro/agency = daily.
   * Keep in sync with backend/core/plans.py.
   */
  watchCadence: "none" | "weekly" | "daily";
  features: FeatureKey[];
}

export const FEATURE_CATALOG: Record<
  FeatureKey,
  { toolHint: string; /** Set true when capability is not fully shipped */ todo?: boolean }
> = {
  headerChecks: { toolHint: "header-checks" },
  tlsChecks: { toolHint: "testssl" },
  subdomainDiscovery: { toolHint: "subfinder" },
  // Nuclei templates commonly cover exposed panels, CMS issues, cloud buckets —
  // we do not ship separate named modules for each.
  nucleiMisconfig: { toolHint: "nuclei" },
  jsDependencyCve: { toolHint: "retire.js" },
  aiExecutiveSummary: { toolHint: "ai_synthesis" },
  pdfHtmlReports: { toolHint: "reporting" },
  chromeExtension: { toolHint: "extension" },
  activeTesting: { toolHint: "zap + sqlmap (human approval)" },
  authorizedTargets: { toolHint: "AUTHORIZED_TARGETS scope" },
  // Reports currently brand as Checkmate; agency white-label is product roadmap.
  whiteLabelReports: { toolHint: "reporting", todo: true },
  multiClientWorkspace: { toolHint: "saas accounts", todo: true },
  prioritySupport: { toolHint: "ops", todo: true },
};

export const PLANS: Plan[] = [
  {
    id: "free",
    nameKey: "plans.free.name",
    blurbKey: "plans.free.blurb",
    cta: "signup",
    prices: {
      monthly: { amount: 0, currency: "MAD" },
      yearly: { amount: 0, currency: "MAD" },
    },
    maxTargets: 1,
    scansPerMonth: 5,
    watchCadence: "none",
    features: [
      "headerChecks",
      "tlsChecks",
      "pdfHtmlReports",
      "chromeExtension",
      "authorizedTargets",
    ],
  },
  {
    id: "starter",
    nameKey: "plans.starter.name",
    blurbKey: "plans.starter.blurb",
    cta: "signup",
    prices: {
      // TODO: confirm Starter pricing
      monthly: { amount: 29900, currency: "MAD" },
      yearly: { amount: 299000, currency: "MAD" },
    },
    maxTargets: 3,
    scansPerMonth: 30,
    watchCadence: "weekly",
    features: [
      "headerChecks",
      "tlsChecks",
      "subdomainDiscovery",
      "nucleiMisconfig",
      "jsDependencyCve",
      "aiExecutiveSummary",
      "pdfHtmlReports",
      "chromeExtension",
      "authorizedTargets",
    ],
  },
  {
    id: "pro",
    nameKey: "plans.pro.name",
    blurbKey: "plans.pro.blurb",
    highlighted: true,
    cta: "signup",
    prices: {
      // TODO: confirm Pro pricing
      monthly: { amount: 79900, currency: "MAD" },
      yearly: { amount: 799000, currency: "MAD" },
    },
    maxTargets: 15,
    scansPerMonth: 150,
    watchCadence: "daily",
    features: [
      "headerChecks",
      "tlsChecks",
      "subdomainDiscovery",
      "nucleiMisconfig",
      "jsDependencyCve",
      "aiExecutiveSummary",
      "activeTesting",
      "pdfHtmlReports",
      "chromeExtension",
      "authorizedTargets",
      "prioritySupport",
    ],
  },
  {
    id: "agency",
    nameKey: "plans.agency.name",
    blurbKey: "plans.agency.blurb",
    cta: "contact",
    prices: {
      // TODO: confirm Agency pricing
      monthly: { amount: 199900, currency: "MAD" },
      yearly: { amount: 1999000, currency: "MAD" },
    },
    maxTargets: null,
    scansPerMonth: null,
    watchCadence: "daily",
    features: [
      "headerChecks",
      "tlsChecks",
      "subdomainDiscovery",
      "nucleiMisconfig",
      "jsDependencyCve",
      "aiExecutiveSummary",
      "activeTesting",
      "pdfHtmlReports",
      "chromeExtension",
      "authorizedTargets",
      "whiteLabelReports",
      "multiClientWorkspace",
      "prioritySupport",
    ],
  },
];

export function formatPlanPrice(
  price: PlanPrice,
  locale: string,
  interval: BillingInterval,
): string {
  if (price.amount === 0) {
    return locale.startsWith("fr") ? "Gratuit" : "Free";
  }
  const major = price.amount / 100;
  const formatted = new Intl.NumberFormat(locale === "fr" ? "fr-MA" : "en-MA", {
    style: "currency",
    currency: price.currency,
    maximumFractionDigits: 0,
  }).format(major);
  const suffix =
    interval === "monthly"
      ? locale.startsWith("fr")
        ? "/mois"
        : "/mo"
      : locale.startsWith("fr")
        ? "/an"
        : "/yr";
  return `${formatted}${suffix}`;
}

export function getPlan(id: PlanId): Plan {
  const plan = PLANS.find((p) => p.id === id);
  if (!plan) {
    throw new Error(`Unknown plan: ${id}`);
  }
  return plan;
}
