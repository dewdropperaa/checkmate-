import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";
import path from "path";

const withNextIntl = createNextIntlPlugin("./src/i18n/request.ts");

/**
 * Security headers also set in middleware.ts (locale routes).
 * Duplicated here so static assets / edge cases still get baseline headers.
 *
 * FLAG — header-checks / CSP:
 * - HSTS, X-Frame-Options DENY, XCTO nosniff, Referrer-Policy match the API.
 * - CSP here omits 'unsafe-inline' and 'unsafe-eval' (header-checks flags those).
 * - Next.js may still emit inline bootstrap scripts in some modes; if scans
 *   fail CSP, switch to nonce-based CSP (see HOSTING.md) or terminate TLS
 *   at a reverse proxy that injects nonces.
 * - HSTS only applies over HTTPS in browsers; ensure production is HTTPS.
 * - Do not set Access-Control-Allow-Origin: * on this marketing site.
 */
// CSP is owned by middleware.ts (dynamic connect-src for API / Firebase).
// Do not set Content-Security-Policy here — multiple CSP headers are AND-ed
// by browsers and a static policy without the API origin blanks authenticated flows.
const securityHeaders = [
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "Cross-Origin-Opener-Policy",
    value: "same-origin-allow-popups",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains",
  },
  {
    key: "X-Robots-Tag",
    value: "noarchive",
  },
];
const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Keep file tracing inside this app when a parent lockfile exists.
  outputFileTracingRoot: path.join(__dirname),
  async rewrites() {
    const backend = process.env.API_BASE_URL?.trim().replace(/\/$/, "");
    if (!backend) {
      return [];
    }
    return [
      {
        source: "/api/backend/:path*",
        destination: `${backend}/:path*`,
      },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default withNextIntl(nextConfig);
