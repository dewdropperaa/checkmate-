import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

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
    key: "Content-Security-Policy",
    // TODO(prod): swap 'unsafe-inline' for nonces — required for Next.js Flight
    // scripts today; strict 'self'-only blanks the page in Chromium.
    value: [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "img-src 'self' data: blob: https://*.googleusercontent.com",
      "font-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline' https://apis.google.com https://*.gstatic.com",
      "frame-src 'self' https://*.firebaseapp.com https://*.google.com https://accounts.google.com https://apis.google.com",
      "connect-src 'self' ws: wss: https://*.googleapis.com https://*.firebaseio.com https://*.firebaseapp.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com http://localhost:* http://127.0.0.1:*",
      "form-action 'self' https://accounts.google.com https://*.firebaseapp.com https://*.google.com",
    ].join("; "),
  },
];
const nextConfig: NextConfig = {
  poweredByHeader: false,
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
