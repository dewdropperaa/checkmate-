# Hosting & security headers (landing)

checkmate’s own `header-checks` module expects production sites to ship:

| Header | Expected |
|--------|----------|
| `Content-Security-Policy` | Present; **no** `'unsafe-inline'` / `'unsafe-eval'`; no permissive `*` / `https:` sources |
| `Strict-Transport-Security` | `max-age` ≥ 31536000 (we set **63072000**); prefer `includeSubDomains` |
| Clickjacking | `X-Frame-Options: DENY` (or CSP `frame-ancestors`) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | Present; not `unsafe-url` (we use `strict-origin-when-cross-origin`) |
| CORS | Do **not** set `Access-Control-Allow-Origin: *` |
| Disclosure | No versioned `Server` / `X-Powered-By` (`poweredByHeader: false`) |

Configured in:

- `next.config.ts` → `headers()`
- `src/middleware.ts` → `withSecurityHeaders()`

## CSP vs Next.js (action required for a clean scan)

**Do not ship `script-src 'self'` alone** — Next.js injects inline Flight/hydration scripts. That policy produces a blank (often solid black) page in Chromium/Brave even though the server returns 200 HTML.

Current middleware/config allow `'unsafe-inline'` for `script-src` / `style-src` so the app renders. checkmate’s own `header-checks` will flag that.

**Recommended for production (to pass header-checks without breaking the UI):**

1. Terminate HTTPS at your edge (Cloudflare, nginx, Caddy, Vercel).
2. Prefer **nonce-based CSP**: generate a nonce per request in middleware, pass it into the root layout (`<html>` / Next.js Script), and set `script-src 'self' 'nonce-…'` (no `'unsafe-inline'`).
3. Avoid third-party analytics unless they support nonces/hashes.
4. Confirm HSTS is only advertised on the real HTTPS hostname.

Dev also needs `connect-src` to allow `ws:` / `wss:` for Turbopack HMR.

## Cookies (when auth lands)

Auth cookies must use `Secure` (HTTPS), `HttpOnly`, and a strict `SameSite` (or `SameSite=None` only with `Secure`).
