import createMiddleware from "next-intl/middleware";
import { NextRequest, NextResponse } from "next/server";
import { routing } from "./i18n/routing";

const intlMiddleware = createMiddleware(routing);

/**
 * Security headers aligned with backend header-checks where possible.
 *
 * Next.js App Router embeds inline bootstrap/Flight scripts. A strict
 * `script-src 'self'` alone blanks the app in the browser (scripts blocked).
 * Until per-request nonces are wired (see HOSTING.md), allow 'unsafe-inline'
 * for script/style so the landing page actually renders. Prefer nonces in prod.
 */
function buildCsp(): string {
  const isDev = process.env.NODE_ENV === "development";
  const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  const serverApi = process.env.API_BASE_URL?.trim();
  const connectExtras = [
    "https://*.googleapis.com",
    "https://*.firebaseio.com",
    "https://*.firebaseapp.com",
    "https://identitytoolkit.googleapis.com",
    "https://securetoken.googleapis.com",
  ];
  if (apiBase) {
    try {
      connectExtras.push(new URL(apiBase).origin);
    } catch {
      /* ignore invalid API URL in CSP build */
    }
  }
  if (serverApi) {
    try {
      connectExtras.push(new URL(serverApi).origin);
    } catch {
      /* ignore */
    }
  }
  const connectSrc = [
    "connect-src 'self'",
    ...connectExtras,
    ...(isDev ? ["ws:", "wss:", "http://localhost:*", "http://127.0.0.1:*"] : []),
  ].join(" ");

  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data: blob: https://*.googleusercontent.com",
    "font-src 'self'",
    // TODO(prod): replace 'unsafe-inline' with per-request nonces (HOSTING.md)
    "style-src 'self' 'unsafe-inline'",
    "script-src 'self' 'unsafe-inline' https://apis.google.com https://*.gstatic.com",
    // Google / Firebase Auth popup + handler iframe
    "frame-src 'self' blob: https://*.firebaseapp.com https://*.google.com https://accounts.google.com https://apis.google.com",
    connectSrc,
    // OAuth may POST back through Google / Firebase auth handler
    "form-action 'self' https://accounts.google.com https://*.firebaseapp.com https://*.google.com",
  ].join("; ");
}

function withSecurityHeaders(response: NextResponse): NextResponse {
  response.headers.set("Content-Security-Policy", buildCsp());
  response.headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains",
  );
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  // Allow Firebase Google popup to read window.closed / postMessage back.
  // `same-origin` alone breaks signInWithPopup (COOP isolates the opener).
  response.headers.set(
    "Cross-Origin-Opener-Policy",
    "same-origin-allow-popups",
  );
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  response.headers.set("X-Robots-Tag", "noarchive");
  response.headers.delete("X-Powered-By");
  return response;
}

export default function middleware(request: NextRequest) {
  // Do not run next-intl on the API proxy (would break /auth/sync).
  if (request.nextUrl.pathname.startsWith("/api/")) {
    return NextResponse.next();
  }
  const response = intlMiddleware(request);
  return withSecurityHeaders(response);
}

export const config = {
  matcher: [
    "/",
    "/(fr|en)/:path*",
    "/((?!_next|_vercel|api/|.*\\..*).*)",
  ],
};
