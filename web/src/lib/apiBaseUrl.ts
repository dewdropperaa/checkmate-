/**
 * Resolves the FastAPI base URL for browser API calls.
 *
 * Local dev: direct loopback (NEXT_PUBLIC_API_BASE_URL or 127.0.0.1:8000).
 * Production (Vercel): public HTTPS URL via NEXT_PUBLIC_API_BASE_URL, or
 * same-origin `/api/backend` when API_BASE_URL is set for Next.js rewrites.
 *
 * Ephemeral tunnels (loca.lt, etc.) are for local dev only. Production must use
 * a cloud API (e.g. Render onrender.com). Misconfigured tunnel URLs fall back to
 * the same-origin /api/backend proxy, which reads server-side API_BASE_URL.
 */

export const API_PROXY_PATH = "/api/backend";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Hosts that inject a browser interstitial before the origin (breaks CORS/API). */
const EPHEMERAL_TUNNEL_HOST_SUFFIXES = [
  ".loca.lt",
  ".localtunnel.me",
  ".ngrok-free.app",
  ".ngrok.io",
  ".trycloudflare.com",
];

function isLoopbackUrl(url: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(url).hostname.toLowerCase());
  } catch {
    return false;
  }
}

export function isEphemeralTunnelUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return EPHEMERAL_TUNNEL_HOST_SUFFIXES.some(
      (suffix) => host === suffix.slice(1) || host.endsWith(suffix),
    );
  } catch {
    return false;
  }
}

/** True when the browser must not call this URL directly in production. */
function shouldPreferApiProxy(url: string): boolean {
  return isLoopbackUrl(url) || isEphemeralTunnelUrl(url);
}

function normalizeBase(url: string): string {
  return url.trim().replace(/\/$/, "");
}

/**
 * Headers that skip Localtunnel's "Tunnel website ahead" interstitial.
 * Safe no-op on non-tunnel backends; required if a tunnel URL is ever called
 * directly from the browser.
 */
export function tunnelBypassHeaders(baseUrl: string): Record<string, string> {
  if (!isEphemeralTunnelUrl(baseUrl)) {
    return {};
  }
  return { "bypass-tunnel-reminder": "1" };
}

/**
 * Public backend URL for the Chrome extension (must be reachable from the browser,
 * not the Vercel same-origin proxy).
 */
export function resolveExtensionBackendBaseUrl(): string {
  const explicit = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  if (explicit) {
    const normalized = normalizeBase(explicit);
    if (
      process.env.NODE_ENV === "production" &&
      (isLoopbackUrl(normalized) || isEphemeralTunnelUrl(normalized))
    ) {
      throw new Error(
        "Extension backend URL must be a cloud HTTPS API in production (not loopback or loca.lt).",
      );
    }
    if (process.env.NODE_ENV !== "production" || !isLoopbackUrl(normalized)) {
      return normalized;
    }
  }
  const serverOnly = process.env.NEXT_PUBLIC_BACKEND_URL?.trim();
  if (serverOnly) {
    return normalizeBase(serverOnly);
  }
  if (process.env.NODE_ENV === "development") {
    return "http://127.0.0.1:8000";
  }
  throw new Error(
    "Extension backend URL is not configured. Set NEXT_PUBLIC_API_BASE_URL to your public HTTPS API on Vercel.",
  );
}

function resolveProxyBase(options?: { origin?: string }): string {
  if (options?.origin) {
    return `${options.origin.replace(/\/$/, "")}${API_PROXY_PATH}`;
  }
  if (typeof window !== "undefined") {
    return `${window.location.origin}${API_PROXY_PATH}`;
  }
  // Relative path is valid for browser fetch; server proxy route holds API_BASE_URL.
  return API_PROXY_PATH;
}

export function resolveApiBaseUrl(options?: { origin?: string }): string {
  const explicit = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  // NOTE: API_BASE_URL is server-only. Next.js never inlines it into the
  // browser bundle — do not gate client routing on it.
  const rewriteTarget = process.env.API_BASE_URL?.trim();

  if (explicit) {
    const normalized = normalizeBase(explicit);
    if (process.env.NODE_ENV === "production" && shouldPreferApiProxy(normalized)) {
      // Loopback / loca.lt in production → same-origin proxy (avoids 511 interstitial).
      return resolveProxyBase(options);
    }
    if (process.env.NODE_ENV !== "production" || !isLoopbackUrl(normalized)) {
      return normalized;
    }
  }

  if (process.env.NODE_ENV === "production") {
    // Browser: always use /api/backend. The route handler reads API_BASE_URL.
    if (typeof window !== "undefined") {
      return resolveProxyBase(options);
    }
    // Server components / SSR: prefer upstream when available, else proxy path.
    if (rewriteTarget) {
      return normalizeBase(rewriteTarget);
    }
    return resolveProxyBase(options);
  }

  if (rewriteTarget && typeof window !== "undefined") {
    return resolveProxyBase(options);
  }

  return explicit ? normalizeBase(explicit) : "http://127.0.0.1:8000";
}

export function formatApiConnectionError(cause: unknown): string {
  if (cause instanceof TypeError && /fetch/i.test(cause.message)) {
    return (
      "Cannot reach the checkmate API. Set NEXT_PUBLIC_API_BASE_URL to your cloud " +
      "FastAPI URL (e.g. https://checkmate-api.onrender.com), not 127.0.0.1 or loca.lt. " +
      "See scripts/deploy-production-api.ps1."
    );
  }
  if (cause instanceof Error) {
    return cause.message;
  }
  return "API request failed";
}
