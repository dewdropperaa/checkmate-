/**
 * Resolves the FastAPI base URL for browser API calls.
 *
 * Local dev: direct loopback (NEXT_PUBLIC_API_BASE_URL or 127.0.0.1:8000).
 * Production (Vercel): public HTTPS URL via NEXT_PUBLIC_API_BASE_URL, or
 * same-origin `/api/backend` when API_BASE_URL is set for Next.js rewrites.
 */

export const API_PROXY_PATH = "/api/backend";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopbackUrl(url: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(url).hostname.toLowerCase());
  } catch {
    return false;
  }
}

function normalizeBase(url: string): string {
  return url.trim().replace(/\/$/, "");
}

/**
 * Public backend URL for the Chrome extension (must be reachable from the browser,
 * not the Vercel same-origin proxy).
 */
export function resolveExtensionBackendBaseUrl(): string {
  const explicit = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  if (explicit) {
    const normalized = normalizeBase(explicit);
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

export function resolveApiBaseUrl(options?: { origin?: string }): string {
  const explicit = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  if (explicit) {
    const normalized = normalizeBase(explicit);
    if (process.env.NODE_ENV !== "production" || !isLoopbackUrl(normalized)) {
      return normalized;
    }
    // Misconfiguration: production build still points at loopback (common when
    // copying web/.env.example into Vercel). Prefer the server proxy below.
  }

  const rewriteTarget = process.env.API_BASE_URL?.trim();
  if (rewriteTarget) {
    if (typeof window !== "undefined") {
      const origin = options?.origin ?? window.location.origin;
      return `${origin}${API_PROXY_PATH}`;
    }
    return normalizeBase(rewriteTarget);
  }

  if (process.env.NODE_ENV === "development") {
    return explicit ? normalizeBase(explicit) : "http://127.0.0.1:8000";
  }

  throw new Error(
    "API is not configured for production. On Vercel set API_BASE_URL (HTTPS FastAPI origin for /api/backend proxy) or NEXT_PUBLIC_API_BASE_URL (public API URL). Redeploy after changing env vars.",
  );
}

export function formatApiConnectionError(cause: unknown): string {
  if (cause instanceof TypeError && /fetch/i.test(cause.message)) {
    return (
      "Cannot reach the checkmate API. On Vercel, set API_BASE_URL or NEXT_PUBLIC_API_BASE_URL " +
      "to your deployed FastAPI URL (not 127.0.0.1), then redeploy."
    );
  }
  if (cause instanceof Error) {
    return cause.message;
  }
  return "API request failed";
}
