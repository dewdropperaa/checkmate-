import { isEphemeralTunnelUrl } from "@/lib/apiBaseUrl";
import { NextRequest, NextResponse } from "next/server";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

function backendBase(): string | null {
  const raw = process.env.API_BASE_URL?.trim();
  if (!raw) return null;
  return raw.replace(/\/$/, "");
}

/**
 * Same-origin FastAPI proxy for /api/backend/*.
 * Strips the browser User-Agent and sets bypass-tunnel-reminder so Localtunnel
 * does not return its IP interstitial (HTTP 511) to clients.
 */
export async function proxyBackendRequest(
  request: NextRequest,
  relativePath: string,
): Promise<Response> {
  const base = backendBase();
  if (!base) {
    return NextResponse.json(
      {
        detail: {
          error: "api_proxy_unconfigured",
          message:
            "API_BASE_URL is not set. Point it at your FastAPI origin and redeploy.",
        },
      },
      { status: 503 },
    );
  }

  const cleanPath = relativePath.replace(/^\/+/, "");
  const upstream = new URL(`${base}/${cleanPath}`);
  request.nextUrl.searchParams.forEach((value, key) => {
    if (key === "__path") return;
    upstream.searchParams.append(key, value);
  });

  const headers = new Headers();
  request.headers.forEach((value, key) => {
    if (HOP_BY_HOP.has(key.toLowerCase())) return;
    if (key.toLowerCase() === "user-agent") return;
    headers.set(key, value);
  });
  headers.set("user-agent", "checkmate-vercel-proxy/1.0");
  if (isEphemeralTunnelUrl(base)) {
    headers.set("bypass-tunnel-reminder", "1");
  }

  const method = request.method.toUpperCase();
  const body =
    method === "GET" || method === "HEAD"
      ? undefined
      : await request.arrayBuffer();

  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(upstream, {
      method,
      headers,
      body,
      redirect: "manual",
      cache: "no-store",
    });
  } catch (cause) {
    const message =
      cause instanceof Error ? cause.message : "Upstream API unreachable";
    return NextResponse.json(
      {
        detail: {
          error: "api_proxy_upstream_error",
          message,
        },
      },
      { status: 502 },
    );
  }

  const responseHeaders = new Headers();
  upstreamResponse.headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (HOP_BY_HOP.has(lower)) return;
    // fetch() may already decompress; never re-advertise upstream encodings.
    if (lower === "content-encoding" || lower === "content-length") return;
    responseHeaders.set(key, value);
  });

  // Buffer the body. Piping upstreamResponse.body can yield empty responses on
  // Vercel when the upstream (e.g. Cloudflare tunnel) uses chunked transfer.
  const payload = Buffer.from(await upstreamResponse.arrayBuffer());
  responseHeaders.set("content-length", String(payload.byteLength));

  return new NextResponse(payload, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
}
