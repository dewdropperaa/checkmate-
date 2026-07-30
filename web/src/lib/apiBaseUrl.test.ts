import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  API_PROXY_PATH,
  isEphemeralTunnelUrl,
  resolveApiBaseUrl,
  resolveExtensionBackendBaseUrl,
  tunnelBypassHeaders,
} from "./apiBaseUrl";

describe("resolveApiBaseUrl", () => {
  const env = process.env;

  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    delete process.env.NEXT_PUBLIC_API_BASE_URL;
    delete process.env.API_BASE_URL;
  });

  afterEach(() => {
    process.env = { ...env };
    vi.unstubAllEnvs();
  });

  it("uses public NEXT_PUBLIC_API_BASE_URL in production", () => {
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "https://api.example.com/");
    expect(resolveApiBaseUrl()).toBe("https://api.example.com");
  });

  it("ignores loopback NEXT_PUBLIC in production when API_BASE_URL is set", () => {
    vi.stubEnv("NEXT_PUBLIC_API_BASE_URL", "http://127.0.0.1:8000");
    vi.stubEnv("API_BASE_URL", "https://api.example.com");
    expect(resolveApiBaseUrl({ origin: "https://app.vercel.app" })).toBe(
      `https://app.vercel.app${API_PROXY_PATH}`,
    );
  });

  it("proxies loca.lt NEXT_PUBLIC in production (cloud API required on server)", () => {
    vi.stubEnv(
      "NEXT_PUBLIC_API_BASE_URL",
      "https://polite-things-thank.loca.lt",
    );
    delete process.env.API_BASE_URL;
    expect(resolveApiBaseUrl({ origin: "https://app.vercel.app" })).toBe(
      `https://app.vercel.app${API_PROXY_PATH}`,
    );
  });

  it("uses onrender.com directly in production", () => {
    vi.stubEnv(
      "NEXT_PUBLIC_API_BASE_URL",
      "https://checkmate-api.onrender.com",
    );
    expect(resolveApiBaseUrl()).toBe("https://checkmate-api.onrender.com");
  });

  it("uses same-origin proxy in production when NEXT_PUBLIC is unset", () => {
    // Simulates the browser bundle: API_BASE_URL is never inlined client-side.
    delete process.env.API_BASE_URL;
    expect(resolveApiBaseUrl({ origin: "https://app.vercel.app" })).toBe(
      `https://app.vercel.app${API_PROXY_PATH}`,
    );
  });

  it("defaults to loopback in development", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(resolveApiBaseUrl()).toBe("http://127.0.0.1:8000");
  });
});

describe("isEphemeralTunnelUrl / tunnelBypassHeaders", () => {
  it("detects loca.lt and returns bypass headers", () => {
    expect(isEphemeralTunnelUrl("https://foo.loca.lt")).toBe(true);
    expect(tunnelBypassHeaders("https://foo.loca.lt")).toEqual({
      "bypass-tunnel-reminder": "1",
    });
  });

  it("skips bypass headers for real APIs", () => {
    expect(isEphemeralTunnelUrl("https://api.example.com")).toBe(false);
    expect(tunnelBypassHeaders("https://api.example.com")).toEqual({});
  });
});

describe("resolveExtensionBackendBaseUrl", () => {
  beforeEach(() => {
    vi.stubEnv("NODE_ENV", "production");
    delete process.env.NEXT_PUBLIC_API_BASE_URL;
    delete process.env.NEXT_PUBLIC_BACKEND_URL;
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("uses HTTPS public API URL", () => {
    vi.stubEnv(
      "NEXT_PUBLIC_API_BASE_URL",
      "https://api.example.com",
    );
    expect(resolveExtensionBackendBaseUrl()).toBe("https://api.example.com");
  });
});
