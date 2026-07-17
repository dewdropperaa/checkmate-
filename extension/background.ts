const DEFAULT_BACKEND_URL = "http://localhost:8000";

type ApiRequestPayload = {
  path: string;
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
};

type RuntimeMessage =
  | { type: "API_REQUEST"; payload: ApiRequestPayload }
  | { type: "GET_SETTINGS" }
  | {
      type: "SAVE_SETTINGS";
      payload: {
        backendBaseUrl?: string;
        authToken?: string;
      };
    };

function normalizeBaseUrl(input?: string): string {
  const trimmed = (input ?? "").trim();
  if (!trimmed) {
    return DEFAULT_BACKEND_URL;
  }
  return trimmed.replace(/\/+$/, "");
}

async function getSettings(): Promise<{ backendBaseUrl: string; authToken: string }> {
  const stored = await chrome.storage.local.get(["backendBaseUrl", "authToken"]);
  return {
    backendBaseUrl: normalizeBaseUrl(stored.backendBaseUrl),
    authToken: typeof stored.authToken === "string" ? stored.authToken : "",
  };
}

function buildUrl(baseUrl: string, path: string, query?: ApiRequestPayload["query"]): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${baseUrl}${normalizedPath}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.toString();
}

async function performApiRequest(
  payload: ApiRequestPayload,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const { backendBaseUrl, authToken } = await getSettings();
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(payload.headers ?? {}),
  };

  let requestBody: BodyInit | undefined;
  if (payload.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
    requestBody =
      headers["Content-Type"] === "application/json"
        ? JSON.stringify(payload.body)
        : (payload.body as BodyInit);
  }

  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
    headers["X-API-Key"] = authToken;
  }

  const response = await fetch(buildUrl(backendBaseUrl, payload.path, payload.query), {
    method: payload.method ?? "GET",
    headers,
    body: requestBody,
  });

  const contentType = response.headers.get("content-type") ?? "";
  let data: unknown;
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  return {
    ok: response.ok,
    status: response.status,
    data,
  };
}

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(["backendBaseUrl"]);
  if (typeof stored.backendBaseUrl !== "string" || !stored.backendBaseUrl.trim()) {
    await chrome.storage.local.set({ backendBaseUrl: DEFAULT_BACKEND_URL });
  }
});

chrome.runtime.onMessage.addListener((message: RuntimeMessage, _sender, sendResponse) => {
  if (message?.type === "API_REQUEST") {
    performApiRequest(message.payload)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, status: 0, data: String(err) }));
    return true;
  }

  if (message?.type === "GET_SETTINGS") {
    getSettings()
      .then((settings) => sendResponse({ ok: true, ...settings }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "SAVE_SETTINGS") {
    const backendBaseUrl = normalizeBaseUrl(message.payload.backendBaseUrl);
    const authToken = (message.payload.authToken ?? "").trim();
    chrome.storage.local
      .set({ backendBaseUrl, authToken })
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  return false;
});

export {};
