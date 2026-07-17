const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
const DEFAULT_WEB_APP_URL = "http://localhost:3000";

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
        webAppUrl?: string;
      };
    }
  | { type: "CLEAR_AUTH" }
  | {
      type: "OPEN_WEB_AUTH";
      payload?: { mode?: "signin" | "signup" };
    };

type ExternalConnectMessage = {
  type: "CHECKMATE_CONNECT";
  authToken?: string;
  backendBaseUrl?: string;
};

function normalizeBaseUrl(input?: string, fallback = DEFAULT_BACKEND_URL): string {
  const trimmed = (input ?? "").trim();
  if (!trimmed) {
    return fallback;
  }
  return trimmed.replace(/\/+$/, "");
}

async function getSettings(): Promise<{
  backendBaseUrl: string;
  authToken: string;
  webAppUrl: string;
}> {
  const stored = await chrome.storage.local.get([
    "backendBaseUrl",
    "authToken",
    "webAppUrl",
  ]);
  return {
    backendBaseUrl: normalizeBaseUrl(stored.backendBaseUrl, DEFAULT_BACKEND_URL),
    authToken: typeof stored.authToken === "string" ? stored.authToken : "",
    webAppUrl: normalizeBaseUrl(stored.webAppUrl, DEFAULT_WEB_APP_URL),
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

async function openWebAuth(mode: "signin" | "signup" = "signin"): Promise<void> {
  const { webAppUrl } = await getSettings();
  const path = mode === "signup" ? "/en/signup" : "/en/signin";
  const url = new URL(`${webAppUrl}${path}`);
  url.searchParams.set("from", "extension");
  url.searchParams.set("next", "/connect-extension");
  url.searchParams.set("extensionId", chrome.runtime.id);
  await chrome.tabs.create({ url: url.toString() });
}

async function applyExternalConnect(
  message: ExternalConnectMessage,
): Promise<{ ok: boolean; error?: string }> {
  const authToken = (message.authToken ?? "").trim();
  if (!authToken) {
    return { ok: false, error: "missing_token" };
  }
  const backendBaseUrl = normalizeBaseUrl(
    message.backendBaseUrl,
    DEFAULT_BACKEND_URL,
  );
  await chrome.storage.local.set({ authToken, backendBaseUrl });
  return { ok: true };
}

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(["backendBaseUrl", "webAppUrl"]);
  const updates: Record<string, string> = {};
  if (typeof stored.backendBaseUrl !== "string" || !stored.backendBaseUrl.trim()) {
    updates.backendBaseUrl = DEFAULT_BACKEND_URL;
  }
  if (typeof stored.webAppUrl !== "string" || !stored.webAppUrl.trim()) {
    updates.webAppUrl = DEFAULT_WEB_APP_URL;
  }
  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
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
      .then((settings) =>
        sendResponse({
          ok: true,
          ...settings,
          connected: Boolean(settings.authToken),
        }),
      )
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "SAVE_SETTINGS") {
    const backendBaseUrl = normalizeBaseUrl(
      message.payload.backendBaseUrl,
      DEFAULT_BACKEND_URL,
    );
    const webAppUrl = normalizeBaseUrl(message.payload.webAppUrl, DEFAULT_WEB_APP_URL);
    const updates: Record<string, string> = { backendBaseUrl, webAppUrl };
    if (typeof message.payload.authToken === "string") {
      updates.authToken = message.payload.authToken.trim();
    }
    chrome.storage.local
      .set(updates)
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "CLEAR_AUTH") {
    chrome.storage.local
      .remove(["authToken"])
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "OPEN_WEB_AUTH") {
    openWebAuth(message.payload?.mode ?? "signin")
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  return false;
});

chrome.runtime.onMessageExternal.addListener(
  (message: ExternalConnectMessage, _sender, sendResponse) => {
    if (message?.type !== "CHECKMATE_CONNECT") {
      sendResponse({ ok: false, error: "unknown_message" });
      return false;
    }
    applyExternalConnect(message)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  },
);

export {};
