type ApiResponse<T = unknown> = {
  ok: boolean;
  status: number;
  data: T;
};

const backendUrlInput = document.getElementById("backend-url") as HTMLInputElement;
const webAppUrlInput = document.getElementById("webapp-url") as HTMLInputElement;
const authTokenInput = document.getElementById("auth-token") as HTMLInputElement;
const saveSettingsBtn = document.getElementById("save-settings") as HTMLButtonElement;
const connectAccountBtn = document.getElementById(
  "connect-account",
) as HTMLButtonElement;
const createAccountBtn = document.getElementById(
  "create-account",
) as HTMLButtonElement;
const disconnectAccountBtn = document.getElementById(
  "disconnect-account",
) as HTMLButtonElement;
const connectionStatusEl = document.getElementById(
  "connection-status",
) as HTMLParagraphElement;
const newTargetInput = document.getElementById("new-target") as HTMLInputElement;
const addTargetBtn = document.getElementById("add-target") as HTMLButtonElement;
const targetListEl = document.getElementById("target-list") as HTMLUListElement;
const emptyStateEl = document.getElementById("empty-state") as HTMLParagraphElement;
const statusEl = document.getElementById("status") as HTMLParagraphElement;

let targets: string[] = [];

function sendMessage<T>(message: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response as T);
    });
  });
}

async function apiRequest<T>(payload: {
  path: string;
  method?: string;
  body?: unknown;
}): Promise<ApiResponse<T>> {
  return sendMessage<ApiResponse<T>>({ type: "API_REQUEST", payload });
}

function setStatus(text: string, error = false): void {
  statusEl.textContent = text;
  statusEl.classList.toggle("status-error", error);
}

function normalizeTarget(input: string): string {
  return input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

function parseTargets(data: unknown): string[] {
  if (Array.isArray(data)) {
    return data.map((entry) => String(entry));
  }

  if (data && typeof data === "object") {
    const candidate = (data as Record<string, unknown>).targets;
    if (Array.isArray(candidate)) {
      return candidate.map((entry) => String(entry));
    }

    const authorized = (data as Record<string, unknown>).authorized_targets;
    if (Array.isArray(authorized)) {
      return authorized.map((entry) => String(entry));
    }
  }

  return [];
}

function renderTargets(): void {
  targetListEl.innerHTML = "";
  emptyStateEl.hidden = targets.length > 0;

  for (const target of targets) {
    const row = document.createElement("li");

    const name = document.createElement("code");
    name.textContent = target;

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "danger";
    removeBtn.textContent = "Remove";
    removeBtn.addEventListener("click", () => {
      void removeTarget(target);
    });

    row.append(name, removeBtn);
    targetListEl.appendChild(row);
  }
}

async function updateTargetsOnBackend(updatedTargets: string[]): Promise<void> {
  const putResponse = await apiRequest({
    path: "/targets",
    method: "PUT",
    body: { targets: updatedTargets },
  });

  if (putResponse.ok) {
    return;
  }

  throw new Error(`Failed to update /targets (${putResponse.status})`);
}

function renderConnectionStatus(connected: boolean): void {
  connectionStatusEl.classList.toggle("empty", !connected);
  if (connected) {
    connectionStatusEl.textContent =
      "Connected to your checkmate account. You can scan from the popup.";
    connectAccountBtn.textContent = "Reconnect account";
    disconnectAccountBtn.hidden = false;
  } else {
    connectionStatusEl.textContent =
      "Not connected. Sign in on the web app, then return here.";
    connectAccountBtn.textContent = "Sign in to connect";
    disconnectAccountBtn.hidden = true;
  }
}

async function loadSettings(): Promise<boolean> {
  const settings = await sendMessage<{
    ok: boolean;
    backendBaseUrl?: string;
    authToken?: string;
    webAppUrl?: string;
    connected?: boolean;
  }>({
    type: "GET_SETTINGS",
  });
  backendUrlInput.value = settings.backendBaseUrl ?? "http://127.0.0.1:8000";
  webAppUrlInput.value = settings.webAppUrl ?? "http://localhost:3000";
  authTokenInput.value = settings.authToken ?? "";
  const connected = Boolean(settings.connected ?? settings.authToken);
  renderConnectionStatus(connected);
  return connected;
}

async function loadTargets(): Promise<void> {
  const response = await apiRequest({
    path: "/targets",
    method: "GET",
  });

  if (!response.ok) {
    setStatus(`Could not load targets (${response.status})`, true);
    return;
  }

  targets = parseTargets(response.data)
    .map((target) => normalizeTarget(target))
    .filter(Boolean)
    .filter((target, index, arr) => arr.indexOf(target) === index);

  renderTargets();
  setStatus("Loaded authorized targets.");
}

async function saveSettings(): Promise<void> {
  const backendBaseUrl = backendUrlInput.value.trim() || "http://127.0.0.1:8000";
  const webAppUrl = webAppUrlInput.value.trim() || "http://localhost:3000";
  const authToken = authTokenInput.value.trim();
  const result = await sendMessage<{ ok: boolean; error?: string }>({
    type: "SAVE_SETTINGS",
    payload: { backendBaseUrl, authToken, webAppUrl },
  });

  if (!result.ok) {
    throw new Error(result.error ?? "Failed to save settings");
  }
  renderConnectionStatus(Boolean(authToken));
}

async function addTarget(): Promise<void> {
  const normalized = normalizeTarget(newTargetInput.value);
  if (!normalized) {
    setStatus("Enter a valid domain to add.", true);
    return;
  }

  if (targets.includes(normalized)) {
    setStatus("Domain is already in authorized-targets.", true);
    return;
  }

  const updated = [...targets, normalized];
  await updateTargetsOnBackend(updated);
  targets = updated;
  newTargetInput.value = "";
  renderTargets();
  setStatus("Authorized targets updated.");
}

async function removeTarget(target: string): Promise<void> {
  const updated = targets.filter((entry) => entry !== target);
  await updateTargetsOnBackend(updated);
  targets = updated;
  renderTargets();
  setStatus("Target removed.");
}

saveSettingsBtn.addEventListener("click", () => {
  void (async () => {
    try {
      await saveSettings();
      setStatus("Settings saved.");
      if (authTokenInput.value.trim()) {
        await loadTargets();
      }
    } catch (error) {
      setStatus(String(error), true);
    }
  })();
});

connectAccountBtn.addEventListener("click", () => {
  void sendMessage({ type: "OPEN_WEB_AUTH", payload: { mode: "signin" } }).then(
    () => {
      setStatus("Complete sign-in in the browser tab, then reopen Options.");
    },
  );
});

createAccountBtn.addEventListener("click", () => {
  void sendMessage({ type: "OPEN_WEB_AUTH", payload: { mode: "signup" } }).then(
    () => {
      setStatus("Create your account in the browser tab, then reopen Options.");
    },
  );
});

disconnectAccountBtn.addEventListener("click", () => {
  void (async () => {
    await sendMessage({ type: "CLEAR_AUTH" });
    authTokenInput.value = "";
    renderConnectionStatus(false);
    setStatus("Disconnected. Sign in again to use the extension.");
  })();
});

addTargetBtn.addEventListener("click", () => {
  void addTarget().catch((error) => {
    setStatus(String(error), true);
  });
});

newTargetInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    void addTarget().catch((error) => {
      setStatus(String(error), true);
    });
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.authToken) {
    return;
  }
  const next = changes.authToken.newValue;
  authTokenInput.value = typeof next === "string" ? next : "";
  renderConnectionStatus(Boolean(next));
  if (next) {
    setStatus("Account connected.");
    void loadTargets().catch(() => undefined);
  }
});

void (async () => {
  try {
    const connected = await loadSettings();
    if (connected) {
      await loadTargets();
    } else {
      setStatus("Sign in to connect before managing targets.");
    }
  } catch (error) {
    setStatus(String(error), true);
  }
})();
