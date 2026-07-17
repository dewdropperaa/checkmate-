type ApiResponse<T = unknown> = {
  ok: boolean;
  status: number;
  data: T;
};

type PendingInterrupt = {
  node?: string;
  value?: {
    scan_id?: string;
    target?: string;
    planned_active_tests?: string[];
    message?: string;
  };
};

type ScanStatusData = {
  scan_id?: string;
  target?: string;
  status?: string;
  current_node?: string;
  next_nodes?: string[];
  human_approval_needed?: boolean;
  human_approved?: boolean;
  approved_tools?: string[];
  rejected_tools?: string[];
  pending_interrupt?: PendingInterrupt | null;
  findings_count?: number;
  is_complete?: boolean;
};

const TOOL_DESCRIPTIONS: Record<string, string> = {
  sqlmap: "SQL injection scanner (parameterized URLs only)",
  zap: "OWASP ZAP active vulnerability scanner",
};

type ReportSeverityData = {
  severity_scores?: {
    severity_counts?: Record<string, number>;
    overall_risk_score?: number;
  };
};

const currentUrlEl = document.getElementById("current-url") as HTMLDivElement;
const scanBtn = document.getElementById("scan-btn") as HTMLButtonElement;
const scanStatusEl = document.getElementById("scan-status") as HTMLParagraphElement;
const liveSectionEl = document.getElementById("live-section") as HTMLDivElement;
const currentNodeEl = document.getElementById("current-node") as HTMLElement;
const findingsCountEl = document.getElementById("findings-count") as HTMLElement;
const summarySectionEl = document.getElementById("summary-section") as HTMLDivElement;
const severitySummaryEl = document.getElementById("severity-summary") as HTMLUListElement;
const reportBtn = document.getElementById("report-btn") as HTMLButtonElement;
const downloadPdfBtn = document.getElementById("download-pdf-btn") as HTMLButtonElement;
const openOptionsBtn = document.getElementById("open-options") as HTMLButtonElement;
const approvalModalEl = document.getElementById("approval-modal") as HTMLDivElement;
const approvalTextEl = document.getElementById("approval-text") as HTMLParagraphElement;
const approvalErrorEl = document.getElementById("approval-error") as HTMLParagraphElement;
const toolChecklistEl = document.getElementById("tool-checklist") as HTMLUListElement;
const approveBtn = document.getElementById("approve-btn") as HTMLButtonElement;
const rejectBtn = document.getElementById("reject-btn") as HTMLButtonElement;
const authGateEl = document.getElementById("auth-gate") as HTMLDivElement;
const scanPanelEl = document.getElementById("scan-panel") as HTMLDivElement;
const authGateStatusEl = document.getElementById(
  "auth-gate-status",
) as HTMLParagraphElement;
const signInBtn = document.getElementById("signin-btn") as HTMLButtonElement;
const signUpBtn = document.getElementById("signup-btn") as HTMLButtonElement;

let pollTimer: number | undefined;
let baseBackendUrl = "";
let activeTarget = "";
let activeScanId = "";
let currentReportUrl = "";
let currentPdfUrl = "";
let approvalActionPending = false;
let approvalShown = false;
let autoApproveTimer: number | undefined;
let plannedActiveTests: string[] = [];
let selectedTools = new Set<string>();

const AUTO_APPROVE_SECONDS = 8;

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
  query?: Record<string, string | number | boolean>;
}): Promise<ApiResponse<T>> {
  return sendMessage<ApiResponse<T>>({ type: "API_REQUEST", payload });
}

async function getSettings(): Promise<{
  backendBaseUrl: string;
  authToken: string;
  connected: boolean;
}> {
  const settings = await sendMessage<{
    ok: boolean;
    backendBaseUrl?: string;
    authToken?: string;
    connected?: boolean;
  }>({ type: "GET_SETTINGS" });
  return {
    backendBaseUrl: (settings.backendBaseUrl ?? "http://127.0.0.1:8000").replace(
      /\/+$/,
      "",
    ),
    authToken: settings.authToken ?? "",
    connected: Boolean(settings.connected ?? settings.authToken),
  };
}

async function getBackendBaseUrl(): Promise<string> {
  const settings = await getSettings();
  return settings.backendBaseUrl;
}

function showAuthGate(message?: string): void {
  authGateEl.hidden = false;
  scanPanelEl.hidden = true;
  if (message) {
    authGateStatusEl.textContent = message;
  }
}

function showScanPanel(): void {
  authGateEl.hidden = true;
  scanPanelEl.hidden = false;
}

async function getActiveTabUrl(): Promise<string> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? "";
}

function isScannableUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function setScanStatus(text: string, muted = false): void {
  scanStatusEl.textContent = text;
  scanStatusEl.classList.toggle("muted", muted);
}

function clearAutoApproveTimer(): void {
  if (autoApproveTimer !== undefined) {
    window.clearTimeout(autoApproveTimer);
    autoApproveTimer = undefined;
  }
}

function clearPolling(): void {
  if (pollTimer !== undefined) {
    window.clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

function renderSeveritySummary(severityMap: Record<string, number>): void {
  severitySummaryEl.innerHTML = "";
  const orderedKeys = ["critical", "high", "medium", "low", "info"];
  for (const key of orderedKeys) {
    const count = severityMap[key] ?? 0;
    const item = document.createElement("li");
    item.dataset.severity = key;
    item.innerHTML = `<span>${key.toUpperCase()}</span><strong>${count}</strong>`;
    severitySummaryEl.appendChild(item);
  }
}

function updateApproveButtonState(): void {
  approveBtn.disabled = approvalActionPending || selectedTools.size === 0;
}

function renderToolChecklist(tools: string[]): void {
  toolChecklistEl.innerHTML = "";
  for (const tool of tools) {
    const item = document.createElement("li");

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = `tool-${tool}`;
    checkbox.checked = selectedTools.has(tool);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        selectedTools.add(tool);
      } else {
        selectedTools.delete(tool);
      }
      updateApproveButtonState();
    });

    const label = document.createElement("label");
    label.htmlFor = checkbox.id;
    const nameEl = document.createElement("span");
    nameEl.className = "tool-name";
    nameEl.textContent = tool;
    const descEl = document.createElement("span");
    descEl.className = "tool-desc";
    descEl.textContent = TOOL_DESCRIPTIONS[tool] ?? "Active/intrusive test";
    label.appendChild(nameEl);
    label.appendChild(descEl);

    item.appendChild(checkbox);
    item.appendChild(label);
    toolChecklistEl.appendChild(item);
  }
  updateApproveButtonState();
}

async function openReport(): Promise<void> {
  if (!currentReportUrl) {
    return;
  }
  await chrome.tabs.create({ url: currentReportUrl });
}

async function downloadPdf(): Promise<void> {
  if (!currentPdfUrl) {
    return;
  }
  await chrome.tabs.create({ url: currentPdfUrl });
}

async function loadSeveritySummary(): Promise<void> {
  const response = await apiRequest<ReportSeverityData>({
    path: `/scan/${encodeURIComponent(activeScanId)}/report/json`,
    method: "GET",
  });

  if (!response.ok || !response.data) {
    return;
  }

  const counts = response.data.severity_scores?.severity_counts ?? {};
  renderSeveritySummary(counts);
  summarySectionEl.hidden = false;
}

async function sendApproval(approvedTools: string[]): Promise<void> {
  if (!activeScanId || approvalActionPending) {
    return;
  }
  approvalActionPending = true;
  approvalErrorEl.hidden = true;
  clearAutoApproveTimer();

  const approved = approvedTools.length > 0;

  // Give immediate feedback: the backend resumes the scan in the background,
  // so hide the dialog right away and show an analyzing state instead of
  // leaving the modal frozen while the request is in flight.
  approveBtn.disabled = true;
  rejectBtn.disabled = true;
  approvalModalEl.hidden = true;
  setScanStatus(
    approved
      ? `Running approved tests: ${approvedTools.join(", ")}...`
      : "All active tests rejected. Finishing up...",
    false,
  );

  try {
    const response = await apiRequest({
      path: `/scan/${encodeURIComponent(activeScanId)}/approve`,
      method: "POST",
      body: { approved, approved_tools: approvedTools },
    });

    if (!response.ok) {
      throw new Error(`Approval request failed (${response.status})`);
    }
  } catch (error) {
    // Re-open the dialog so the user can retry the decision.
    approvalModalEl.hidden = false;
    rejectBtn.disabled = false;
    updateApproveButtonState();
    approvalErrorEl.textContent = String(error);
    approvalErrorEl.hidden = false;
  } finally {
    approvalActionPending = false;
  }
}

function scheduleAutoApprove(): void {
  clearAutoApproveTimer();
  let remaining = AUTO_APPROVE_SECONDS;
  const updateCountdown = (): void => {
    approvalTextEl.textContent =
      `This scan wants to run active tests against ${activeTarget}. ` +
      `Auto-approving the checked tools in ${remaining}s unless you change the selection or reject.`;
  };
  updateCountdown();
  autoApproveTimer = window.setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearAutoApproveTimer();
      void sendApproval(Array.from(selectedTools));
      return;
    }
    updateCountdown();
  }, 1000);
}
let statusRetryCount = 0;
const MAX_STATUS_RETRIES = 5;

async function pollScanStatus(): Promise<void> {
  if (!activeScanId) {
    return;
  }

  let response: ApiResponse<ScanStatusData>;
  try {
    response = await apiRequest<ScanStatusData>({
      path: `/scan/${encodeURIComponent(activeScanId)}/status`,
      method: "GET",
    });
  } catch {
    statusRetryCount++;
    if (statusRetryCount >= MAX_STATUS_RETRIES) {
      clearPolling();
      scanBtn.disabled = false;
      setScanStatus("Lost connection to backend. Click to re-scan.", false);
    }
    return;
  }

  if (!response.ok) {
    statusRetryCount++;
    if (response.status === 0) {
      if (statusRetryCount >= MAX_STATUS_RETRIES) {
        clearPolling();
        scanBtn.disabled = false;
        setScanStatus("Backend unreachable. Start it and check Options.", false);
      }
      return;
    }
    if (statusRetryCount >= MAX_STATUS_RETRIES) {
      clearPolling();
      scanBtn.disabled = false;
      setScanStatus(`Scan status unavailable (${response.status}). Try re-scanning.`, false);
    } else {
      setScanStatus(`Retrying status check... (${statusRetryCount}/${MAX_STATUS_RETRIES})`, true);
    }
    return;
  }

  statusRetryCount = 0;

  const data = response.data ?? {};
  const status = (data.status ?? "unknown").toLowerCase();
  const currentNode = data.current_node ?? "-";
  const findingsCount = data.findings_count ?? 0;
  const awaitingApproval =
    Boolean(data.pending_interrupt) ||
    (Boolean(data.human_approval_needed) && !data.human_approved);

  liveSectionEl.hidden = false;
  currentNodeEl.textContent = currentNode;
  findingsCountEl.textContent = String(findingsCount);
  setScanStatus(`Scan status: ${status}`, false);

  if (awaitingApproval && !data.is_complete && !approvalShown) {
    approvalShown = true;
    plannedActiveTests = data.pending_interrupt?.value?.planned_active_tests ?? [];
    selectedTools = new Set(plannedActiveTests);
    approvalTextEl.textContent =
      data.pending_interrupt?.value?.message ??
      `This scan wants to run active tests against ${activeTarget}. ` +
        `Pick which tools to allow, then approve.`;
    renderToolChecklist(plannedActiveTests);
    approveBtn.disabled = false;
    rejectBtn.disabled = false;
    approvalModalEl.hidden = false;
    updateApproveButtonState();
    scheduleAutoApprove();
  }

  if (data.is_complete) {
    clearPolling();
    clearAutoApproveTimer();
    scanBtn.disabled = false;
    approvalModalEl.hidden = true;
    currentReportUrl = `${baseBackendUrl}/scan/${encodeURIComponent(activeScanId)}/report/html`;
    currentPdfUrl = `${baseBackendUrl}/scan/${encodeURIComponent(activeScanId)}/report/pdf`;
    reportBtn.hidden = false;
    downloadPdfBtn.hidden = false;
    await loadSeveritySummary().catch(() => undefined);
    setScanStatus(`Scan complete (${status}).`, false);
  }
}

async function startScan(): Promise<void> {
  if (!activeTarget) {
    setScanStatus("No scannable URL on this tab.", false);
    return;
  }

  try {
    clearPolling();
    clearAutoApproveTimer();
    approvalShown = false;
    plannedActiveTests = [];
    selectedTools = new Set();
    activeScanId = "";
    currentReportUrl = "";
    currentPdfUrl = "";
    statusRetryCount = 0;
    scanBtn.disabled = true;
    liveSectionEl.hidden = true;
    summarySectionEl.hidden = true;
    reportBtn.hidden = true;
    downloadPdfBtn.hidden = true;
    approvalModalEl.hidden = true;
    setScanStatus("Submitting scan request...", true);

    const response = await apiRequest<{ scan_id?: string; id?: string }>({
      path: "/scan",
      method: "POST",
      body: { target: activeTarget, confirmed_authorized: true },
    });

    if (!response.ok) {
      scanBtn.disabled = false;
      if (response.status === 429) {
        setScanStatus("Rate limit reached. Wait a moment and try again.", false);
        return;
      }
      if (response.status === 0) {
        setScanStatus(
          "Cannot reach backend. Start it and check the URL in Options.",
          false,
        );
        return;
      }
      setScanStatus(`Failed to start scan (${response.status}).`, false);
      return;
    }

    activeScanId = response.data?.scan_id ?? response.data?.id ?? "";
    if (!activeScanId) {
      scanBtn.disabled = false;
      setScanStatus("Backend did not return a scan id.", false);
      return;
    }

    setScanStatus(`Scan queued: ${activeScanId}`, false);
    await pollScanStatus();
    clearPolling();
    pollTimer = window.setInterval(() => {
      void pollScanStatus().catch((error) => {
        setScanStatus(`Status polling error: ${String(error)}`, false);
      });
    }, 3000);
  } catch (error) {
    scanBtn.disabled = false;
    setScanStatus(`Failed to start scan: ${String(error)}`, false);
  }
}

async function checkBackendHealth(): Promise<boolean> {
  try {
    const response = await apiRequest<{ status?: string }>({
      path: "/health",
      method: "GET",
    });
    return response.ok && response.data?.status === "ok";
  } catch {
    return false;
  }
}

async function init(): Promise<void> {
  const settings = await getSettings();
  baseBackendUrl = settings.backendBaseUrl;

  if (!settings.connected) {
    showAuthGate("Sign in or create an account on the web app to connect.");
    return;
  }

  showScanPanel();
  const currentTabUrl = await getActiveTabUrl();
  activeTarget = currentTabUrl;
  currentUrlEl.textContent = currentTabUrl || "No active tab URL detected.";

  if (!isScannableUrl(currentTabUrl)) {
    scanBtn.disabled = true;
    setScanStatus("Open an http/https page to scan it.", true);
    return;
  }

  scanBtn.textContent = "Re-scan this site";
  scanBtn.addEventListener("click", () => {
    void startScan();
  });

  setScanStatus("Checking backend connectivity...", true);
  const healthy = await checkBackendHealth();
  if (!healthy) {
    scanBtn.disabled = false;
    setScanStatus(
      "Cannot reach backend. Start it and check the URL in Options.",
      false,
    );
    return;
  }

  scanBtn.disabled = false;
  setScanStatus("Starting scan for this site...", true);
  await startScan();
}

approveBtn.addEventListener("click", () => {
  clearAutoApproveTimer();
  void sendApproval(Array.from(selectedTools));
});

rejectBtn.addEventListener("click", () => {
  clearAutoApproveTimer();
  selectedTools.clear();
  void sendApproval([]);
});

reportBtn.addEventListener("click", () => {
  void openReport();
});

downloadPdfBtn.addEventListener("click", () => {
  void downloadPdf();
});

openOptionsBtn.addEventListener("click", () => {
  void chrome.runtime.openOptionsPage();
});

signInBtn.addEventListener("click", () => {
  void sendMessage({ type: "OPEN_WEB_AUTH", payload: { mode: "signin" } }).then(
    () => {
      authGateStatusEl.textContent =
        "Complete sign-in in the browser tab, then reopen this popup.";
    },
  );
});

signUpBtn.addEventListener("click", () => {
  void sendMessage({ type: "OPEN_WEB_AUTH", payload: { mode: "signup" } }).then(
    () => {
      authGateStatusEl.textContent =
        "Create your account in the browser tab, then reopen this popup.";
    },
  );
});

window.addEventListener("beforeunload", () => {
  clearPolling();
  clearAutoApproveTimer();
});

void init().catch((err) => {
  setScanStatus(`Initialization failed: ${String(err)}`, false);
  scanBtn.disabled = true;
});
