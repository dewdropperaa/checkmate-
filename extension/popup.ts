type ApiResponse<T = unknown> = {
  ok: boolean;
  status: number;
  data: T;
};

type ScanStatusData = {
  scan_id?: string;
  target?: string;
  status?: string;
  current_node?: string;
  next_nodes?: string[];
  human_approval_needed?: boolean;
  human_approved?: boolean;
  pending_interrupt?: unknown | null;
  findings_count?: number;
  is_complete?: boolean;
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
const openOptionsBtn = document.getElementById("open-options") as HTMLButtonElement;
const approvalModalEl = document.getElementById("approval-modal") as HTMLDivElement;
const approvalTextEl = document.getElementById("approval-text") as HTMLParagraphElement;
const approvalErrorEl = document.getElementById("approval-error") as HTMLParagraphElement;
const approveBtn = document.getElementById("approve-btn") as HTMLButtonElement;
const rejectBtn = document.getElementById("reject-btn") as HTMLButtonElement;

let pollTimer: number | undefined;
let baseBackendUrl = "";
let activeTarget = "";
let activeScanId = "";
let currentReportUrl = "";
let approvalActionPending = false;
let approvalShown = false;

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

async function getBackendBaseUrl(): Promise<string> {
  const settings = await sendMessage<{ ok: boolean; backendBaseUrl?: string }>({
    type: "GET_SETTINGS",
  });
  return (settings.backendBaseUrl ?? "http://localhost:8000").replace(/\/+$/, "");
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
    item.innerHTML = `<span>${key.toUpperCase()}</span><strong>${count}</strong>`;
    severitySummaryEl.appendChild(item);
  }
}

async function openReport(): Promise<void> {
  if (!currentReportUrl) {
    return;
  }
  await chrome.tabs.create({ url: currentReportUrl });
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

async function sendApproval(approved: boolean): Promise<void> {
  if (!activeScanId || approvalActionPending) {
    return;
  }
  approvalActionPending = true;
  approvalErrorEl.hidden = true;

  try {
    const response = await apiRequest({
      path: `/scan/${encodeURIComponent(activeScanId)}/approve`,
      method: "POST",
      body: { approved },
    });

    if (!response.ok) {
      throw new Error(`Approval request failed (${response.status})`);
    }

    approvalModalEl.hidden = true;
    setScanStatus(
      approved ? "Active tests approved. Scan continuing..." : "Active tests rejected.",
      false,
    );
  } catch (error) {
    approvalErrorEl.textContent = String(error);
    approvalErrorEl.hidden = false;
  } finally {
    approvalActionPending = false;
  }
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
    approvalTextEl.textContent =
      `This scan wants to run active tests (sqlmap / ZAP active scan) against ` +
      `${activeTarget}. Approve?`;
    approvalModalEl.hidden = false;
  }

  if (data.is_complete) {
    clearPolling();
    scanBtn.disabled = false;
    approvalModalEl.hidden = true;
    currentReportUrl = `${baseBackendUrl}/scan/${encodeURIComponent(activeScanId)}/report/html`;
    reportBtn.hidden = false;
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
    approvalShown = false;
    activeScanId = "";
    currentReportUrl = "";
    statusRetryCount = 0;
    scanBtn.disabled = true;
    liveSectionEl.hidden = true;
    summarySectionEl.hidden = true;
    reportBtn.hidden = true;
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
  baseBackendUrl = await getBackendBaseUrl();
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
  void sendApproval(true);
});

rejectBtn.addEventListener("click", () => {
  void sendApproval(false);
});

reportBtn.addEventListener("click", () => {
  void openReport();
});

openOptionsBtn.addEventListener("click", () => {
  void chrome.runtime.openOptionsPage();
});

window.addEventListener("beforeunload", () => {
  clearPolling();
});

void init().catch((err) => {
  setScanStatus(`Initialization failed: ${String(err)}`, false);
  scanBtn.disabled = true;
});
