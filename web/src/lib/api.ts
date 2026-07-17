/**
 * Thin client for the checkmate backend API.
 * Always sends a verified Firebase ID token — never a client-invented user id.
 */

function apiBaseUrl(): string {
  const base = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();
  if (!base) {
    throw new Error(
      "Missing NEXT_PUBLIC_API_BASE_URL. Set it in web/.env.local (e.g. http://127.0.0.1:8000).",
    );
  }
  return base.replace(/\/$/, "");
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message);
  }
}

async function authenticatedRequest<T>(
  path: string,
  idToken: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${idToken}`,
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const detail = payload?.detail ?? payload;
    throw new ApiError(
      detail?.message || response.statusText || "API request failed",
      response.status,
      detail?.error,
    );
  }
  return (await response.json()) as T;
}

export type BackendUser = {
  id: string;
  email: string | null;
  display_name: string | null;
  email_verified: boolean;
  auth_provider: string | null;
  org_id: string;
  plan_id: string;
  max_targets: number | null;
  scans_per_month: number | null;
  terms_accepted_at?: string | null;
  terms_version?: string | null;
};

export type SyncUserResponse = {
  user: BackendUser;
  created: boolean;
};

export type ScanHistoryItem = {
  id: string;
  target: string;
  status: string;
  current_node: string | null;
  overall_risk_score: number | null;
  severity: "critical" | "high" | "medium" | "low" | "info" | null;
  created_at: string;
  updated_at: string;
};

export type ScanHistoryResponse = {
  scans: ScanHistoryItem[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  target_count: number;
  scans_this_month: number;
  targets: string[];
};

export type ScanStatus = {
  scan_id: string;
  target: string;
  status: string;
  current_node: string | null;
  next_nodes: string[];
  human_approval_needed: boolean;
  human_approved: boolean;
  pending_interrupt: Record<string, unknown> | null;
  findings_count: number;
  is_complete: boolean;
  created_at: string;
  updated_at: string;
  error?: { code: string; message: string } | null;
};

export type ScanCreateResponse = {
  scan_id: string;
  target: string;
  status: string;
};

export type ScanApprovalResponse = {
  scan_id: string;
  human_approved: boolean;
  approved_tools: string[];
  rejected_tools: string[];
};

export type ExtensionTokenResponse = {
  token: string;
  token_meta: {
    id: string;
    org_id: string;
    user_id: string;
    key_prefix: string;
    label: string | null;
    created_at: string;
    revoked_at: string | null;
  };
};

export type SyncUserOptions = {
  termsAccepted?: boolean;
  termsVersion?: string;
};

export async function syncBackendUser(
  idToken: string,
  options?: SyncUserOptions,
): Promise<SyncUserResponse> {
  const body: Record<string, unknown> = {};
  if (options?.termsAccepted) {
    body.terms_accepted = true;
    if (options.termsVersion) {
      body.terms_version = options.termsVersion;
    }
  }

  const response = await fetch(`${apiBaseUrl()}/auth/sync`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${idToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(
      `Backend user sync failed (${response.status}): ${detail || response.statusText}`,
    );
  }

  return (await response.json()) as SyncUserResponse;
}

export function getScanHistory(
  idToken: string,
  page = 1,
  pageSize = 10,
): Promise<ScanHistoryResponse> {
  return authenticatedRequest(
    `/orgs/me/scans?page=${page}&page_size=${pageSize}`,
    idToken,
  );
}

export function createScan(
  idToken: string,
  target: string,
): Promise<ScanCreateResponse> {
  return authenticatedRequest("/scan", idToken, {
    method: "POST",
    body: JSON.stringify({ target, confirmed_authorized: true }),
  });
}

export function getScanStatus(
  idToken: string,
  scanId: string,
): Promise<ScanStatus> {
  return authenticatedRequest(
    `/scan/${encodeURIComponent(scanId)}/status`,
    idToken,
  );
}

export function approveScan(
  idToken: string,
  scanId: string,
  approved: boolean,
): Promise<ScanApprovalResponse> {
  return authenticatedRequest(
    `/scan/${encodeURIComponent(scanId)}/approve`,
    idToken,
    {
      method: "POST",
      body: JSON.stringify({ approved }),
    },
  );
}

export async function fetchScanReportPdf(
  idToken: string,
  scanId: string,
): Promise<Blob> {
  const response = await fetch(
    `${apiBaseUrl()}/scan/${encodeURIComponent(scanId)}/report/pdf`,
    {
      headers: {
        Authorization: `Bearer ${idToken}`,
        Accept: "application/pdf",
      },
    },
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const detail = payload?.detail ?? payload;
    throw new ApiError(
      detail?.message || response.statusText || "PDF report unavailable",
      response.status,
      detail?.error,
    );
  }
  return response.blob();
}

export function mintExtensionToken(
  idToken: string,
  label = "chrome-extension",
): Promise<ExtensionTokenResponse> {
  return authenticatedRequest("/auth/extension/token", idToken, {
    method: "POST",
    body: JSON.stringify({ label }),
  });
}

export function revokeExtensionTokens(
  idToken: string,
): Promise<{ revoked: number }> {
  return authenticatedRequest("/auth/extension/revoke", idToken, {
    method: "POST",
  });
}
