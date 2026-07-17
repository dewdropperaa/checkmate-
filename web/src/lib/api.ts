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
};

export type SyncUserResponse = {
  user: BackendUser;
  created: boolean;
};

export async function syncBackendUser(
  idToken: string,
): Promise<SyncUserResponse> {
  const response = await fetch(`${apiBaseUrl()}/auth/sync`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${idToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({}),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(
      `Backend user sync failed (${response.status}): ${detail || response.statusText}`,
    );
  }

  return (await response.json()) as SyncUserResponse;
}
