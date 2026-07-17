/** Current published Terms / Privacy version recorded when a user accepts. */
export const TERMS_VERSION = "2026-07-17";

const STORAGE_KEY = "checkmate:pendingTermsAcceptance";

export type PendingTermsAcceptance = {
  version: string;
  acceptedAt: string;
};

/** Stash acceptance so the next /auth/sync can record it (signup or sign-in clickwrap). */
export function markTermsAccepted(version: string = TERMS_VERSION): void {
  if (typeof window === "undefined") return;
  const payload: PendingTermsAcceptance = {
    version,
    acceptedAt: new Date().toISOString(),
  };
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // Private mode / quota — sync may still succeed for existing users.
  }
}

/** Read and clear pending acceptance (one-shot for the upcoming sync). */
export function takePendingTermsAcceptance(): PendingTermsAcceptance | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PendingTermsAcceptance;
    if (!parsed?.version) return null;
    return parsed;
  } catch {
    return null;
  }
}
