const STORAGE_KEY = "checkmate:pendingTarget";

export function setPendingTarget(target: string): void {
  const trimmed = target.trim();
  if (!trimmed || typeof window === "undefined") return;
  try {
    sessionStorage.setItem(STORAGE_KEY, trimmed);
  } catch {
    // Private mode / quota — URL param still works for immediate navigations.
  }
}

export function takePendingTarget(): string | undefined {
  if (typeof window === "undefined") return undefined;
  try {
    const value = sessionStorage.getItem(STORAGE_KEY)?.trim();
    if (value) sessionStorage.removeItem(STORAGE_KEY);
    return value || undefined;
  } catch {
    return undefined;
  }
}
