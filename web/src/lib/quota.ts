import type { BackendUser, ScanHistoryResponse } from "@/lib/api";

export type QuotaDecision =
  | { allowed: true }
  | { allowed: false; reason: "target_limit" | "scan_limit" };

function normalizeTarget(target: string): string {
  const value = target.trim().toLowerCase();
  if (!value) return "";
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).hostname;
  } catch {
    return value.replace(/\/+$/, "");
  }
}

export function canAddSite(
  user: BackendUser,
  usage: ScanHistoryResponse,
  target: string,
): QuotaDecision {
  const normalized = normalizeTarget(target);
  const alreadyKnown = usage.targets.some(
    (item) => normalizeTarget(item) === normalized,
  );
  if (
    !alreadyKnown &&
    user.max_targets !== null &&
    usage.target_count >= user.max_targets
  ) {
    return { allowed: false, reason: "target_limit" };
  }
  return { allowed: true };
}

export function canRunScan(
  user: BackendUser,
  usage: ScanHistoryResponse,
): QuotaDecision {
  if (
    user.scans_per_month !== null &&
    usage.scans_this_month >= user.scans_per_month
  ) {
    return { allowed: false, reason: "scan_limit" };
  }
  return { allowed: true };
}
