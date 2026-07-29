import type { BackendUser, ScanHistoryResponse } from "@/lib/api";
import { getPlan, type PlanId } from "@/config/plans";

export type QuotaDecision =
  | { allowed: true }
  | { allowed: false; reason: "target_limit" | "scan_limit" };

export type FeatureDecision =
  | { allowed: true }
  | { allowed: false; reason: "authenticated_scanning_locked" };

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

export function canUseAuthenticatedScanning(user: BackendUser): FeatureDecision {
  const planId = user.plan_id as PlanId;
  try {
    if (getPlan(planId).authenticatedScanning) {
      return { allowed: true };
    }
  } catch {
    // Unknown plan id — treat as locked.
  }
  return { allowed: false, reason: "authenticated_scanning_locked" };
}
