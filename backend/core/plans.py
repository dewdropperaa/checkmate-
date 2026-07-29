"""Plan catalog + Watch Agent cadence.

Limits mirror ``web/src/config/plans.ts``. Watch cadence is backend-owned:
free = manual scans only; starter = weekly; pro/agency = daily.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PlanId = Literal["free", "starter", "pro", "agency"]
WatchCadence = Literal["none", "weekly", "daily"]


@dataclass(frozen=True)
class PlanLimits:
    plan_id: PlanId
    max_targets: int | None
    scans_per_month: int | None
    watch_cadence: WatchCadence
    # Authenticated scanning (login-as-user crawl + active tests) — Pro/Agency only.
    authenticated_scanning: bool = False
    # Agency white-label PDF/HTML reports (custom brand name + logo).
    white_label_reports: bool = False


PLAN_LIMITS: dict[str, PlanLimits] = {
    "free": PlanLimits(
        plan_id="free",
        max_targets=1,
        scans_per_month=5,
        watch_cadence="none",
        authenticated_scanning=False,
        white_label_reports=False,
    ),
    "starter": PlanLimits(
        plan_id="starter",
        max_targets=3,
        scans_per_month=30,
        watch_cadence="weekly",
        authenticated_scanning=False,
        white_label_reports=False,
    ),
    "pro": PlanLimits(
        plan_id="pro",
        max_targets=15,
        scans_per_month=150,
        watch_cadence="daily",
        authenticated_scanning=True,
        white_label_reports=False,
    ),
    "agency": PlanLimits(
        plan_id="agency",
        max_targets=None,
        scans_per_month=None,
        watch_cadence="daily",
        authenticated_scanning=True,
        white_label_reports=True,
    ),
}


def get_plan_limits(plan_id: str) -> PlanLimits:
    return PLAN_LIMITS.get(plan_id, PLAN_LIMITS["free"])


def watch_cadence_for_plan(plan_id: str) -> WatchCadence:
    return get_plan_limits(plan_id).watch_cadence


def plan_supports_watch(plan_id: str) -> bool:
    return watch_cadence_for_plan(plan_id) != "none"


def plan_supports_authenticated_scanning(plan_id: str) -> bool:
    return bool(get_plan_limits(plan_id).authenticated_scanning)


def can_use_authenticated_scanning(org_id: str) -> bool:
    """Server-side gate: True only when the org's current plan includes the feature.

    Credentials may still be stored after a downgrade, but they must not be
    used until the org is on Pro/Agency again (graceful unauthenticated fallback).
    """
    # Imported lazily to avoid a circular import with accounts ↔ plans.
    from core.accounts import get_organization

    org = get_organization(org_id)
    if org is None:
        return False
    return plan_supports_authenticated_scanning(org.plan_id)


def plan_supports_white_label_reports(plan_id: str) -> bool:
    return bool(get_plan_limits(plan_id).white_label_reports)


def can_use_white_label_reports(org_id: str) -> bool:
    """Server-side gate: Agency-tier orgs may inject custom brand into reports."""
    from core.accounts import get_organization

    org = get_organization(org_id)
    if org is None:
        return False
    return plan_supports_white_label_reports(org.plan_id)


def cron_for_cadence(cadence: WatchCadence) -> str | None:
    """Return an APScheduler cron trigger expression, or None when disabled."""
    if cadence == "daily":
        return "0 6 * * *"  # 06:00 UTC daily
    if cadence == "weekly":
        return "0 6 * * 1"  # Monday 06:00 UTC
    return None
