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


PLAN_LIMITS: dict[str, PlanLimits] = {
    "free": PlanLimits(
        plan_id="free",
        max_targets=1,
        scans_per_month=5,
        watch_cadence="none",
    ),
    "starter": PlanLimits(
        plan_id="starter",
        max_targets=3,
        scans_per_month=30,
        watch_cadence="weekly",
    ),
    "pro": PlanLimits(
        plan_id="pro",
        max_targets=15,
        scans_per_month=150,
        watch_cadence="daily",
    ),
    "agency": PlanLimits(
        plan_id="agency",
        max_targets=None,
        scans_per_month=None,
        watch_cadence="daily",
    ),
}


def get_plan_limits(plan_id: str) -> PlanLimits:
    return PLAN_LIMITS.get(plan_id, PLAN_LIMITS["free"])


def watch_cadence_for_plan(plan_id: str) -> WatchCadence:
    return get_plan_limits(plan_id).watch_cadence


def plan_supports_watch(plan_id: str) -> bool:
    return watch_cadence_for_plan(plan_id) != "none"


def cron_for_cadence(cadence: WatchCadence) -> str | None:
    """Return an APScheduler cron trigger expression, or None when disabled."""
    if cadence == "daily":
        return "0 6 * * *"  # 06:00 UTC daily
    if cadence == "weekly":
        return "0 6 * * 1"  # Monday 06:00 UTC
    return None
