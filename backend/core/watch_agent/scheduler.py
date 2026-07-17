"""APScheduler setup with persistent SQLAlchemy job store for Watch Agent."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from core.accounts import (
    get_accounts_db_path,
    get_organization,
    get_site,
    list_org_sites,
    list_watchable_sites,
)
from core.plans import cron_for_cadence, plan_supports_watch, watch_cadence_for_plan

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def _scheduler_db_url() -> str:
    # Dedicated SQLite file beside accounts.db so APScheduler tables stay isolated.
    accounts = get_accounts_db_path()
    path = accounts.parent / "watch_scheduler.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    # SQLAlchemy needs forward slashes even on Windows.
    return f"sqlite:///{path.as_posix()}"


def get_scheduler() -> AsyncIOScheduler | None:
    return _scheduler


def configure_scheduler_db(path: Path | str) -> None:
    """Test helper: point the job store at a temp SQLite file before start."""
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        raise RuntimeError("Cannot reconfigure a running scheduler")
    url = f"sqlite:///{Path(path).as_posix()}"
    jobstores = {"default": SQLAlchemyJobStore(url=url)}
    _scheduler = AsyncIOScheduler(jobstores=jobstores, timezone="UTC")


def _ensure_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        jobstores = {"default": SQLAlchemyJobStore(url=_scheduler_db_url())}
        _scheduler = AsyncIOScheduler(jobstores=jobstores, timezone="UTC")
    return _scheduler


def watch_scan_job_id(site_id: str) -> str:
    return f"watch-scan:{site_id}"


async def _job_run_watch_scan(site_id: str) -> None:
    from core.watch_agent.scan_job import run_watch_scan_for_site

    await run_watch_scan_for_site(site_id)


async def _job_run_cve_watch() -> None:
    from core.watch_agent.cve_job import run_cve_watch_all

    await run_cve_watch_all()


async def _job_process_email_outbox() -> None:
    from core.watch_agent.email_notify import process_email_outbox

    await process_email_outbox()


def schedule_site_watch_job(site_id: str, *, plan_id: str | None = None) -> bool:
    """Create/update the recurring watch-scan job for a site.

    Returns True when a job is scheduled, False when canceled/skipped (free plan).
    """
    scheduler = _ensure_scheduler()
    site = get_site(site_id)
    if site is None or not site.active:
        cancel_site_watch_job(site_id)
        return False

    org = get_organization(site.org_id)
    resolved_plan = plan_id or (org.plan_id if org else "free")
    if not plan_supports_watch(resolved_plan):
        cancel_site_watch_job(site_id)
        return False

    cadence = watch_cadence_for_plan(resolved_plan)
    cron_expr = cron_for_cadence(cadence)
    if not cron_expr:
        cancel_site_watch_job(site_id)
        return False

    trigger = CronTrigger.from_crontab(cron_expr, timezone="UTC")
    job_id = watch_scan_job_id(site_id)
    scheduler.add_job(
        _job_run_watch_scan,
        trigger=trigger,
        id=job_id,
        kwargs={"site_id": site_id},
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=3600,
    )
    logger.info(
        "Scheduled watch-scan job",
        extra={"site_id": site_id, "cadence": cadence, "cron": cron_expr},
    )
    return True


def cancel_site_watch_job(site_id: str) -> bool:
    scheduler = _ensure_scheduler()
    job_id = watch_scan_job_id(site_id)
    job = scheduler.get_job(job_id)
    if job is None:
        return False
    scheduler.remove_job(job_id)
    logger.info("Canceled watch-scan job", extra={"site_id": site_id})
    return True


def sync_org_watch_jobs(org_id: str) -> dict[str, Any]:
    """Reschedule or cancel all site jobs for an org after plan changes."""
    org = get_organization(org_id)
    if org is None:
        return {"scheduled": 0, "canceled": 0}
    scheduled = 0
    canceled = 0
    for site in list_org_sites(org_id, active_only=False):
        if site.active and plan_supports_watch(org.plan_id):
            if schedule_site_watch_job(site.id, plan_id=org.plan_id):
                scheduled += 1
            else:
                canceled += 1
        else:
            if cancel_site_watch_job(site.id):
                canceled += 1
    return {"org_id": org_id, "scheduled": scheduled, "canceled": canceled}


def sync_all_watch_jobs() -> dict[str, Any]:
    """Reconcile persistent jobs with current sites/plans (startup)."""
    scheduler = _ensure_scheduler()
    # Ensure global jobs exist.
    scheduler.add_job(
        _job_run_cve_watch,
        trigger=CronTrigger.from_crontab("30 5 * * *", timezone="UTC"),
        id="watch-cve:daily",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=7200,
    )
    scheduler.add_job(
        _job_process_email_outbox,
        trigger=CronTrigger.from_crontab("*/10 * * * *", timezone="UTC"),
        id="watch-email:outbox",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        misfire_grace_time=600,
    )

    desired = {site.id for site in list_watchable_sites()}
    scheduled = 0
    for site_id in desired:
        if schedule_site_watch_job(site_id):
            scheduled += 1

    # Drop orphaned watch-scan jobs (site removed / plan downgraded).
    canceled = 0
    for job in list(scheduler.get_jobs()):
        if not str(job.id).startswith("watch-scan:"):
            continue
        site_id = str(job.id).split(":", 1)[1]
        if site_id not in desired:
            scheduler.remove_job(job.id)
            canceled += 1

    return {"scheduled": scheduled, "canceled": canceled}


def start_scheduler() -> AsyncIOScheduler:
    scheduler = _ensure_scheduler()
    if not scheduler.running:
        sync_all_watch_jobs()
        scheduler.start()
        logger.info("Watch Agent scheduler started")
    return scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Watch Agent scheduler stopped")
    _scheduler = None


def on_site_added(site_id: str) -> None:
    schedule_site_watch_job(site_id)


def on_site_removed(site_id: str) -> None:
    cancel_site_watch_job(site_id)


def on_plan_changed(org_id: str) -> dict[str, Any]:
    return sync_org_watch_jobs(org_id)
