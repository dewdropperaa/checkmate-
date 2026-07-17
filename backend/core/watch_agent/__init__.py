"""Watch Agent: scheduled background monitoring for previously scanned sites."""

from core.watch_agent.cve_job import run_cve_watch_all, run_cve_watch_for_site
from core.watch_agent.diff import FindingsDiff, diff_findings
from core.watch_agent.email_notify import (
    WatchAlertPayload,
    process_email_outbox,
    queue_watch_alert,
    render_watch_email_html,
)
from core.watch_agent.scan_job import run_watch_scan_for_site
from core.watch_agent.scheduler import (
    cancel_site_watch_job,
    on_plan_changed,
    on_site_added,
    on_site_removed,
    schedule_site_watch_job,
    shutdown_scheduler,
    start_scheduler,
    sync_all_watch_jobs,
    sync_org_watch_jobs,
)

__all__ = [
    "FindingsDiff",
    "WatchAlertPayload",
    "cancel_site_watch_job",
    "diff_findings",
    "on_plan_changed",
    "on_site_added",
    "on_site_removed",
    "process_email_outbox",
    "queue_watch_alert",
    "render_watch_email_html",
    "run_cve_watch_all",
    "run_cve_watch_for_site",
    "run_watch_scan_for_site",
    "schedule_site_watch_job",
    "shutdown_scheduler",
    "start_scheduler",
    "sync_all_watch_jobs",
    "sync_org_watch_jobs",
]
