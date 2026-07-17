"""Diff-based Watch Agent re-scan job (passive subset, no quota)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from core.accounts import (
    create_scan_record,
    get_latest_findings_snapshot,
    get_site,
    save_findings_snapshot,
    save_watch_diff,
    touch_site_watch,
    update_scan_record,
    update_site_fingerprint,
)
from core.watch_agent.diff import diff_findings
from core.watch_agent.email_notify import WatchAlertPayload, queue_watch_alert
from tools.cms_fingerprint import CmsFingerprint
from tools.exposed_files import ExposedFilesChecker
from tools.header_checks import HeaderChecker
from tools.schemas import Finding, deduplicate_findings

logger = logging.getLogger(__name__)


def _as_findings(raw: list[Any]) -> list[dict[str, Any]]:
    parsed: list[Finding] = []
    for item in raw:
        try:
            if isinstance(item, Finding):
                parsed.append(item)
            elif isinstance(item, dict):
                parsed.append(Finding.model_validate(item))
        except Exception:  # noqa: BLE001
            continue
    return [f.model_dump_for_state() for f in deduplicate_findings(parsed)]


async def run_watch_modules(target: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Run header-checks + exposed-files + cms-fingerprint only."""
    header = HeaderChecker()
    exposed = ExposedFilesChecker()
    cms = CmsFingerprint()

    findings: list[dict[str, Any]] = []
    products: list[dict[str, str]] = []

    header_result = await header.run(target, {})
    if header_result.success:
        findings.extend(header_result.data.get("findings") or [])

    exposed_result = await exposed.run(target, {})
    if exposed_result.success:
        findings.extend(exposed_result.data.get("findings") or [])

    cms_result = await cms.run(target, {})
    if cms_result.success:
        findings.extend(cms_result.data.get("findings") or [])
        products = list(cms_result.data.get("products") or [])

    return _as_findings(findings), products


async def run_watch_scan_for_site(site_id: str) -> dict[str, Any]:
    """Execute one scheduled watch job for a site.

    Does not consume manual scan quota and never enters the human-approval gate.
    """
    site = get_site(site_id)
    if site is None or not site.active:
        return {"skipped": True, "reason": "site_inactive_or_missing"}

    scan_id = str(uuid.uuid4())
    create_scan_record(
        scan_id=scan_id,
        org_id=site.org_id,
        target=site.target,
        kind="watch",
    )
    update_scan_record(scan_id, status="running", current_node="watch_scan")

    try:
        current, products = await run_watch_modules(site.target)
        previous = get_latest_findings_snapshot(site.id)
        diff = diff_findings(previous, current)

        save_findings_snapshot(
            site_id=site.id,
            org_id=site.org_id,
            findings=current,
            source="watch",
            scan_id=scan_id,
        )
        if products:
            update_site_fingerprint(site.id, products)

        save_watch_diff(
            site_id=site.id,
            org_id=site.org_id,
            newly_appeared=diff.newly_appeared,
            severity_increased=diff.severity_increased,
            fixed=diff.fixed,
            should_alert=diff.should_alert,
            scan_id=scan_id,
        )
        touch_site_watch(site.id)
        update_scan_record(
            scan_id,
            status="completed",
            current_node="watch_scan",
            overall_risk_score=None,
            severity=None,
        )

        email_ids: list[str] = []
        if diff.should_alert:
            alert_items = list(diff.newly_appeared) + list(diff.severity_increased)
            email_ids = await queue_watch_alert(
                WatchAlertPayload(
                    site_target=site.target,
                    site_id=site.id,
                    org_id=site.org_id,
                    alert_kind="findings",
                    items=alert_items,
                    scan_id=scan_id,
                )
            )

        return {
            "site_id": site.id,
            "scan_id": scan_id,
            "findings_count": len(current),
            "should_alert": diff.should_alert,
            "diff": diff.to_dict(),
            "email_ids": email_ids,
            "products": products,
        }
    except Exception as exc:
        logger.exception("Watch scan failed for site %s", site_id)
        update_scan_record(
            scan_id,
            status="failed",
            current_node="watch_scan",
        )
        return {"site_id": site_id, "scan_id": scan_id, "error": str(exc)}
