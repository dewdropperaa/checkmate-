"""Daily CVE-watch job using the free NVD API."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from core.accounts import (
    get_site,
    has_cve_alert,
    list_watchable_sites,
    record_cve_alert,
    touch_site_cve_check,
)
from core.watch_agent.email_notify import WatchAlertPayload, queue_watch_alert
from core.watch_agent.nvd_client import NvdClient

logger = logging.getLogger(__name__)


def _parse_fingerprint(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict) and item.get("name")]


def _since_for_site(last_cve_check_at: str | None) -> datetime | None:
    if not last_cve_check_at:
        # First run: look back 7 days to avoid a huge historical dump.
        return datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=7)
    try:
        return datetime.fromisoformat(last_cve_check_at)
    except ValueError:
        return None


async def run_cve_watch_for_site(
    site_id: str,
    *,
    client: NvdClient | None = None,
) -> dict[str, Any]:
    site = get_site(site_id)
    if site is None or not site.active:
        return {"skipped": True, "reason": "site_inactive_or_missing"}

    products = _parse_fingerprint(site.fingerprint_json)
    if not products:
        touch_site_cve_check(site.id)
        return {"site_id": site.id, "skipped": True, "reason": "no_fingerprint"}

    nvd = client or NvdClient()
    since = _since_for_site(site.last_cve_check_at)
    new_alerts: list[dict[str, Any]] = []

    for product in products:
        name = str(product.get("name") or "").strip()
        version = str(product.get("version") or "").strip()
        if not name or not version or version.lower() == "unknown":
            continue
        try:
            matches = await nvd.find_matching_cves(
                product_name=name,
                version=version,
                since=since,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "NVD lookup failed for %s@%s on site %s: %s",
                name,
                version,
                site.id,
                exc,
            )
            continue

        for match in matches:
            if has_cve_alert(site.id, match.cve_id):
                continue
            inserted = record_cve_alert(
                site_id=site.id,
                cve_id=match.cve_id,
                product=match.product,
                version=match.version,
                summary=match.summary,
            )
            if not inserted:
                continue
            new_alerts.append(
                {
                    "cve_id": match.cve_id,
                    "product": match.product,
                    "version": match.version,
                    "summary": match.summary,
                    "severity": match.severity,
                }
            )

    touch_site_cve_check(site.id)

    email_ids: list[str] = []
    if new_alerts:
        email_ids = await queue_watch_alert(
            WatchAlertPayload(
                site_target=site.target,
                site_id=site.id,
                org_id=site.org_id,
                alert_kind="cve",
                items=new_alerts,
            )
        )

    return {
        "site_id": site.id,
        "products_checked": len(products),
        "new_alerts": new_alerts,
        "email_ids": email_ids,
    }


async def run_cve_watch_all(*, client: NvdClient | None = None) -> dict[str, Any]:
    """Iterate watchable sites sequentially so NVD rate limits are respected."""
    nvd = client or NvdClient()
    sites = list_watchable_sites()
    results: list[dict[str, Any]] = []
    for site in sites:
        results.append(await run_cve_watch_for_site(site.id, client=nvd))
    return {"sites": len(sites), "results": results}
