"""Resend email notifications for Watch Agent alerts."""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from core.accounts import (
    enqueue_email,
    get_organization,
    list_due_emails,
    list_org_member_emails,
    mark_email_retry,
    mark_email_sent,
)
from core.config import get_settings
from core.pdf_design import COLORS

logger = logging.getLogger(__name__)

RESEND_API_URL = "https://api.resend.com/emails"


def _rgb_hex(rgb: tuple[int, int, int]) -> str:
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


@dataclass
class WatchAlertPayload:
    site_target: str
    site_id: str
    org_id: str
    alert_kind: str  # findings | cve
    items: list[dict[str, Any]]
    scan_id: str | None = None
    locale: str = "en"


def build_dashboard_link(
    *,
    site_target: str,
    scan_id: str | None = None,
    locale: str = "en",
) -> str:
    settings = get_settings()
    base = settings.public_app_url.rstrip("/")
    if scan_id:
        return f"{base}/{locale}/dashboard?scan={quote(scan_id)}"
    return f"{base}/{locale}/dashboard?target={quote(site_target)}"


def build_manual_scan_link(*, site_target: str, locale: str = "en") -> str:
    settings = get_settings()
    base = settings.public_app_url.rstrip("/")
    return f"{base}/{locale}/dashboard?runScan={quote(site_target)}"


def render_watch_email_html(payload: WatchAlertPayload) -> tuple[str, str]:
    """Return (subject, html_body) matching Checkmate brand colors."""
    settings = get_settings()
    accent = _rgb_hex(COLORS.ACCENT)
    bg = _rgb_hex(COLORS.BG_DARK)
    panel = _rgb_hex(COLORS.PANEL)
    fg = _rgb_hex(COLORS.FG_PRIMARY)
    dim = _rgb_hex(COLORS.FG_DIM)
    border = _rgb_hex(COLORS.BORDER)
    critical = _rgb_hex(COLORS.CRITICAL)
    high = _rgb_hex(COLORS.HIGH)

    site = html.escape(payload.site_target)
    dash = build_dashboard_link(
        site_target=payload.site_target,
        scan_id=payload.scan_id,
        locale=payload.locale,
    )
    manual = build_manual_scan_link(
        site_target=payload.site_target,
        locale=payload.locale,
    )

    if payload.alert_kind == "cve":
        subject = f"Watch Agent: new CVE affecting {payload.site_target}"
        headline = "New CVE affecting a product on your site"
    else:
        subject = f"Watch Agent: new findings on {payload.site_target}"
        headline = "New or worsened findings since last check"

    rows: list[str] = []
    for item in payload.items:
        if payload.alert_kind == "cve":
            cve_id = html.escape(str(item.get("cve_id") or ""))
            product = html.escape(str(item.get("product") or ""))
            version = html.escape(str(item.get("version") or ""))
            summary = html.escape(str(item.get("summary") or "")[:280])
            sev = html.escape(str(item.get("severity") or "unknown"))
            rows.append(
                f"<tr><td style='padding:10px 0;border-bottom:1px solid {border};'>"
                f"<div style='color:{accent};font-weight:600;'>{cve_id}</div>"
                f"<div style='color:{fg};margin-top:4px;'>{product} {version}</div>"
                f"<div style='color:{dim};margin-top:4px;font-size:13px;'>{summary}</div>"
                f"<div style='color:{high};margin-top:4px;font-size:12px;text-transform:uppercase;'>"
                f"{sev}</div></td></tr>"
            )
        else:
            ftype = html.escape(str(item.get("type") or "finding"))
            sev = html.escape(str(item.get("severity") or "info"))
            desc = html.escape(str(item.get("description") or "")[:280])
            prev = item.get("previous_severity")
            badge = (
                f" (was {html.escape(str(prev))})"
                if prev
                else ""
            )
            finding_id = item.get("id") or ""
            verify_href = dash
            if payload.scan_id and finding_id:
                verify_href = (
                    f"{settings.public_app_url.rstrip('/')}/{payload.locale}"
                    f"/dashboard/scan/{quote(str(payload.scan_id))}"
                    f"?finding={quote(str(finding_id))}"
                )
            verify_link = (
                f"<div style='margin-top:8px;'>"
                f"<a href='{html.escape(verify_href)}' style='color:{accent};"
                f"font-size:12px;font-weight:600;text-decoration:none;'>"
                f"Verify Fix in dashboard →</a></div>"
            )
            rows.append(
                f"<tr><td style='padding:10px 0;border-bottom:1px solid {border};'>"
                f"<div style='color:{accent};font-weight:600;'>{ftype}</div>"
                f"<div style='color:{critical if sev == 'critical' else high};"
                f"font-size:12px;text-transform:uppercase;margin-top:4px;'>"
                f"{sev}{badge}</div>"
                f"<div style='color:{dim};margin-top:4px;font-size:13px;'>{desc}</div>"
                f"{verify_link}</td></tr>"
            )

    body = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:{bg};font-family:ui-sans-serif,system-ui,Segoe UI,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:{bg};padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="560" style="max-width:560px;background:{panel};border:1px solid {border};border-radius:12px;padding:28px;">
        <tr><td>
          <div style="color:{accent};font-size:22px;font-weight:700;letter-spacing:-0.02em;">checkmate</div>
          <div style="color:{fg};font-size:18px;font-weight:600;margin-top:20px;">{html.escape(headline)}</div>
          <div style="color:{dim};margin-top:8px;font-size:14px;">Site: <span style="color:{fg};">{site}</span></div>
          <table role="presentation" width="100%" style="margin-top:18px;">{''.join(rows)}</table>
          <div style="margin-top:24px;">
            <a href="{html.escape(dash)}" style="display:inline-block;background:{accent};color:#0a0d0b;text-decoration:none;font-weight:700;padding:10px 16px;border-radius:8px;">
              Open in dashboard
            </a>
          </div>
          <p style="color:{dim};font-size:12px;line-height:1.5;margin-top:22px;">
            This was an automated Watch Agent background check (headers, exposed files, and CMS fingerprint) — not a full recon + active scan.
            <a href="{html.escape(manual)}" style="color:{accent};">Run a full manual scan</a> for deeper verification.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""
    return subject, body


async def send_via_resend(
    *,
    to_email: str,
    subject: str,
    html_body: str,
) -> tuple[bool, str | None]:
    """Send one email through Resend. Returns (ok, error_message)."""
    settings = get_settings()
    api_key = settings.resend_api_key
    if not api_key:
        return False, "RESEND_API_KEY not configured"

    payload = {
        "from": settings.resend_from_email,
        "to": [to_email],
        "subject": subject,
        "html": html_body,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                RESEND_API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
        if response.status_code in {200, 201}:
            return True, None
        if response.status_code == 429:
            return False, f"resend_rate_limited:{response.text[:300]}"
        return False, f"resend_http_{response.status_code}:{response.text[:300]}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


async def queue_watch_alert(payload: WatchAlertPayload) -> list[str]:
    """Enqueue alert emails for org members when notifications are enabled."""
    org = get_organization(payload.org_id)
    if org is None or not org.watch_emails_enabled:
        logger.info(
            "Skipping watch email (disabled or missing org)",
            extra={"org_id": payload.org_id},
        )
        return []

    subject, html_body = render_watch_email_html(payload)
    emails = list_org_member_emails(payload.org_id)
    ids: list[str] = []
    for to_email in emails:
        ids.append(
            enqueue_email(
                org_id=payload.org_id,
                to_email=to_email,
                subject=subject,
                html_body=html_body,
            )
        )
    return ids


def _retry_delay_seconds(attempts: int) -> int:
    # 1m, 5m, 15m, 1h, 3h, 6h, 12h, 24h
    ladder = [60, 300, 900, 3600, 10800, 21600, 43200, 86400]
    idx = min(max(attempts, 0), len(ladder) - 1)
    return ladder[idx]


async def process_email_outbox(*, limit: int = 20) -> dict[str, int]:
    """Drain due outbox rows — never raises; failed sends are retried."""
    due = list_due_emails(limit=limit)
    sent = 0
    retried = 0
    for row in due:
        ok, err = await send_via_resend(
            to_email=row["to_email"],
            subject=row["subject"],
            html_body=row["html_body"],
        )
        if ok:
            mark_email_sent(row["id"])
            sent += 1
        else:
            delay = _retry_delay_seconds(int(row.get("attempts") or 0))
            mark_email_retry(row["id"], error=err or "unknown", delay_seconds=delay)
            retried += 1
            logger.warning(
                "Watch email send failed; queued for retry",
                extra={
                    "email_id": row["id"],
                    "error": err,
                    "retry_in_seconds": delay,
                },
            )
    return {"sent": sent, "retried": retried, "checked_at": datetime.now(timezone.utc).isoformat()}
