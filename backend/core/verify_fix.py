"""Per-finding Verify Fix: narrow live re-check that does not consume scan quota.

Reuses ActiveVerifier checkers for a single finding, maps the live verdict to
fixed / still_present / changed, and persists a verification history so users
can see repeated failures over time.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from agents.verification import ActiveVerifier
from core.accounts import (
    get_latest_finding_fix_verification,
    list_finding_fix_verifications,
    list_scan_fix_verification_summaries,
    save_finding_fix_verification,
)
from core.config import get_settings

logger = logging.getLogger(__name__)

FIX_FIXED = "fixed"
FIX_STILL_PRESENT = "still_present"
FIX_CHANGED = "changed"
FIX_RESULTS = frozenset({FIX_FIXED, FIX_STILL_PRESENT, FIX_CHANGED})


class VerifyFixError(Exception):
    """Base error for verify-fix operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class VerifyFixRateLimited(VerifyFixError):
    def __init__(self, *, retry_after_seconds: int) -> None:
        super().__init__(
            "verify_fix_rate_limited",
            (
                "Verify Fix was run recently for this finding. "
                f"Try again in about {retry_after_seconds} seconds."
            ),
        )
        self.retry_after_seconds = retry_after_seconds


class FindingNotFound(VerifyFixError):
    def __init__(self, finding_id: str) -> None:
        super().__init__(
            "finding_not_found",
            f"Finding {finding_id!r} was not found on this scan.",
        )
        self.finding_id = finding_id


def map_verifier_to_fix_result(
    *,
    original: dict[str, Any],
    verified: dict[str, Any],
) -> tuple[str, str | None]:
    """Map ActiveVerifier outcome to fixed / still_present / changed.

    Returns (result, evidence_or_note).
    """
    verification = verified.get("verification") or {}
    status = str(verification.get("status") or "")
    evidence = verification.get("evidence") or verification.get("reason")
    evidence_str = str(evidence) if evidence else None

    if status == "refuted":
        return FIX_FIXED, evidence_str

    if status == "confirmed":
        return FIX_STILL_PRESENT, evidence_str

    # unreachable / tool_attested / unknown — cannot force a binary.
    note_parts: list[str] = []
    if status:
        note_parts.append(f"Live check status: {status}")
    if evidence_str:
        note_parts.append(evidence_str)
    orig_ev = (original.get("verification") or {}).get("evidence") or original.get(
        "evidence"
    )
    if orig_ev and evidence_str and str(orig_ev).strip() != evidence_str.strip():
        note_parts.append(f"Original evidence: {orig_ev}")
    return FIX_CHANGED, " | ".join(note_parts) if note_parts else None


def finding_identity(finding: dict[str, Any], index: int = 0) -> str:
    """Stable finding id used by API and history (matches scoring assignment)."""
    existing = finding.get("id")
    if existing:
        return str(existing)
    tool = finding.get("tool") or "finding"
    return f"{tool}-{index}"


def resolve_finding(
    findings: list[dict[str, Any]], finding_id: str
) -> dict[str, Any] | None:
    """Locate a finding by id, falling back to tool-index style ids."""
    wanted = str(finding_id)
    for idx, finding in enumerate(findings):
        if finding_identity(finding, idx) == wanted:
            return dict(finding)
    return None


def _assert_rate_limit(scan_id: str, finding_id: str) -> None:
    settings = get_settings()
    cooldown = int(settings.verify_fix_cooldown_seconds)
    latest = get_latest_finding_fix_verification(scan_id, finding_id)
    if latest is None:
        return
    checked_raw = str(latest.get("checked_at") or "")
    try:
        checked = datetime.fromisoformat(checked_raw.replace("Z", "+00:00"))
    except ValueError:
        return
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    elapsed = datetime.now(timezone.utc) - checked
    remaining = timedelta(seconds=cooldown) - elapsed
    if remaining.total_seconds() > 0:
        raise VerifyFixRateLimited(
            retry_after_seconds=max(1, int(remaining.total_seconds()))
        )


async def run_verify_fix(
    *,
    scan_id: str,
    org_id: str,
    finding_id: str,
    findings: list[dict[str, Any]],
    client: Any | None = None,
) -> dict[str, Any]:
    """Re-check one finding against the live target. Does not consume scan quota."""
    finding = resolve_finding(findings, finding_id)
    if finding is None:
        raise FindingNotFound(finding_id)

    _assert_rate_limit(scan_id, finding_id)

    verifier = ActiveVerifier(client=client)
    try:
        verified_list = await verifier.verify([finding])
    finally:
        await verifier.close()

    verified = verified_list[0]
    result, evidence = map_verifier_to_fix_result(
        original=finding, verified=verified
    )
    verification_status = (verified.get("verification") or {}).get("status")

    save_finding_fix_verification(
        record_id=str(uuid.uuid4()),
        scan_id=scan_id,
        org_id=org_id,
        finding_id=finding_id,
        finding_url=str(finding.get("url") or ""),
        finding_type=str(finding.get("type") or ""),
        result=result,
        evidence=evidence,
        verification_status=str(verification_status) if verification_status else None,
    )
    history = list_finding_fix_verifications(scan_id, finding_id)
    checked_at = str(history[0]["checked_at"]) if history else ""

    logger.info(
        "Verify Fix completed",
        extra={
            "scan_id": scan_id,
            "finding_id": finding_id,
            "result": result,
            "quota_consumed": False,
        },
    )

    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "result": result,
        "evidence": evidence,
        "verification": verified.get("verification"),
        "confidence": verified.get("confidence"),
        "checked_at": checked_at,
        "quota_consumed": False,
        "history": history,
        "attempt_count": len(history),
        "finding": {
            "id": finding_id,
            "tool": finding.get("tool"),
            "type": finding.get("type"),
            "url": finding.get("url"),
            "severity": finding.get("severity"),
            "description": finding.get("description"),
        },
    }


def get_scan_verify_summaries(scan_id: str) -> dict[str, dict[str, Any]]:
    return list_scan_fix_verification_summaries(scan_id)
