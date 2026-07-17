"""Append-only scan audit log for compliance and abuse investigation."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_AUDIT_FILE = Path(__file__).resolve().parent.parent / "data" / "scan_audit.jsonl"
_RETENTION_DAYS = 90


def _ensure_audit_dir() -> None:
    _AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)


def log_scan_triggered(
    *,
    scan_id: str,
    target: str,
    client_id: str,
    org_id: str | None = None,
    user_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Record a scan trigger event. Retained for at least 90 days (operator responsibility)."""
    entry: dict[str, Any] = {
        "event": "scan_triggered",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "target": target,
        "client_id": client_id,
    }
    if org_id:
        entry["org_id"] = org_id
    if user_id:
        entry["user_id"] = user_id
    if extra:
        entry.update(extra)

    _ensure_audit_dir()
    try:
        with _AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as exc:
        logger.warning("Failed to write scan audit log: %s", exc)

    logger.info(
        "scan_triggered audit",
        extra={
            "scan_id": scan_id,
            "target": target,
            "client_id": client_id,
            "org_id": org_id,
            "user_id": user_id,
        },
    )
