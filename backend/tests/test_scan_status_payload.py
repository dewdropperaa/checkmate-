"""Scan status response must never 500 on empty findings / string errors."""

from __future__ import annotations

from app.main import ScanStatusResponse, _normalize_scan_status_payload


def test_normalize_coerces_none_findings_count_and_string_error() -> None:
    payload = {
        "scan_id": "scan-1",
        "target": "https://example.com/",
        "status": "running",
        "current_node": "recon",
        "next_nodes": ["recon"],
        "human_approval_needed": False,
        "human_approved": False,
        "approved_tools": [],
        "rejected_tools": [],
        "pending_interrupt": None,
        "findings_count": None,
        "is_complete": False,
        "created_at": "2026-07-29T22:26:11.133248+00:00",
        "updated_at": "2026-07-29T22:26:52.858724+00:00",
        "error": "tool failed",
    }
    model = ScanStatusResponse(**_normalize_scan_status_payload(payload))
    assert model.findings_count == 0
    assert model.error == {"code": "scan_error", "message": "tool failed"}


def test_normalize_preserves_dict_error_as_strings() -> None:
    payload = {
        "scan_id": "scan-1",
        "target": "https://example.com/",
        "status": "failed",
        "findings_count": 2,
        "is_complete": True,
        "created_at": "2026-07-29T22:26:11.133248+00:00",
        "updated_at": "2026-07-29T22:26:52.858724+00:00",
        "error": {"code": "timeout", "message": "scan timed out", "extra": 12},
    }
    model = ScanStatusResponse(**_normalize_scan_status_payload(payload))
    assert model.findings_count == 2
    assert model.error == {
        "code": "timeout",
        "message": "scan timed out",
        "extra": "12",
    }
