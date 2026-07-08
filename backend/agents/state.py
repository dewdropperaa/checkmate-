"""Shared LangGraph state definitions."""

from typing import Any, TypedDict


class ScanState(TypedDict):
    scan_id: str
    target: str
    scope: dict[str, Any]
    authorized: bool
    recon_results: dict[str, Any]
    planned_active_tests: list[str]
    findings: list[dict[str, Any]]
    severity_scores: dict[str, Any]
    report: dict[str, Any] | None
    status: str
    human_approval_needed: bool
    human_approved: bool
