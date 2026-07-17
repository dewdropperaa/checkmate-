"""Shared LangGraph state definitions."""

from typing import Any, TypedDict


class ScanState(TypedDict, total=False):
    scan_id: str
    target: str
    scope: dict[str, Any]
    authorized: bool
    recon_results: dict[str, Any]
    planned_active_tests: list[str]
    findings: list[dict[str, Any]]
    severity_scores: dict[str, Any]
    # Optional AI Security Copilot output (executive summary, roadmap, config fixes).
    # Absent / skipped when no LLM key is configured or the stage fails soft.
    ai_synthesis: dict[str, Any]
    report: dict[str, Any] | None
    status: str
    human_approval_needed: bool
    human_approved: bool
    # Per-tool approval outcome from the human_approval_gate node. `approved_tools`
    # is the subset of `planned_active_tests` the reviewer allowed to run (e.g. the
    # reviewer may approve sqlmap while rejecting zap); `rejected_tools` is the
    # complement. `human_approved` remains True iff `approved_tools` is non-empty,
    # preserving the legacy all-or-nothing semantics for older callers.
    approved_tools: list[str]
    rejected_tools: list[str]
    error: dict[str, str]
    detection_metadata: dict[str, Any]
