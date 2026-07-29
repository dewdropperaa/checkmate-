"""Coverage & limitations section — fixed disclaimer must not drift."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")

from agents.reporting import (
    _build_html_report,
    _build_markdown_report,
    build_coverage_section,
    run_reporting,
)
from agents.state import ScanState
from core.scan_disclaimer import SCAN_COVERAGE_DISCLAIMER

# Snapshot: if this assertion fails, the disclaimer was edited. That requires an
# explicit product/legal review — do not "fix" tests by quietly changing copy.
_DISCLAIMER_SNAPSHOT = (
    "This is an automated vulnerability scan, not a manual penetration test. "
    "It does not test complex business logic, does not attempt social engineering, "
    "and authenticated-scan coverage is limited to the account and paths you "
    "configured. For a comprehensive security assessment, consider a manual "
    "penetration test from a qualified provider in addition to this ongoing "
    "security monitoring."
)


def test_disclaimer_snapshot_unchanged() -> None:
    assert SCAN_COVERAGE_DISCLAIMER == _DISCLAIMER_SNAPSHOT


def _report_state() -> ScanState:
    return {
        "scan_id": "scan-coverage-disclaimer",
        "target": "https://authorized.example.com",
        "scope": {},
        "authorized": True,
        "recon_results": {
            "tool_results": {
                "subfinder": {"success": True},
                "httpx": {"success": True},
            },
            "errors": {"katana": "timeout"},
        },
        "planned_active_tests": ["zap", "sqlmap"],
        "findings": [
            {
                "id": "f1",
                "tool": "header-checks",
                "type": "missing-csp",
                "url": "https://authorized.example.com/",
                "severity": "medium",
                "description": "Missing CSP",
                "remediation": "Add a Content-Security-Policy header.",
            }
        ],
        "severity_scores": {
            "overall_risk_score": 4.0,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "scan_coverage": {
                "recon_modules_run": ["subfinder", "httpx"],
                "detection_modules_run": ["header-checks", "nuclei"],
                "modules_failed": ["katana", "testssl"],
                "modules_skipped": ["sqlmap"],
                "modules_not_applicable": ["retirejs"],
                "modules_rejected": ["zap"],
                "coverage_notes": ["ZAP daemon unavailable"],
                "score_basis": "passive+partial-active",
            },
        },
        "report": None,
        "status": "completed",
        "human_approval_needed": False,
        "human_approved": True,
        "detection_metadata": {
            "rejected_tools": ["zap"],
            "active_tools_executed": [],
        },
    }


def test_build_coverage_section_lists_module_status() -> None:
    cov = build_coverage_section(
        {"severity_scores": _report_state()["severity_scores"]}
    )
    assert cov["disclaimer"] == _DISCLAIMER_SNAPSHOT
    assert "header-checks" in cov["modules_run"]
    assert "katana" in cov["modules_failed"]
    assert "sqlmap" in cov["modules_skipped"]
    assert "retirejs" in cov["modules_not_applicable"]
    assert "zap" in cov["modules_rejected"]
    assert cov["title"] == "What this scan covered"


def test_disclaimer_present_unmodified_across_report_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
    result = run_reporting(_report_state())
    report = result["report"]
    assert report["coverage"]["disclaimer"] == _DISCLAIMER_SNAPSHOT

    md = _build_markdown_report({**report, "_branding": report.get("_branding")})
    # Re-build with branding resolved inside builders
    from agents.reporting import resolve_report_branding

    branded = {**report, "_branding": resolve_report_branding(None)}
    md = _build_markdown_report(branded)
    html = _build_html_report(branded)

    assert _DISCLAIMER_SNAPSHOT in md
    assert "What this scan covered" in md
    assert "katana" in md
    assert "testssl" in md
    assert "sqlmap" in md

    assert _DISCLAIMER_SNAPSHOT in html
    assert "What this scan covered" in html
    assert "scan-coverage" in html

    json_path = tmp_path / "scan-coverage-disclaimer" / "report.json"
    md_path = tmp_path / "scan-coverage-disclaimer" / "report.md"
    html_path = tmp_path / "scan-coverage-disclaimer" / "report.html"
    pdf_path = tmp_path / "scan-coverage-disclaimer" / "report.pdf"
    assert json_path.is_file()
    assert md_path.is_file()
    assert html_path.is_file()
    assert pdf_path.is_file()

    json_text = json_path.read_text(encoding="utf-8")
    assert _DISCLAIMER_SNAPSHOT in json_text
    assert _DISCLAIMER_SNAPSHOT in md_path.read_text(encoding="utf-8")
    assert _DISCLAIMER_SNAPSHOT in html_path.read_text(encoding="utf-8")
    # PDF is binary; ensure the artifact exists and disclaimer is in the
    # structured coverage object that fed the writer.
    assert report["coverage"]["disclaimer"] == SCAN_COVERAGE_DISCLAIMER
