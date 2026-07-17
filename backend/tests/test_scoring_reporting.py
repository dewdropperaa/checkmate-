"""Tests for scoring, reporting artifacts, and report delivery."""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agents.reporting import (
    run_reporting,
    _deduplicate_findings,
    _group_findings_by_severity_deduplicated,
)
from agents.scoring import run_scoring
from agents.state import ScanState
from core.config import get_settings
from core.pdf_design import (
    COLORS,
    TYPOGRAPHY,
    SPACING,
    severity_color,
    severity_light_color,
    risk_score_color,
)


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: fake_results)


def _base_state() -> ScanState:
    return {
        "scan_id": "scan-scoring-reporting",
        "target": "https://authorized.example.com",
        "scope": {},
        "authorized": True,
        "recon_results": {},
        "planned_active_tests": [],
        "findings": [],
        "severity_scores": {},
        "report": None,
        "status": "running",
        "human_approval_needed": False,
        "human_approved": False,
    }


def test_run_scoring_normalizes_scores_and_sorts_findings() -> None:
    state = _base_state()
    state["findings"] = [
        {
            "id": "f-low",
            "tool": "header-checks",
            "type": "missing-x-content-type-options",
            "url": "https://authorized.example.com/a",
            "severity": "low",
            "description": "missing xcto",
        },
        {
            "id": "f-critical",
            "tool": "nuclei",
            "type": "xss",
            "url": "https://authorized.example.com/search?q=test",
            "score": 9.8,
            "description": "reflected xss",
        },
        {
            "id": "f-medium",
            "tool": "header-checks",
            "type": "missing-csp",
            "url": "https://authorized.example.com/",
            "severity": "medium",
            "description": "missing csp",
        },
    ]

    result = run_scoring(state)
    scored = result["findings"]

    assert scored[0]["id"] == "f-critical"
    assert scored[0]["severity"] == "critical"
    assert scored[0]["cvss_score"] == 9.8
    assert result["severity_scores"]["overall_risk_score"] > 0
    assert result["severity_scores"]["total_findings"] == 3


def test_run_reporting_writes_json_markdown_html_and_pdf(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-artifacts"
    state["status"] = "scored"
    state["severity_scores"] = {
        "overall_risk_score": 6.7,
        "severity_counts": {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0},
        "total_findings": 2,
        "per_finding": {},
    }
    state["findings"] = [
        {
            "tool": "nuclei",
            "type": "xss",
            "url": "https://authorized.example.com/search?q=foo",
            "severity": "high",
            "description": "XSS finding",
            "cvss_score": 8.1,
        },
        {
            "tool": "header-checks",
            "type": "missing-csp",
            "url": "https://authorized.example.com/",
            "severity": "medium",
            "description": "CSP missing",
            "cvss_score": 5.5,
        },
    ]

    result = run_reporting(state)
    artifacts = result["report"]["artifacts"]

    assert Path(artifacts["json"]).exists()
    assert Path(artifacts["md"]).exists()
    assert Path(artifacts["html"]).exists()
    assert Path(artifacts["pdf"]).exists()
    assert Path(artifacts["pdf"]).read_bytes().startswith(b"%PDF")
    html_content = Path(artifacts["html"]).read_text(encoding="utf-8")
    assert "data:image/png;base64," in html_content
    assert "findings_by_severity" in result["report"]


def test_report_format_endpoint_serves_json_md_html(client: TestClient, fast_scan: None) -> None:
    target = "https://authorized.example.com/"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    deadline = time.monotonic() + 5.0
    pending = False
    while time.monotonic() < deadline:
        status_resp = client.get(f"/scan/{scan_id}/status", params={"target": target})
        assert status_resp.status_code == 200
        if status_resp.json().get("pending_interrupt"):
            pending = True
            break
        time.sleep(0.05)
    assert pending is True

    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"target": target, "approved": True},
    )
    assert approve.status_code == 200

    # Approval resumes the scan in the background; wait for the report artifacts.
    deadline = time.monotonic() + 5.0
    completed = False
    while time.monotonic() < deadline:
        status_resp = client.get(f"/scan/{scan_id}/status", params={"target": target})
        assert status_resp.status_code == 200
        if status_resp.json().get("is_complete"):
            completed = True
            break
        time.sleep(0.05)
    assert completed is True

    json_report = client.get(f"/scan/{scan_id}/report/json", params={"target": target})
    assert json_report.status_code == 200
    assert "scan_id" in json_report.json()

    md_report = client.get(f"/scan/{scan_id}/report/md", params={"target": target})
    assert md_report.status_code == 200
    assert "# Checkmate Report" in md_report.text

    html_report = client.get(f"/scan/{scan_id}/report/html", params={"target": target})
    assert html_report.status_code == 200
    assert "<!DOCTYPE html>" in html_report.text
    assert "Checkmate Report" in html_report.text

    pdf_report = client.get(f"/scan/{scan_id}/report/pdf", params={"target": target})
    assert pdf_report.status_code == 200
    assert pdf_report.headers["content-type"] == "application/pdf"
    assert pdf_report.content.startswith(b"%PDF")


def test_scan_rate_limiting_on_scan_endpoint(client: TestClient, public_dns: None) -> None:
    settings = get_settings()
    old_window = settings.scan_rate_limit_window_seconds
    old_requests = settings.scan_rate_limit_max_requests
    old_per_client = settings.scan_rate_limit_max_concurrent_per_client
    old_global = settings.scan_rate_limit_max_concurrent_global

    settings.scan_rate_limit_window_seconds = 60
    settings.scan_rate_limit_max_requests = 1
    settings.scan_rate_limit_max_concurrent_per_client = 10
    settings.scan_rate_limit_max_concurrent_global = 50

    try:
        headers = {"X-API-Key": "rate-limit-test-key"}
        first = client.post(
            "/scan",
            json={"target": "https://authorized.example.com/", "confirmed_authorized": True},
            headers=headers,
        )
        assert first.status_code == 202

        second = client.post(
            "/scan",
            json={"target": "https://example.com/", "confirmed_authorized": True},
            headers=headers,
        )
        assert second.status_code == 429
        assert second.json()["detail"]["error"] == "scan_rate_limit_exceeded"
    finally:
        settings.scan_rate_limit_window_seconds = old_window
        settings.scan_rate_limit_max_requests = old_requests
        settings.scan_rate_limit_max_concurrent_per_client = old_per_client
        settings.scan_rate_limit_max_concurrent_global = old_global


def test_per_client_concurrency_limit_returns_429(
    client: TestClient,
    public_dns: None,
) -> None:
    settings = get_settings()
    old_window = settings.scan_rate_limit_window_seconds
    old_requests = settings.scan_rate_limit_max_requests
    old_per_client = settings.scan_rate_limit_max_concurrent_per_client
    old_global = settings.scan_rate_limit_max_concurrent_global
    settings.scan_rate_limit_window_seconds = 60
    settings.scan_rate_limit_max_requests = 10
    settings.scan_rate_limit_max_concurrent_per_client = 1
    settings.scan_rate_limit_max_concurrent_global = 50
    headers = {"X-API-Key": "client-concurrency-key"}
    try:
        first = client.post(
            "/scan",
            json={"target": "https://authorized.example.com/", "confirmed_authorized": True},
            headers=headers,
        )
        assert first.status_code == 202
        second = client.post(
            "/scan",
            json={"target": "https://example.com/", "confirmed_authorized": True},
            headers=headers,
        )
        assert second.status_code == 429
        assert second.json()["detail"]["error"] == "scan_concurrency_exceeded"
    finally:
        settings.scan_rate_limit_window_seconds = old_window
        settings.scan_rate_limit_max_requests = old_requests
        settings.scan_rate_limit_max_concurrent_per_client = old_per_client
        settings.scan_rate_limit_max_concurrent_global = old_global


def test_global_concurrency_limit_returns_429(
    client: TestClient,
    public_dns: None,
) -> None:
    settings = get_settings()
    old_window = settings.scan_rate_limit_window_seconds
    old_requests = settings.scan_rate_limit_max_requests
    old_per_client = settings.scan_rate_limit_max_concurrent_per_client
    old_global = settings.scan_rate_limit_max_concurrent_global
    settings.scan_rate_limit_window_seconds = 60
    settings.scan_rate_limit_max_requests = 10
    settings.scan_rate_limit_max_concurrent_per_client = 10
    settings.scan_rate_limit_max_concurrent_global = 1
    try:
        first = client.post(
            "/scan",
            json={"target": "https://authorized.example.com/", "confirmed_authorized": True},
            headers={"X-API-Key": "global-limit-a"},
        )
        assert first.status_code == 202
        second = client.post(
            "/scan",
            json={"target": "https://example.com/", "confirmed_authorized": True},
            headers={"X-API-Key": "global-limit-b"},
        )
        assert second.status_code == 429
        assert second.json()["detail"]["error"] == "global_scan_concurrency_exceeded"
    finally:
        settings.scan_rate_limit_window_seconds = old_window
        settings.scan_rate_limit_max_requests = old_requests
        settings.scan_rate_limit_max_concurrent_per_client = old_per_client
        settings.scan_rate_limit_max_concurrent_global = old_global


# =============================================================================
# FINDING DEDUPLICATION TESTS
# =============================================================================


def test_deduplicate_findings_collapses_same_type_tool() -> None:
    """Test that findings with same (type, tool) are collapsed into one entry."""
    findings = [
        {
            "id": "f1",
            "type": "missing-x-frame-options",
            "tool": "header-checks",
            "url": "https://example.com/",
            "severity": "medium",
            "description": "Missing anti-clickjacking header",
            "evidence": "X-Frame-Options header not set",
        },
        {
            "id": "f2",
            "type": "missing-x-frame-options",
            "tool": "header-checks",
            "url": "https://example.com/index.html",
            "severity": "medium",
            "description": "Missing anti-clickjacking header",
            "evidence": "X-Frame-Options header not set",
        },
        {
            "id": "f3",
            "type": "missing-x-frame-options",
            "tool": "header-checks",
            "url": "https://example.com/contact.html",
            "severity": "medium",
            "description": "Missing anti-clickjacking header",
            "evidence": "X-Frame-Options header not set",
        },
    ]

    result = _deduplicate_findings(findings)

    assert len(result) == 1
    collapsed = result[0]
    assert collapsed["is_collapsed"] is True
    assert collapsed["instance_count"] == 3
    assert len(collapsed["affected_urls"]) == 3
    assert "https://example.com/" in collapsed["affected_urls"]
    assert "https://example.com/index.html" in collapsed["affected_urls"]
    assert "https://example.com/contact.html" in collapsed["affected_urls"]
    # Evidence is the same, so should be preserved as single value
    assert collapsed.get("evidence") == "X-Frame-Options header not set"
    assert "url_evidence" not in collapsed


def test_deduplicate_findings_preserves_varying_evidence() -> None:
    """Test that per-URL evidence is preserved when it varies."""
    findings = [
        {
            "id": "f1",
            "type": "cache-exposure",
            "tool": "zap",
            "url": "https://example.com/api/data",
            "severity": "info",
            "description": "Cached response",
            "evidence": "Age: 120",
        },
        {
            "id": "f2",
            "type": "cache-exposure",
            "tool": "zap",
            "url": "https://example.com/api/users",
            "severity": "info",
            "description": "Cached response",
            "evidence": "Age: 3600",
        },
    ]

    result = _deduplicate_findings(findings)

    assert len(result) == 1
    collapsed = result[0]
    assert collapsed["is_collapsed"] is True
    assert collapsed["instance_count"] == 2
    # Evidence varies, so should be in url_evidence map
    assert "url_evidence" in collapsed
    assert collapsed["url_evidence"]["https://example.com/api/data"] == "Age: 120"
    assert collapsed["url_evidence"]["https://example.com/api/users"] == "Age: 3600"


def test_deduplicate_findings_single_instance_unchanged() -> None:
    """Test that single findings are not modified."""
    findings = [
        {
            "id": "f1",
            "type": "xss",
            "tool": "nuclei",
            "url": "https://example.com/search",
            "severity": "critical",
            "description": "Reflected XSS",
        },
    ]

    result = _deduplicate_findings(findings)

    assert len(result) == 1
    assert result[0] == findings[0]
    assert "is_collapsed" not in result[0]


def test_deduplicate_findings_different_tools_not_collapsed() -> None:
    """Test that same finding type from different tools stays separate."""
    findings = [
        {
            "id": "f1",
            "type": "missing-csp",
            "tool": "header-checks",
            "url": "https://example.com/",
            "severity": "medium",
        },
        {
            "id": "f2",
            "type": "missing-csp",
            "tool": "zap",
            "url": "https://example.com/",
            "severity": "medium",
        },
    ]

    result = _deduplicate_findings(findings)

    # Should NOT be collapsed because tools are different
    assert len(result) == 2


def test_deduplicate_findings_mixed_scenarios() -> None:
    """Test deduplication with mixed single and multi-instance findings."""
    findings = [
        # 3 instances of missing-hsts from same tool
        {"id": "f1", "type": "missing-hsts", "tool": "header-checks", "url": "https://example.com/", "severity": "medium"},
        {"id": "f2", "type": "missing-hsts", "tool": "header-checks", "url": "https://example.com/page1", "severity": "medium"},
        {"id": "f3", "type": "missing-hsts", "tool": "header-checks", "url": "https://example.com/page2", "severity": "medium"},
        # 1 instance of XSS (should remain single)
        {"id": "f4", "type": "xss", "tool": "nuclei", "url": "https://example.com/search", "severity": "critical"},
        # 2 instances of SQLi from same tool
        {"id": "f5", "type": "sqli", "tool": "nuclei", "url": "https://example.com/login", "severity": "critical"},
        {"id": "f6", "type": "sqli", "tool": "nuclei", "url": "https://example.com/admin", "severity": "critical"},
    ]

    result = _deduplicate_findings(findings)

    # Should have 3 entries: collapsed hsts, single xss, collapsed sqli
    assert len(result) == 3

    types_found = {f["type"] for f in result}
    assert types_found == {"missing-hsts", "xss", "sqli"}

    hsts_finding = next(f for f in result if f["type"] == "missing-hsts")
    assert hsts_finding["is_collapsed"] is True
    assert hsts_finding["instance_count"] == 3

    xss_finding = next(f for f in result if f["type"] == "xss")
    assert "is_collapsed" not in xss_finding

    sqli_finding = next(f for f in result if f["type"] == "sqli")
    assert sqli_finding["is_collapsed"] is True
    assert sqli_finding["instance_count"] == 2


def test_group_findings_by_severity_deduplicated() -> None:
    """Test that grouping by severity works with deduplication."""
    findings = [
        {"id": "f1", "type": "xss", "tool": "nuclei", "url": "https://example.com/a", "severity": "critical"},
        {"id": "f2", "type": "missing-hsts", "tool": "header-checks", "url": "https://example.com/", "severity": "medium"},
        {"id": "f3", "type": "missing-hsts", "tool": "header-checks", "url": "https://example.com/page", "severity": "medium"},
        {"id": "f4", "type": "info-disclosure", "tool": "zap", "url": "https://example.com/robots.txt", "severity": "info"},
    ]

    result = _group_findings_by_severity_deduplicated(findings)

    assert len(result["critical"]) == 1
    assert len(result["medium"]) == 1  # Collapsed from 2
    assert len(result["info"]) == 1
    assert len(result["high"]) == 0
    assert len(result["low"]) == 0

    # Check the medium one is collapsed
    medium_finding = result["medium"][0]
    assert medium_finding["is_collapsed"] is True
    assert medium_finding["instance_count"] == 2


# =============================================================================
# PDF DESIGN CONSTANTS TESTS
# =============================================================================


def test_severity_color_returns_correct_rgb() -> None:
    """Test that severity colors return correct RGB values."""
    assert severity_color("critical") == COLORS.CRITICAL
    assert severity_color("high") == COLORS.HIGH
    assert severity_color("medium") == COLORS.MEDIUM
    assert severity_color("low") == COLORS.LOW
    assert severity_color("info") == COLORS.INFO
    # Unknown should default to info
    assert severity_color("unknown") == COLORS.INFO


def test_severity_light_color_returns_correct_rgb() -> None:
    """Test that severity light colors return correct RGB values."""
    assert severity_light_color("critical") == COLORS.CRITICAL_LIGHT
    assert severity_light_color("high") == COLORS.HIGH_LIGHT


def test_risk_score_color_returns_appropriate_color() -> None:
    """Test that risk score colors follow severity thresholds."""
    assert risk_score_color(0.0) == COLORS.SUCCESS
    assert risk_score_color(1.5) == COLORS.LOW
    assert risk_score_color(3.0) == COLORS.MEDIUM
    assert risk_score_color(5.5) == COLORS.HIGH
    assert risk_score_color(8.0) == COLORS.CRITICAL
    assert risk_score_color(10.0) == COLORS.CRITICAL


def test_typography_constants_defined() -> None:
    """Test that typography constants are properly defined."""
    assert TYPOGRAPHY.FONT_SANS == "Helvetica"
    assert TYPOGRAPHY.FONT_MONO == "Courier"
    assert TYPOGRAPHY.SIZE_TITLE > TYPOGRAPHY.SIZE_H1 > TYPOGRAPHY.SIZE_BODY


def test_spacing_constants_defined() -> None:
    """Test that spacing constants are properly defined."""
    assert SPACING.MARGIN_TOP > 0
    assert SPACING.MARGIN_BOTTOM > 0
    assert SPACING.MARGIN_LEFT > 0
    assert SPACING.MARGIN_RIGHT > 0


# =============================================================================
# PDF GENERATION EDGE CASE TESTS
# =============================================================================


def test_pdf_handles_zero_findings(tmp_path: Path, monkeypatch) -> None:
    """Test PDF generation with zero findings (clean scan)."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-clean"
    state["status"] = "scored"
    state["severity_scores"] = {
        "overall_risk_score": 0.0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "total_findings": 0,
    }
    state["findings"] = []

    result = run_reporting(state)
    pdf_path = Path(result["report"]["artifacts"]["pdf"])

    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")
    # Check outcome is clean
    assert result["report"]["outcome"] == "clean"


def test_pdf_handles_all_severity_tiers(tmp_path: Path, monkeypatch) -> None:
    """Test PDF generation with findings in every severity tier."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-all-severities"
    state["status"] = "scored"
    state["findings"] = [
        {"id": "f1", "type": "xss", "tool": "nuclei", "url": "https://example.com/", "severity": "critical", "description": "XSS"},
        {"id": "f2", "type": "sqli", "tool": "nuclei", "url": "https://example.com/", "severity": "high", "description": "SQLi"},
        {"id": "f3", "type": "missing-csp", "tool": "header-checks", "url": "https://example.com/", "severity": "medium", "description": "CSP"},
        {"id": "f4", "type": "weak-hsts", "tool": "header-checks", "url": "https://example.com/", "severity": "low", "description": "HSTS"},
        {"id": "f5", "type": "server-disclosure", "tool": "header-checks", "url": "https://example.com/", "severity": "info", "description": "Info"},
    ]
    state["severity_scores"] = {
        "overall_risk_score": 7.5,
        "severity_counts": {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1},
        "total_findings": 5,
    }

    result = run_reporting(state)
    pdf_path = Path(result["report"]["artifacts"]["pdf"])

    assert pdf_path.exists()
    # All reports should exist
    assert Path(result["report"]["artifacts"]["json"]).exists()
    assert Path(result["report"]["artifacts"]["md"]).exists()
    assert Path(result["report"]["artifacts"]["html"]).exists()


def test_pdf_handles_duplicate_findings(tmp_path: Path, monkeypatch) -> None:
    """Test PDF generation with many duplicate finding instances (deduplication test)."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-duplicates"
    state["status"] = "scored"
    # Create 12 instances of the same finding type
    state["findings"] = [
        {
            "id": f"f{i}",
            "type": "missing-x-frame-options",
            "tool": "header-checks",
            "url": f"https://example.com/page{i}.html",
            "severity": "medium",
            "description": "Missing anti-clickjacking header",
        }
        for i in range(12)
    ]
    state["severity_scores"] = {
        "overall_risk_score": 3.5,
        "severity_counts": {"critical": 0, "high": 0, "medium": 12, "low": 0, "info": 0},
        "total_findings": 12,
    }

    result = run_reporting(state)

    # Check that deduplication happened
    deduplicated = result["report"]["findings_by_severity_deduplicated"]["medium"]
    assert len(deduplicated) == 1
    assert deduplicated[0]["is_collapsed"] is True
    assert deduplicated[0]["instance_count"] == 12
    assert len(deduplicated[0]["affected_urls"]) == 12

    # PDF should still be generated
    pdf_path = Path(result["report"]["artifacts"]["pdf"])
    assert pdf_path.exists()


def test_pdf_handles_long_urls(tmp_path: Path, monkeypatch) -> None:
    """Test PDF generation with unusually long URLs."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    # Create a very long URL
    long_url = "https://example.com/" + "a" * 200 + "/page?param=" + "b" * 100

    state = _base_state()
    state["scan_id"] = "scan-long-urls"
    state["status"] = "scored"
    state["findings"] = [
        {
            "id": "f1",
            "type": "xss",
            "tool": "nuclei",
            "url": long_url,
            "severity": "critical",
            "description": "XSS vulnerability with very long URL",
        },
    ]
    state["severity_scores"] = {
        "overall_risk_score": 8.5,
        "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        "total_findings": 1,
    }

    result = run_reporting(state)
    pdf_path = Path(result["report"]["artifacts"]["pdf"])

    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_pdf_handles_long_ai_summary(tmp_path: Path, monkeypatch) -> None:
    """Test PDF generation with long AI-generated summary text."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    long_summary = (
        "This is a comprehensive security assessment that identified multiple "
        "critical vulnerabilities requiring immediate attention. " * 20
    )

    state = _base_state()
    state["scan_id"] = "scan-long-ai"
    state["status"] = "scored"
    state["findings"] = [
        {"id": "f1", "type": "xss", "tool": "nuclei", "url": "https://example.com/", "severity": "critical"},
    ]
    state["severity_scores"] = {
        "overall_risk_score": 8.0,
        "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        "total_findings": 1,
    }
    state["ai_synthesis"] = {
        "status": "completed",
        "executive_summary": {
            "summary_text": long_summary,
            "business_impact_one_liner": "Critical security risk requiring immediate remediation.",
        },
        "remediation_roadmap": [
            {"estimated_effort": "high", "rationale": "Fix XSS immediately", "finding_ids": ["f1"]},
        ],
    }

    result = run_reporting(state)
    pdf_path = Path(result["report"]["artifacts"]["pdf"])

    assert pdf_path.exists()


def test_pdf_handles_no_evidence_field(tmp_path: Path, monkeypatch) -> None:
    """Test PDF generation when findings have no evidence field."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-no-evidence"
    state["status"] = "scored"
    state["findings"] = [
        {
            "id": "f1",
            "type": "missing-csp",
            "tool": "header-checks",
            "url": "https://example.com/",
            "severity": "medium",
            "description": "No CSP header",
            # No evidence field
        },
    ]
    state["severity_scores"] = {
        "overall_risk_score": 4.0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        "total_findings": 1,
    }

    result = run_reporting(state)
    pdf_path = Path(result["report"]["artifacts"]["pdf"])

    assert pdf_path.exists()


def test_html_report_uses_deduplicated_findings(tmp_path: Path, monkeypatch) -> None:
    """Test that HTML report uses deduplicated findings."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-html-dedup"
    state["status"] = "scored"
    state["findings"] = [
        {"id": f"f{i}", "type": "missing-hsts", "tool": "header-checks",
         "url": f"https://example.com/page{i}", "severity": "medium"}
        for i in range(5)
    ]
    state["severity_scores"] = {
        "overall_risk_score": 3.0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 5, "low": 0, "info": 0},
        "total_findings": 5,
    }

    result = run_reporting(state)
    html_path = Path(result["report"]["artifacts"]["html"])

    html_content = html_path.read_text(encoding="utf-8")

    # Should show instance count badge
    assert "5 instances" in html_content
    # Should show affected URLs list
    assert "Found on 5 pages" in html_content


def test_markdown_report_uses_deduplicated_findings(tmp_path: Path, monkeypatch) -> None:
    """Test that Markdown report uses deduplicated findings."""
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)

    state = _base_state()
    state["scan_id"] = "scan-md-dedup"
    state["status"] = "scored"
    state["findings"] = [
        {"id": f"f{i}", "type": "missing-csp", "tool": "header-checks",
         "url": f"https://example.com/page{i}", "severity": "medium"}
        for i in range(3)
    ]
    state["severity_scores"] = {
        "overall_risk_score": 4.0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 3, "low": 0, "info": 0},
        "total_findings": 3,
    }

    result = run_reporting(state)
    md_path = Path(result["report"]["artifacts"]["md"])

    md_content = md_path.read_text(encoding="utf-8")

    # Should show instance count in title
    assert "[3 instances]" in md_content
    # Should show found on X pages
    assert "Found on 3 pages" in md_content
