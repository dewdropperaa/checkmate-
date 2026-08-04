"""Tests for OWASP Top 10 mapping helpers."""

from __future__ import annotations

from core.owasp import classify_finding_owasp, coverage_for_modules


def test_classify_xss_and_sqli() -> None:
    assert classify_finding_owasp(finding_type="reflected-xss", tool="nuclei", tags=["xss"]) == "A03:2021"
    assert classify_finding_owasp(finding_type="sqli", tool="sqlmap") == "A03:2021"
    assert classify_finding_owasp(finding_type="ssrf-via-pdf", tool="nuclei", tags=["ssrf"]) == "A10:2021"
    assert classify_finding_owasp(finding_type="missing-hsts", tool="header-checks") == "A02:2021"


def test_coverage_for_modules_lists_injection_when_zap_runs() -> None:
    cov = coverage_for_modules(["nuclei", "header-checks", "testssl", "retirejs", "zap", "sqlmap"])
    assert "A03:2021" in cov["categories_covered"]
    assert "A02:2021" in cov["categories_covered"]
    assert "A06:2021" in cov["categories_covered"]
    assert "A04:2021" in cov["categories_not_covered"]
    assert "A09:2021" in cov["not_automatable"]
