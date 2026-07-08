"""Tests for scoring, reporting artifacts, and report delivery."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from agents.reporting import run_reporting
from agents.scoring import run_scoring
from agents.state import ScanState
from core.config import get_settings


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


def test_run_reporting_writes_json_markdown_html(tmp_path: Path, monkeypatch) -> None:
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
    assert "findings_by_severity" in result["report"]


def test_report_format_endpoint_serves_json_md_html(client: TestClient) -> None:
    target = "https://authorized.example.com"
    create = client.post("/scan", json={"target": target})
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

    json_report = client.get(f"/scan/{scan_id}/report/json", params={"target": target})
    assert json_report.status_code == 200
    assert "scan_id" in json_report.json()

    md_report = client.get(f"/scan/{scan_id}/report/md", params={"target": target})
    assert md_report.status_code == 200
    assert "# Sentinel Scan Report" in md_report.text

    html_report = client.get(f"/scan/{scan_id}/report/html", params={"target": target})
    assert html_report.status_code == 200
    assert "<!DOCTYPE html>" in html_report.text


def test_scan_rate_limiting_on_scan_endpoint(client: TestClient) -> None:
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
        target = "https://authorized.example.com"
        headers = {"X-API-Key": "rate-limit-test-key"}
        first = client.post("/scan", json={"target": target}, headers=headers)
        assert first.status_code == 202

        second = client.post("/scan", json={"target": target}, headers=headers)
        assert second.status_code == 429
        assert second.json()["detail"]["error"] == "scan_rate_limit_exceeded"
    finally:
        settings.scan_rate_limit_window_seconds = old_window
        settings.scan_rate_limit_max_requests = old_requests
        settings.scan_rate_limit_max_concurrent_per_client = old_per_client
        settings.scan_rate_limit_max_concurrent_global = old_global
