"""Production-readiness regression tests for scan lifecycle edge cases."""

from __future__ import annotations

import asyncio
import socket
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agents.orchestrator import ScanOrchestrator
from agents.reporting import run_reporting
from agents.scoring import run_scoring
from agents.state import ScanState
from core.config import Settings, get_settings, validate_startup_settings
from core.ssrf import SSRFError, normalize_scan_target


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: fake_results)


@pytest.fixture
def fast_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _instant_recon(state):
        return {
            "recon_results": {
                "target": state["target"],
                "subdomains": [],
                "hosts": [state["target"]],
                "technologies": [],
                "endpoints": [],
                "urls": [state["target"]],
                "js_files": [],
                "pages": [],
                "tool_results": {},
                "errors": {},
                "partial_failure": False,
            }
        }

    monkeypatch.setattr("agents.recon.run_recon_async", _instant_recon)


def _base_state(**overrides) -> ScanState:
    state: ScanState = {
        "scan_id": "scan-prod-readiness",
        "target": "https://authorized.example.com/",
        "scope": {},
        "authorized": True,
        "recon_results": {},
        "planned_active_tests": [],
        "findings": [],
        "severity_scores": {},
        "report": None,
        "status": "running",
        "human_approval_needed": False,
        "human_approved": True,
    }
    state.update(overrides)
    return state


class TestTargetNormalization:
    def test_strips_path_query_and_adds_scheme(self, public_dns: None) -> None:
        normalized = normalize_scan_target("matchupfoot.ma/admin?q=1#frag")
        assert normalized == "https://matchupfoot.ma/"

    def test_accepts_punycode_idn(self, public_dns: None) -> None:
        normalized = normalize_scan_target("https://xn--bcher-kva.example/")
        assert normalized == "https://xn--bcher-kva.example/"

    def test_api_returns_normalized_target(self, client: TestClient, public_dns: None) -> None:
        response = client.post(
            "/scan",
            json={
                "target": "authorized.example.com/path?x=1",
                "confirmed_authorized": True,
            },
        )
        assert response.status_code == 202
        assert response.json()["target"] == "https://authorized.example.com/"

    def test_dns_failure_has_distinct_message(self, client: TestClient) -> None:
        def _fail_dns(*_args, **_kwargs):
            raise socket.gaierror("Name or service not known")

        with patch("core.ssrf.socket.getaddrinfo", side_effect=_fail_dns):
            response = client.post(
                "/scan",
                json={
                    "target": "https://does-not-resolve.example",
                    "confirmed_authorized": True,
                },
            )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert detail["error"] == "invalid_scan_target"
        assert "Could not resolve hostname" in detail["message"]


class TestZeroFindingsAndScoring:
    def test_user_summary_rejected_includes_passive_note(self) -> None:
        from agents.reporting import _user_summary

        state = {
            "status": "rejected",
            "human_approval_needed": True,
            "human_approved": False,
        }
        summary = _user_summary(state, findings_count=3)
        assert "Passive detection findings" in summary

    def test_zero_findings_produces_clean_outcome(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
        state = _base_state(status="scored")
        state["severity_scores"] = run_scoring(state)["severity_scores"]

        result = run_reporting(state)
        report = result["report"]
        assert report["outcome"] == "clean"
        assert report["findings_count"] == 0
        assert report["summary"]
        assert "No security findings" in report["summary"]
        assert report["severity_scores"]["overall_risk_score"] == 0.0

    def test_partial_module_scoring_includes_coverage(self) -> None:
        state = _base_state(
            recon_results={
                "tool_results": {"header-checks": {"success": True}},
                "partial_failure": True,
                "errors": {"firecrawl": "timed out"},
            },
            detection_metadata={
                "errors": {"nuclei": "Binary validation failed"},
                "active_tools_run": False,
            },
            findings=[
                {
                    "tool": "header-checks",
                    "type": "missing-csp",
                    "url": "https://authorized.example.com/",
                    "severity": "medium",
                }
            ],
        )
        scored = run_scoring(state)
        coverage = scored["severity_scores"]["scan_coverage"]
        assert coverage["recon_modules_run"] == ["header-checks"]
        assert "nuclei" in coverage["modules_skipped"]
        assert coverage["recon_partial_failure"] is True
        assert scored["severity_scores"]["overall_risk_score"] > 0

    def test_failed_modules_apply_non_zero_uncertainty_floor(self) -> None:
        clean_full = run_scoring(_base_state(findings=[]))
        partial_failed = run_scoring(
            _base_state(
                findings=[],
                recon_results={"tool_results": {}, "partial_failure": True},
                detection_metadata={"errors": {"nuclei": "timed out"}},
            )
        )
        assert clean_full["severity_scores"]["overall_risk_score"] == 0.0
        assert partial_failed["severity_scores"]["overall_risk_score"] >= 0.5
        assert "nuclei" in partial_failed["severity_scores"]["scan_coverage"]["modules_failed"]


class TestFailureReporting:
    def test_scope_failure_generates_report(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
        state = _base_state(
            authorized=False,
            status="failed",
            error={
                "code": "target_not_authorized",
                "message": "This target is not authorized for scanning.",
            },
        )
        result = run_reporting(state)
        report = result["report"]
        assert report["outcome"] == "failed"
        assert report["error"]["code"] == "target_not_authorized"
        assert Path(report["artifacts"]["json"]).exists()

    @pytest.mark.asyncio
    async def test_scan_timeout_marks_failed_with_report(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
        get_settings.cache_clear()
        settings = get_settings()
        settings.scan_timeout_seconds = 0.01

        orchestrator = ScanOrchestrator(use_sqlite=False)
        scan_id = "scan-timeout-test"
        target = "https://authorized.example.com/"

        async def _slow_invoke(*_args, **_kwargs):
            await asyncio.sleep(1.0)

        monkeypatch.setattr(orchestrator._graph, "ainvoke", _slow_invoke)

        orchestrator.register_scan(scan_id, target)
        await orchestrator.start_scan(scan_id, target)

        summary = await orchestrator.get_status_summary(scan_id)
        assert summary is not None
        assert summary["status"] == "failed"
        assert summary["error"]["code"] == "scan_timeout"
        assert summary["is_complete"] is True

        report_path = tmp_path / scan_id / "report.json"
        assert report_path.exists()
        get_settings.cache_clear()


class TestInflightDedup:
    def test_duplicate_scan_returns_409(
        self, client: TestClient, public_dns: None, fast_recon: None
    ) -> None:
        headers = {"X-API-Key": "dedup-test-key"}
        payload = {
            "target": "https://authorized.example.com",
            "confirmed_authorized": True,
        }
        first = client.post("/scan", json=payload, headers=headers)
        assert first.status_code == 202
        scan_id = first.json()["scan_id"]

        second = client.post("/scan", json=payload, headers=headers)
        assert second.status_code == 409
        detail = second.json()["detail"]
        assert detail["error"] == "scan_already_in_progress"
        assert detail["scan_id"] == scan_id

    @pytest.mark.asyncio
    async def test_concurrent_register_only_keeps_one_inflight(self) -> None:
        from app.main import InflightScanRegistry

        registry = InflightScanRegistry()
        client_id = "api_key:concurrent-unit"
        target = "https://authorized.example.com/"

        await registry.register(client_id, target, "scan-a")

        async def _try_register_b():
            return await registry.get_inflight(client_id, target)

        existing = await asyncio.gather(_try_register_b(), _try_register_b())
        assert existing == ["scan-a", "scan-a"]

    @pytest.mark.asyncio
    async def test_concurrency_rejection_does_not_consume_rate_slot(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fastapi import HTTPException

        from app.main import ScanRateLimiter

        limiter = ScanRateLimiter()
        settings = get_settings()
        old_requests = settings.scan_rate_limit_max_requests
        old_per_client = settings.scan_rate_limit_max_concurrent_per_client
        old_global = settings.scan_rate_limit_max_concurrent_global
        old_window = settings.scan_rate_limit_window_seconds
        settings.scan_rate_limit_window_seconds = 60
        settings.scan_rate_limit_max_requests = 1
        settings.scan_rate_limit_max_concurrent_per_client = 0
        settings.scan_rate_limit_max_concurrent_global = 10
        client_id = "api_key:no-rate-burn"
        try:
            with pytest.raises(HTTPException) as exc:
                await limiter.acquire(client_id)
            assert exc.value.detail["error"] == "scan_concurrency_exceeded"
            # Raise only due concurrency. If concurrency rejections consumed rate
            # slots, this second attempt would now fail as a rate-limit breach.
            settings.scan_rate_limit_max_concurrent_per_client = 1
            await limiter.acquire(client_id)
        finally:
            settings.scan_rate_limit_max_requests = old_requests
            settings.scan_rate_limit_max_concurrent_per_client = old_per_client
            settings.scan_rate_limit_max_concurrent_global = old_global
            settings.scan_rate_limit_window_seconds = old_window


class TestReportTruncation:
    def test_large_findings_are_truncated_in_artifacts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
        settings = get_settings()
        old_max = settings.report_max_findings
        settings.report_max_findings = 10

        findings = [
            {
                "tool": "header-checks",
                "type": f"missing-header-{i}",
                "url": f"https://authorized.example.com/{i}",
                "severity": "low",
                "description": f"finding {i}",
            }
            for i in range(25)
        ]
        state = _base_state(status="scored", findings=findings)
        state["severity_scores"] = {
            "overall_risk_score": 1.0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 25, "info": 0},
            "total_findings": 25,
            "likely_false_positives": 0,
            "per_finding": {},
        }

        try:
            result = run_reporting(state)
            report = result["report"]
            assert report["findings_count"] == 25
            assert report["truncation"]["truncated"] is True
            rendered = sum(
                len(items) for items in report["findings_by_severity"].values()
            )
            assert rendered == 10
        finally:
            settings.report_max_findings = old_max

    def test_truncation_keeps_highest_severity_findings_first(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
        settings = get_settings()
        old_max = settings.report_max_findings
        settings.report_max_findings = 3
        findings = [
            {"tool": "nuclei", "type": "info-a", "url": "https://a", "severity": "info"},
            {"tool": "nuclei", "type": "critical-a", "url": "https://b", "severity": "critical"},
            {"tool": "nuclei", "type": "low-a", "url": "https://c", "severity": "low"},
            {"tool": "nuclei", "type": "high-a", "url": "https://d", "severity": "high"},
            {"tool": "nuclei", "type": "medium-a", "url": "https://e", "severity": "medium"},
        ]
        state = _base_state(status="scored", findings=findings)
        state["severity_scores"] = {
            "overall_risk_score": 7.0,
            "severity_counts": {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1},
            "total_findings": 5,
            "likely_false_positives": 0,
            "per_finding": {},
        }
        try:
            result = run_reporting(state)
            report = result["report"]
            assert report["truncation"]["truncated"] is True
            assert report["truncation"]["rendered_findings"] == 3
            assert "Lower-severity entries were truncated first" in report["truncation"]["message"]
            assert len(report["findings_by_severity"]["critical"]) == 1
            assert len(report["findings_by_severity"]["high"]) == 1
            assert len(report["findings_by_severity"]["medium"]) == 1
            assert len(report["findings_by_severity"]["low"]) == 0
            assert len(report["findings_by_severity"]["info"]) == 0
        finally:
            settings.report_max_findings = old_max


class TestStartupAndHealth:
    def test_production_startup_requires_firecrawl_when_enabled(self) -> None:
        settings = Settings(
            app_env="production",
            firecrawl_enabled=True,
            firecrawl_api_key=None,
            zap_api_key="zap-key",
        )
        with pytest.raises(ValueError, match="FIRECRAWL_API_KEY"):
            validate_startup_settings(settings)

    def test_development_skips_production_validation(self) -> None:
        settings = Settings(app_env="development", firecrawl_enabled=True)
        validate_startup_settings(settings)

    def test_health_reports_orchestrator_ready(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] in ("ok", "degraded")
        assert body["service"] == "checkmate"
        assert body["orchestrator_ready"] is True
        assert "toolchain" in body

    def test_scan_endpoint_returns_503_when_toolchain_not_ready(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app import main as api_main

        monkeypatch.setattr(
            api_main,
            "ensure_toolchain_ready",
            lambda: (_ for _ in ()).throw(ValueError("missing binaries: nuclei, sqlmap")),
        )
        response = client.post(
            "/scan",
            json={"target": "https://authorized.example.com", "confirmed_authorized": True},
        )
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["error"] == "toolchain_not_ready"
        assert "missing binaries" in detail["message"]


class TestAuthorizationGate:
    def test_unconfirmed_authorization_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/scan",
            json={"target": "https://authorized.example.com", "confirmed_authorized": False},
        )
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "authorization_not_confirmed"
