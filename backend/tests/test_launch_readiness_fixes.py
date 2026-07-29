"""Proving tests for production launch readiness fixes."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from agents.detection import run_passive_tools
from agents.reporting import run_reporting
from agents.scoring import run_scoring
from agents.state import ScanState
from core.accounts import (
    get_or_create_user_from_firebase,
    get_site_auth_credentials,
    upsert_site,
    upsert_site_auth_credentials,
)
from core.config import Settings, get_settings, validate_startup_settings
from core.credential_crypto import encrypt_credentials
from core.logging import JsonFormatter
from core.ssrf import SSRFError, validate_login_url_for_site
from tools.base import ToolResult
from tools.nuclei_tool import NucleiTool
from tools.retirejs_tool import RetireJSTool
from tools.sqlmap_tool import SQLMapTool


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: fake_results)


def _base_state(**overrides) -> ScanState:
    state: ScanState = {
        "scan_id": "scan-launch-fix",
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


class TestNucleiFailureHonesty:
    @pytest.mark.asyncio
    async def test_nonzero_exit_is_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/usr/bin/nuclei"))
        monkeypatch.setattr(
            "tools.nuclei_tool.run_subprocess_safely",
            AsyncMock(return_value=(1, "", "boom", False)),
        )
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)
        result = await tool.run("https://authorized.example.com", {})
        assert result.success is False
        assert "exited with code 1" in (result.error or "")

    @pytest.mark.asyncio
    async def test_malformed_stdout_is_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/usr/bin/nuclei"))
        monkeypatch.setattr(
            "tools.nuclei_tool.run_subprocess_safely",
            AsyncMock(return_value=(0, "not-json-at-all{{{", "", False)),
        )
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)
        result = await tool.run("https://authorized.example.com", {})
        assert result.success is False
        assert "could not be parsed" in (result.error or "")


class TestRetireAndSqlmapBatchFailures:
    @pytest.mark.asyncio
    async def test_retire_batch_all_timeouts_fail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = RetireJSTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/usr/bin/retire"))
        monkeypatch.setattr(
            "tools.retirejs_tool.run_subprocess_safely",
            AsyncMock(return_value=(-1, "", "", True)),
        )
        monkeypatch.setattr("tools.retirejs_tool.validate_scope", lambda *_a, **_k: None)
        result = await tool.run_batch(
            ["https://authorized.example.com/a.js", "https://authorized.example.com/b.js"],
            {},
        )
        assert result.success is False
        assert "failed for all URLs" in (result.error or "")

    @pytest.mark.asyncio
    async def test_sqlmap_batch_all_child_failures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = SQLMapTool(timeout=5)

        async def _fail_run(url, scope):
            return ToolResult(
                tool_name="sqlmap",
                target=url,
                success=False,
                error="exit 2",
                exit_code=2,
            )

        monkeypatch.setattr(tool, "run", _fail_run)
        monkeypatch.setattr("tools.sqlmap_tool.validate_scope", lambda *_a, **_k: None)
        result = await tool.run_batch(
            ["https://authorized.example.com/?id=1", "https://authorized.example.com/?id=2"],
            {},
        )
        assert result.success is False
        assert "failed for all URLs" in (result.error or "")


class TestPassiveDetectionRecordsToolFailure:
    @pytest.mark.asyncio
    async def test_failed_tool_result_enters_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _fake_safely(name, factory):
            return (
                name,
                ToolResult(
                    tool_name=name,
                    target="https://authorized.example.com",
                    success=False,
                    error=f"{name} crashed",
                    exit_code=1,
                    data={"findings": []},
                ),
                None,
            )

        monkeypatch.setattr("agents.detection.run_tool_safely", _fake_safely)
        monkeypatch.setattr(
            "agents.detection.HeaderChecker.close",
            AsyncMock(return_value=None),
        )
        state = _base_state(
            recon_results={
                "hosts": ["https://authorized.example.com"],
                "urls": ["https://authorized.example.com"],
                "js_files": [],
            }
        )
        findings, errors = await run_passive_tools(state)
        assert findings == []
        assert "nuclei" in errors
        assert "header-checks" in errors


class TestScoringCoverageHonesty:
    def test_approving_only_sqlmap_does_not_credit_zap(self) -> None:
        scored = run_scoring(
            _base_state(
                findings=[],
                detection_metadata={
                    "active_tools_run": True,
                    "active_tools_executed": ["sqlmap"],
                    "approved_tools": ["sqlmap"],
                    "rejected_tools": ["zap"],
                    "errors": {},
                },
            )
        )
        coverage = scored["severity_scores"]["scan_coverage"]
        assert "sqlmap" in coverage["detection_modules_run"]
        assert "zap" not in coverage["detection_modules_run"]
        assert "zap" in coverage["modules_skipped"]

    def test_failed_nuclei_raises_uncertainty_floor_above_clean(self) -> None:
        clean = run_scoring(_base_state(findings=[]))
        failed = run_scoring(
            _base_state(
                findings=[],
                detection_metadata={"errors": {"nuclei": "exited with code 1"}},
            )
        )
        assert clean["severity_scores"]["overall_risk_score"] == 0.0
        assert failed["severity_scores"]["overall_risk_score"] >= 0.5
        assert "nuclei" in failed["severity_scores"]["scan_coverage"]["modules_failed"]


class TestLoginUrlSsrf:
    def test_rejects_metadata_login_url(self, public_dns: None) -> None:
        with pytest.raises(SSRFError):
            validate_login_url_for_site(
                "http://169.254.169.254/latest/meta-data/",
                "https://authorized.example.com",
                resolve_dns=False,
            )

    def test_rejects_cross_origin_login_url(self, public_dns: None) -> None:
        with pytest.raises(SSRFError, match="same-site"):
            validate_login_url_for_site(
                "https://evil.example/login",
                "https://authorized.example.com",
                resolve_dns=False,
            )

    def test_accepts_same_site_login_url(self, public_dns: None) -> None:
        normalized = validate_login_url_for_site(
            "https://authorized.example.com/login",
            "https://authorized.example.com",
            resolve_dns=False,
        )
        assert normalized.startswith("https://authorized.example.com")


class TestDodoWebhookHardening:
    def test_rejects_bad_secret(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = get_settings()
        monkeypatch.setattr(settings, "dodo_webhook_secret", "expected-secret")
        monkeypatch.setattr(settings, "app_env", "development")
        response = client.post(
            "/webhooks/dodo",
            json={
                "event": "subscription.active",
                "org_id": "org-missing",
                "plan_id": "pro",
            },
            headers={"X-Dodo-Webhook-Secret": "wrong"},
        )
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "invalid_webhook_secret"

    def test_staging_rejects_missing_secret_config(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = get_settings()
        monkeypatch.setattr(settings, "dodo_webhook_secret", None)
        monkeypatch.setattr(settings, "app_env", "staging")
        response = client.post(
            "/webhooks/dodo",
            json={"event": "subscription.active", "org_id": "org-x", "plan_id": "pro"},
        )
        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "webhook_not_configured"


class TestCredentialOrgScoping:
    def test_credentials_not_visible_across_orgs(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
        from core import credential_crypto

        credential_crypto._master_fernet = None  # noqa: SLF001
        get_settings.cache_clear()

        owner = get_or_create_user_from_firebase(
            uid="uid-owner",
            email="owner@example.com",
            display_name="Owner",
            email_verified=True,
            auth_provider="password",
        )
        other = get_or_create_user_from_firebase(
            uid="uid-other",
            email="other@example.com",
            display_name="Other",
            email_verified=True,
            auth_provider="password",
        )
        site = upsert_site(org_id=owner.org_id, target="https://authorized.example.com")
        blob = encrypt_credentials("alice", "secret-password")
        upsert_site_auth_credentials(
            site_id=site.id,
            org_id=owner.org_id,
            login_url="https://authorized.example.com/login",
            username_field="username",
            password_field="password",
            encrypted_data_key=blob.encrypted_data_key,
            encrypted_payload=blob.ciphertext,
            username_hint="a***e",
            credentials_consent_user_id=owner.id,
        )
        assert get_site_auth_credentials(site.id, org_id=owner.org_id) is not None
        assert get_site_auth_credentials(site.id, org_id=other.org_id) is None


class TestReportDedupBeforeTruncate:
    def test_unique_types_survive_repeat_flood(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
        settings = get_settings()
        old_max = settings.report_max_findings
        settings.report_max_findings = 3
        findings = [
            {
                "tool": "nuclei",
                "type": "repeated-xss",
                "url": f"https://authorized.example.com/{i}",
                "severity": "high",
                "description": "xss",
            }
            for i in range(20)
        ] + [
            {
                "tool": "header-checks",
                "type": "missing-csp",
                "url": "https://authorized.example.com/",
                "severity": "medium",
                "description": "csp",
            },
            {
                "tool": "testssl",
                "type": "tls-weak-cipher",
                "url": "https://authorized.example.com/",
                "severity": "low",
                "description": "tls",
            },
        ]
        try:
            result = run_reporting(_base_state(status="scored", findings=findings))
            report = result["report"]
            assert report["findings_count"] == 22
            assert report["unique_finding_groups"] == 3
            deduped = report["findings_by_severity_deduplicated"]
            types = {
                f["type"]
                for items in deduped.values()
                for f in items
            }
            assert "repeated-xss" in types
            assert "missing-csp" in types
            assert "tls-weak-cipher" in types
            assert "full data remains in JSON metadata" not in (
                report.get("truncation") or {}
            ).get("message", "")
        finally:
            settings.report_max_findings = old_max


class TestStructuredLoggingOrgId:
    def test_formatter_includes_org_id(self) -> None:
        import logging

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.org_id = "org-123"  # type: ignore[attr-defined]
        record.scan_id = "scan-456"  # type: ignore[attr-defined]
        payload = JsonFormatter().format(record)
        assert '"org_id": "org-123"' in payload
        assert '"scan_id": "scan-456"' in payload


class TestProductionStartupGates:
    def test_validate_startup_passes_when_complete(self) -> None:
        settings = Settings(
            app_env="production",
            debug=False,
            firecrawl_enabled=False,
            zap_api_key="zap",
            firebase_project_id="proj",
            production_firebase_project_id="proj",
            firebase_credentials_path="/tmp/sa.json",
            require_firebase_auth=True,
            dodo_environment="live",
            dodo_api_key="dodo_live_launch_readiness",
            dodo_webhook_secret="whsec",
            credentials_master_key=Fernet.generate_key().decode(),
        )
        validate_startup_settings(settings)
