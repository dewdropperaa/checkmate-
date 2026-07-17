"""Tests for detection tools with mocked outputs and fixtures.

These tests verify:
1. Deduplication logic works correctly
2. Active tools are skipped without human approval
3. Finding schema validates correctly for each tool's output format
4. Scope validation is enforced
5. Tool output parsing is robust
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com,test.example.com")
os.environ.setdefault("TOOLS_BINARY_DIR", "/opt/tools")

from agents.state import ScanState
from tools.base import ScopeViolationError, ToolResult
from tools.schemas import Finding, Severity, deduplicate_findings


NUCLEI_FIXTURE = {
    "template-id": "cve-2021-44228",
    "info": {
        "name": "Apache Log4j RCE",
        "severity": "critical",
        "description": "Apache Log4j2 <=2.14.1 JNDI features allow remote code execution",
        "tags": ["cve", "rce", "log4j"],
        "classification": {
            "cwe-id": [94]
        }
    },
    "matched-at": "https://authorized.example.com/api",
    "matcher-name": "log4j-rce",
    "extracted-results": ["jndi-payload-detected"]
}

NUCLEI_HEADER_FIXTURE = {
    "template-id": "http-missing-security-headers",
    "info": {
        "name": "Missing Security Headers",
        "severity": "info",
        "description": "HTTP security headers are missing",
        "tags": ["misconfig", "headers"]
    },
    "matched-at": "https://authorized.example.com/",
    "matcher-name": "x-frame-options"
}

TESTSSL_FIXTURE = {
    "scanResult": [{
        "serverDefaults": [
            {"id": "HSTS", "severity": "MEDIUM", "finding": "HSTS is not set"},
        ],
        "protocols": [
            {"id": "TLS1", "severity": "LOW", "finding": "TLS 1.0 offered"},
        ],
        "vulnerabilities": [
            {"id": "POODLE_SSL", "severity": "HIGH", "finding": "VULNERABLE -- SSLv3 POODLE attack"},
        ],
        "ciphers": [
            {"id": "cipherlist_weak", "severity": "MEDIUM", "finding": "Weak cipher suites offered"},
        ]
    }]
}

RETIREJS_FIXTURE = [
    {
        "file": "https://authorized.example.com/js/jquery-1.6.2.min.js",
        "results": [
            {
                "component": "jquery",
                "version": "1.6.2",
                "vulnerabilities": [
                    {
                        "severity": "medium",
                        "identifiers": {
                            "CVE": ["CVE-2012-6708"],
                            "CWE": ["CWE-79"]
                        },
                        "info": ["XSS vulnerability in jQuery before 1.9.0"]
                    }
                ]
            }
        ]
    }
]

ZAP_ALERTS_FIXTURE = [
    {
        "pluginId": "10010",
        "alert": "Cookie Without Secure Flag",
        "risk": "1",
        "confidence": "2",
        "url": "https://authorized.example.com/",
        "param": "session",
        "description": "A cookie has been set without the secure flag",
        "cweid": "614",
        "evidence": "Set-Cookie: session=abc123"
    },
    {
        "pluginId": "40012",
        "alert": "Cross Site Scripting (Reflected)",
        "risk": "3",
        "confidence": "3",
        "url": "https://authorized.example.com/search?q=test",
        "param": "q",
        "description": "Cross-site scripting vulnerability",
        "cweid": "79",
        "evidence": "<script>alert(1)</script>"
    }
]

SQLMAP_OUTPUT_FIXTURE = """
[*] starting @ 12:00:00 /2024-01-01/

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] testing if the target URL content is stable
[12:00:03] [INFO] target URL content is stable
[12:00:04] [INFO] testing if GET parameter 'id' is dynamic
[12:00:05] [INFO] GET parameter 'id' appears to be dynamic
[12:00:10] [INFO] GET parameter 'id' is vulnerable

Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5678=5678

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)

[12:00:20] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
"""


class TestFindingSchema:
    """Tests for the Finding schema and validation."""

    def test_finding_creation_with_all_fields(self) -> None:
        """Finding should accept all valid fields."""
        finding = Finding(
            tool="nuclei",
            type="cve-2021-44228",
            url="https://authorized.example.com/api",
            param="input",
            severity=Severity.CRITICAL,
            description="Log4j RCE vulnerability",
            evidence="JNDI payload detected",
            cwe_id=94,
        )
        assert finding.tool == "nuclei"
        assert finding.severity == Severity.CRITICAL
        assert finding.cwe_id == 94

    def test_finding_severity_normalization(self) -> None:
        """Finding should normalize various severity strings."""
        assert Finding(
            tool="test", type="test", url="https://test.com",
            severity="informational", description="test"
        ).severity == Severity.INFO

        assert Finding(
            tool="test", type="test", url="https://test.com",
            severity="moderate", description="test"
        ).severity == Severity.MEDIUM

        assert Finding(
            tool="test", type="test", url="https://test.com",
            severity="CRITICAL", description="test"
        ).severity == Severity.CRITICAL

    def test_finding_dedup_key(self) -> None:
        """Finding dedup_key should return (url, type) tuple."""
        finding = Finding(
            tool="nuclei",
            type="missing-header",
            url="https://authorized.example.com/",
            severity=Severity.MEDIUM,
            description="Test",
        )
        assert finding.dedup_key() == ("https://authorized.example.com/", "missing-header")

    def test_finding_model_dump_for_state(self) -> None:
        """Finding should serialize correctly for ScanState."""
        finding = Finding(
            tool="nuclei",
            type="test",
            url="https://test.com",
            severity=Severity.HIGH,
            description="Test finding",
        )
        dumped = finding.model_dump_for_state()
        assert dumped["severity"] == "high"
        assert dumped["tool"] == "nuclei"


class TestDeduplication:
    """Tests for finding deduplication logic."""

    def test_deduplicate_removes_duplicates_by_url_type(self) -> None:
        """Deduplication should remove findings with same (url, type)."""
        findings = [
            Finding(tool="nuclei", type="missing-csp", url="https://test.com/",
                    severity=Severity.MEDIUM, description="From nuclei"),
            Finding(tool="zap", type="missing-csp", url="https://test.com/",
                    severity=Severity.MEDIUM, description="From ZAP"),
            Finding(tool="nuclei", type="xss", url="https://test.com/search",
                    severity=Severity.HIGH, description="XSS finding"),
        ]
        deduplicated = deduplicate_findings(findings)
        assert len(deduplicated) == 2

    def test_deduplicate_keeps_higher_severity(self) -> None:
        """Deduplication should keep the finding with higher severity."""
        findings = [
            Finding(tool="header-checks", type="missing-csp", url="https://test.com/",
                    severity=Severity.LOW, description="Low severity"),
            Finding(tool="nuclei", type="missing-csp", url="https://test.com/",
                    severity=Severity.HIGH, description="High severity"),
        ]
        deduplicated = deduplicate_findings(findings)
        assert len(deduplicated) == 1
        assert deduplicated[0].severity == Severity.HIGH
        assert deduplicated[0].tool == "nuclei"

    def test_deduplicate_preserves_different_urls(self) -> None:
        """Deduplication should preserve findings with different URLs."""
        findings = [
            Finding(tool="nuclei", type="xss", url="https://test.com/page1",
                    severity=Severity.HIGH, description="XSS on page1"),
            Finding(tool="nuclei", type="xss", url="https://test.com/page2",
                    severity=Severity.HIGH, description="XSS on page2"),
        ]
        deduplicated = deduplicate_findings(findings)
        assert len(deduplicated) == 2

    def test_deduplicate_empty_list(self) -> None:
        """Deduplication should handle empty list."""
        assert deduplicate_findings([]) == []


class TestNucleiTool:
    """Tests for NucleiTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_nuclei_parses_findings_correctly(self) -> None:
        """Nuclei should parse JSON output into Finding objects."""
        from tools.nuclei_tool import NucleiTool

        mock_output = json.dumps(NUCLEI_FIXTURE) + "\n"

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(mock_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(NucleiTool, "get_binary_path", return_value=Path("/opt/tools/nuclei")):
            tool = NucleiTool()
            result = await tool.run("https://authorized.example.com", {})

        assert result.success is True
        assert result.data["finding_count"] == 1
        findings = result.data["findings"]
        assert findings[0]["type"] == "cve-2021-44228"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cwe_id"] == 94

    @pytest.mark.asyncio
    async def test_nuclei_accepts_any_target(self) -> None:
        """Allowlist enforcement disabled: Nuclei does not raise ScopeViolationError."""
        from tools.nuclei_tool import NucleiTool

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"[]", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(NucleiTool, "get_binary_path", return_value=Path("/opt/tools/nuclei")):
            tool = NucleiTool()
            result = await tool.run("https://evil.attacker.com", {})

        assert result is not None
        assert "authorized scope" not in (result.error or "").lower()


class TestTestSSLTool:
    """Tests for TestSSLTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_testssl_parses_findings_correctly(self) -> None:
        """testssl.sh should parse JSON output into Finding objects."""
        from tools.testssl_tool import TestSSLTool

        mock_output = json.dumps(TESTSSL_FIXTURE)

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(mock_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(TestSSLTool, "get_binary_path", return_value=Path("/opt/tools/testssl.sh")):
            tool = TestSSLTool()
            result = await tool.run("authorized.example.com:443", {})

        assert result.success is True
        assert result.data["finding_count"] >= 3
        findings = result.data["findings"]
        types = [f["type"] for f in findings]
        assert any("HSTS" in t for t in types)
        assert any("POODLE" in t for t in types)


class TestRetireJSTool:
    """Tests for RetireJSTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_retirejs_parses_findings_correctly(self) -> None:
        """retire.js should parse JSON output into Finding objects."""
        from tools.retirejs_tool import RetireJSTool

        mock_output = json.dumps(RETIREJS_FIXTURE)

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(mock_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(RetireJSTool, "get_binary_path", return_value=Path("/opt/tools/retire")):
            tool = RetireJSTool()
            result = await tool.run("https://authorized.example.com/js/jquery-1.6.2.min.js", {})

        assert result.success is True
        assert result.data["finding_count"] == 1
        findings = result.data["findings"]
        assert "jquery" in findings[0]["type"]
        assert findings[0]["severity"] == "medium"
        assert findings[0]["cwe_id"] == 79


def _secure_baseline_headers(**overrides: str) -> httpx.Headers:
    """Full secure header set used by HeaderChecker happy-path tests."""
    headers = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; script-src 'self'",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
    }
    headers.update(overrides)
    return httpx.Headers(headers)


def _mock_header_response(headers: httpx.Headers, cookies: list[str] | None = None) -> MagicMock:
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = headers
    mock_response.headers.get_list = MagicMock(return_value=cookies or [])
    return mock_response


class TestHeaderChecker:
    """Tests for HeaderChecker with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_header_checker_detects_missing_headers(self) -> None:
        """Header checker should detect missing security headers."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(httpx.Headers({"content-type": "text/html"}))

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            checker = HeaderChecker()
            result = await checker.run("https://authorized.example.com", {})

        assert result.success is True
        assert result.data["finding_count"] >= 3
        types = [f["type"] for f in result.data["findings"]]
        assert "missing-csp" in types
        assert "missing-hsts" in types
        assert "missing-x-frame-options" in types

    @pytest.mark.asyncio
    async def test_header_checker_detects_insecure_cookies(self) -> None:
        """Header checker should detect insecure cookie attributes."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(
            _secure_baseline_headers(
                **{"strict-transport-security": "max-age=31536000; includeSubDomains"}
            ),
            cookies=["session=abc123; Path=/"],
        )

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            checker = HeaderChecker()
            result = await checker.run("https://authorized.example.com", {})

        assert result.success is True
        cookie_findings = [
            f for f in result.data["findings"]
            if f["type"] == "insecure-cookie"
        ]
        assert len(cookie_findings) >= 1

    @pytest.mark.asyncio
    async def test_hsts_missing_entirely(self) -> None:
        """Missing HSTS header must emit missing-hsts only (not weak-hsts)."""
        from tools.header_checks import HeaderChecker

        baseline = dict(_secure_baseline_headers())
        headers = httpx.Headers({
            k: v for k, v in baseline.items()
            if k.lower() != "strict-transport-security"
        })
        mock_response = _mock_header_response(headers)

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await HeaderChecker().run("https://authorized.example.com/", {})

        types = [f["type"] for f in result.data["findings"]]
        assert "missing-hsts" in types
        assert "weak-hsts" not in types
        assert "weak-hsts-max-age" not in types
        finding = next(f for f in result.data["findings"] if f["type"] == "missing-hsts")
        assert finding["severity"] == "medium"
        assert "missing entirely" in finding["description"].lower()

    @pytest.mark.asyncio
    async def test_hsts_fully_correct_produces_zero_hsts_findings(self) -> None:
        """Strong max-age + includeSubDomains + preload should yield no HSTS findings."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(_secure_baseline_headers())

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await HeaderChecker().run("https://authorized.example.com/", {})

        hsts_types = [
            f["type"] for f in result.data["findings"]
            if "hsts" in f["type"]
        ]
        assert hsts_types == []
        assert result.data["finding_count"] == 0

    @pytest.mark.asyncio
    async def test_hsts_weak_max_age_only(self) -> None:
        """Short max-age must be labeled weak-hsts-max-age with the actual value."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(_secure_baseline_headers(
            **{"strict-transport-security": "max-age=86400; includeSubDomains; preload"}
        ))

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await HeaderChecker().run("https://authorized.example.com/", {})

        types = [f["type"] for f in result.data["findings"]]
        assert "weak-hsts-max-age" in types
        assert "weak-hsts" not in types
        assert "missing-hsts-includesubdomains" not in types
        finding = next(f for f in result.data["findings"] if f["type"] == "weak-hsts-max-age")
        assert finding["severity"] == "low"
        assert "86400" in finding["description"]
        assert "31536000" in finding["description"]

    @pytest.mark.asyncio
    async def test_hsts_strong_max_age_missing_includesubdomains(self) -> None:
        """Strong max-age without includeSubDomains must not be labeled simply 'weak'."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(_secure_baseline_headers(
            **{"strict-transport-security": "max-age=63072000"}
        ))

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await HeaderChecker().run("https://authorized.example.com/", {})

        types = [f["type"] for f in result.data["findings"]]
        assert "missing-hsts-includesubdomains" in types
        assert "weak-hsts-max-age" not in types
        assert "weak-hsts" not in types
        finding = next(
            f for f in result.data["findings"] if f["type"] == "missing-hsts-includesubdomains"
        )
        assert finding["severity"] == "low"
        assert "63072000" in finding["description"]
        assert "includeSubDomains" in finding["description"]
        assert "missing-hsts-preload" in types

    @pytest.mark.asyncio
    async def test_cors_wildcard_with_credentials(self) -> None:
        """Wildcard ACAO + credentials must emit the distinct medium+ finding."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(_secure_baseline_headers(
            **{
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        ))

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = await HeaderChecker().run("https://authorized.example.com/", {})

        types = [f["type"] for f in result.data["findings"]]
        assert "cors-wildcard-with-credentials" in types
        assert "cors-wildcard" not in types
        finding = next(
            f for f in result.data["findings"] if f["type"] == "cors-wildcard-with-credentials"
        )
        assert finding["severity"] in ("medium", "high")

    @pytest.mark.asyncio
    async def test_run_batch_dedupes_by_origin(self) -> None:
        """Multiple paths under one origin must produce a single set of header findings."""
        from tools.header_checks import HeaderChecker

        mock_response = _mock_header_response(httpx.Headers({"content-type": "text/html"}))

        with patch.object(HeaderChecker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            checker = HeaderChecker(rate_limit_delay=0)
            result = await checker.run_batch(
                [
                    "https://authorized.example.com/",
                    "https://authorized.example.com/sitemap.xml",
                    "https://authorized.example.com/app/page?x=1",
                ],
                {},
            )

        assert result.data["origins_checked"] == 1
        assert mock_client.head.await_count == 1
        csp_findings = [f for f in result.data["findings"] if f["type"] == "missing-csp"]
        assert len(csp_findings) == 1
        assert csp_findings[0]["url"] == "https://authorized.example.com"
        assert len(csp_findings[0]["raw_data"]["seen_at"]) == 3


class TestZAPTool:
    """Tests for ZAPTool with mocked API responses."""

    @pytest.mark.asyncio
    async def test_zap_parses_alerts_correctly(self) -> None:
        """ZAP should parse API alerts into Finding objects."""
        from tools.zap_tool import ZAPTool

        tool = ZAPTool(api_url="http://localhost:8080")

        async def mock_api_call(endpoint: str, params: dict = None):
            if "accessUrl" in endpoint:
                return {}
            elif "spider/action/scan" in endpoint:
                return {"scan": "1"}
            elif "spider/view/status" in endpoint:
                return {"status": "100"}
            elif "ascan/action/scan" in endpoint:
                return {"scan": "1"}
            elif "ascan/view/status" in endpoint:
                return {"status": "100"}
            elif "alerts" in endpoint:
                return {"alerts": ZAP_ALERTS_FIXTURE}
            return {}

        with patch.object(tool, "_api_call", side_effect=mock_api_call):
            result = await tool.run("https://authorized.example.com", {})

        assert result.success is True
        assert result.data["finding_count"] == 2
        findings = result.data["findings"]
        severities = [f["severity"] for f in findings]
        assert "low" in severities
        assert "high" in severities

    @pytest.mark.asyncio
    async def test_zap_accepts_any_target(self) -> None:
        """Allowlist enforcement disabled: ZAP does not raise ScopeViolationError."""
        from tools.zap_tool import ZAPTool

        tool = ZAPTool(api_url="http://localhost:8080")

        async def mock_api_call(endpoint: str, params: dict = None):
            if "spider/action/scan" in endpoint or "ascan/action/scan" in endpoint:
                return {"scan": "1"}
            if "status" in endpoint:
                return {"status": "100"}
            if "alerts" in endpoint:
                return {"alerts": []}
            return {}

        with patch.object(tool, "_api_call", side_effect=mock_api_call):
            result = await tool.run("https://evil.attacker.com", {})

        assert result is not None
        assert "authorized scope" not in (result.error or "").lower()


class TestSQLMapTool:
    """Tests for SQLMapTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_sqlmap_parses_output_correctly(self) -> None:
        """SQLMap should parse console output into Finding objects."""
        from tools.sqlmap_tool import SQLMapTool

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(SQLMAP_OUTPUT_FIXTURE.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(SQLMapTool, "get_binary_path", return_value=Path("/opt/tools/sqlmap")):
            tool = SQLMapTool()
            result = await tool.run("https://authorized.example.com/api?id=1", {})

        assert result.success is True
        assert result.data["finding_count"] >= 1
        assert result.data["vulnerable"] is True
        findings = result.data["findings"]
        assert all(f["type"] == "sqli" for f in findings)
        assert all(f["cwe_id"] == 89 for f in findings)

    @pytest.mark.asyncio
    async def test_sqlmap_rejects_bare_domain(self) -> None:
        """SQLMap should reject URLs without query parameters."""
        from tools.sqlmap_tool import SQLMapTool

        tool = SQLMapTool()
        result = await tool.run("https://authorized.example.com/api", {})

        assert result.success is False
        assert "parameterized" in result.error.lower()

    @pytest.mark.asyncio
    async def test_sqlmap_accepts_any_target(self) -> None:
        """Allowlist enforcement disabled: SQLMap does not raise ScopeViolationError."""
        from tools.sqlmap_tool import SQLMapTool

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(SQLMapTool, "get_binary_path", return_value=Path("/opt/tools/sqlmap")):
            tool = SQLMapTool()
            result = await tool.run("https://evil.attacker.com/api?id=1", {})

        assert result is not None
        assert "authorized scope" not in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_sqlmap_caps_level_and_risk_in_command_args(self) -> None:
        """Configured scope above caps is clamped before subprocess execution."""
        from tools.sqlmap_tool import SQLMapTool

        captured: dict[str, Any] = {}

        async def _fake_run_subprocess(
            binary_path: Path,
            args: list[str],
            timeout: float = 120.0,
            env: dict[str, str] | None = None,
        ) -> tuple[int, str, str, bool]:
            captured["args"] = list(args)
            return (0, "", "", False)

        with patch.object(SQLMapTool, "get_binary_path", return_value=Path("/opt/tools/sqlmap")), \
             patch("tools.sqlmap_tool.run_subprocess_safely", side_effect=_fake_run_subprocess):
            tool = SQLMapTool()
            await tool.run(
                "https://authorized.example.com/api?id=1",
                {"level": 9, "risk": 9},
            )

        args = captured["args"]
        assert "--level" in args and args[args.index("--level") + 1] == "2"
        assert "--risk" in args and args[args.index("--risk") + 1] == "2"


class TestFindInjectableURLs:
    """Tests for the injectable URL finder."""

    def test_find_injectable_urls_extracts_parameterized_urls(self) -> None:
        """Should extract URLs with common SQL injection indicators."""
        from tools.sqlmap_tool import find_injectable_urls

        recon_results = {
            "urls": [
                "https://example.com/",
                "https://example.com/api/users?id=1",
                "https://example.com/search?q=test",
                "https://example.com/products?category=electronics",
                "https://example.com/static/style.css",
            ],
            # Real recon stores endpoints as dicts, not bare strings.
            "endpoints": [
                {
                    "url": "https://example.com/api/orders?user_id=123",
                    "method": "GET",
                    "status_code": 200,
                },
            ],
        }

        injectable = find_injectable_urls(recon_results)

        assert len(injectable) >= 3
        assert any("id=1" in url for url in injectable)
        assert any("user_id=" in url for url in injectable)
        assert not any("style.css" in url for url in injectable)

    def test_find_injectable_urls_empty_recon(self) -> None:
        """Should handle empty recon results."""
        from tools.sqlmap_tool import find_injectable_urls

        assert find_injectable_urls({}) == []
        assert find_injectable_urls({"urls": []}) == []
        assert find_injectable_urls({"endpoints": [{"method": "GET"}]}) == []


class TestDetectionAgent:
    """Tests for the detection agent orchestration."""

    @pytest.mark.asyncio
    async def test_detection_skips_active_tools_without_approval(self) -> None:
        """Detection should skip active tools when human_approved is False."""
        from agents.detection import run_detection_async

        state: ScanState = {
            "scan_id": "test-123",
            "target": "authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {
                "hosts": ["authorized.example.com"],
                "urls": ["https://authorized.example.com/"],
                "js_files": [],
            },
            "planned_active_tests": ["zap", "sqlmap"],
            "findings": [],
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": True,
            "human_approved": False,
        }

        with patch("agents.detection.run_passive_tools") as mock_passive, \
             patch("agents.detection.run_active_tools") as mock_active:
            mock_passive.return_value = ([], {})
            mock_active.return_value = ([], {})

            result = await run_detection_async(state)

            mock_passive.assert_called_once()
            mock_active.assert_not_called()

        assert result["detection_metadata"]["active_tools_run"] is False

    @pytest.mark.asyncio
    async def test_detection_runs_active_tools_with_approval(self) -> None:
        """Detection should run active tools when human_approved is True."""
        from agents.detection import run_detection_async

        state: ScanState = {
            "scan_id": "test-123",
            "target": "authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {
                "hosts": ["authorized.example.com"],
                "urls": ["https://authorized.example.com/"],
                "js_files": [],
            },
            "planned_active_tests": ["zap", "sqlmap"],
            "findings": [],
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": True,
            "human_approved": True,
        }

        with patch("agents.detection.run_passive_tools") as mock_passive, \
             patch("agents.detection.run_active_tools") as mock_active:
            mock_passive.return_value = ([], {})
            mock_active.return_value = ([], {})

            result = await run_detection_async(state)

            mock_passive.assert_called_once()
            mock_active.assert_called_once()

        assert result["detection_metadata"]["active_tools_run"] is True

    @pytest.mark.asyncio
    async def test_detection_deduplicates_findings(self) -> None:
        """Detection should deduplicate findings from multiple tools."""
        from agents.detection import run_detection_async

        state: ScanState = {
            "scan_id": "test-123",
            "target": "authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {
                "hosts": ["authorized.example.com"],
                "urls": ["https://authorized.example.com/"],
                "js_files": [],
            },
            "planned_active_tests": [],
            "findings": [],
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": False,
            "human_approved": False,
        }

        duplicate_findings = [
            Finding(
                tool="nuclei",
                type="missing-csp",
                url="https://authorized.example.com/",
                severity=Severity.MEDIUM,
                description="CSP missing (nuclei)",
            ),
            Finding(
                tool="header-checks",
                type="missing-csp",
                url="https://authorized.example.com/",
                severity=Severity.LOW,
                description="CSP missing (header-checks)",
            ),
            Finding(
                tool="nuclei",
                type="xss",
                url="https://authorized.example.com/search",
                severity=Severity.HIGH,
                description="XSS found",
            ),
        ]

        with patch("agents.detection.run_passive_tools") as mock_passive:
            mock_passive.return_value = (duplicate_findings, {})

            result = await run_detection_async(state)

        assert result["detection_metadata"]["deduplicated_count"] == 2
        assert len(result["findings"]) == 2

    @pytest.mark.asyncio
    async def test_detection_handles_tool_failures_gracefully(self) -> None:
        """Detection should continue even if some tools fail."""
        from agents.detection import run_passive_tools

        state: ScanState = {
            "scan_id": "test-123",
            "target": "authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {
                "hosts": ["authorized.example.com"],
                "urls": ["https://authorized.example.com/"],
                "js_files": ["https://authorized.example.com/app.js"],
            },
            "planned_active_tests": [],
            "findings": [],
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": False,
            "human_approved": False,
        }

        mock_header_result = ToolResult(
            tool_name="header-checks",
            target="https://authorized.example.com/",
            success=True,
            data={
                "findings": [
                    {
                        "tool": "header-checks",
                        "type": "missing-csp",
                        "url": "https://authorized.example.com/",
                        "severity": "medium",
                        "description": "CSP missing",
                    }
                ],
                "finding_count": 1,
            },
        )

        from tools.nuclei_tool import NucleiTool
        from tools.testssl_tool import TestSSLTool
        from tools.retirejs_tool import RetireJSTool
        from tools.header_checks import HeaderChecker

        with patch.object(NucleiTool, "run_batch", side_effect=Exception("Nuclei failed")), \
             patch.object(TestSSLTool, "run", side_effect=Exception("testssl failed")), \
             patch.object(RetireJSTool, "run_batch", side_effect=Exception("retire failed")), \
             patch.object(HeaderChecker, "run_batch", return_value=mock_header_result), \
             patch.object(HeaderChecker, "close", return_value=None):

            findings, errors = await run_passive_tools(state)

        assert len(findings) == 1
        assert "nuclei" in errors
        assert "testssl" in errors


class TestPerToolActiveApproval:
    """Tests for per-tool gating: a reviewer may approve sqlmap while
    rejecting zap (or vice versa), instead of one bulk approve/reject."""

    def _base_state(self, **overrides: Any) -> ScanState:
        state: ScanState = {
            "scan_id": "test-per-tool",
            "target": "authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {
                "hosts": ["authorized.example.com"],
                "urls": ["https://authorized.example.com/api?id=1"],
                "js_files": [],
            },
            "planned_active_tests": ["zap", "sqlmap"],
            "findings": [],
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": True,
            "human_approved": True,
        }
        state.update(overrides)  # type: ignore[typeddict-item]
        return state

    def test_resolve_active_tool_selection_honors_subset(self) -> None:
        from agents.detection import _resolve_active_tool_selection

        state = self._base_state(approved_tools=["sqlmap"])
        approved, rejected = _resolve_active_tool_selection(state)
        assert approved == ["sqlmap"]
        assert rejected == ["zap"]

    def test_resolve_active_tool_selection_empty_list_rejects_all(self) -> None:
        from agents.detection import _resolve_active_tool_selection

        state = self._base_state(approved_tools=[])
        approved, rejected = _resolve_active_tool_selection(state)
        assert approved == []
        assert rejected == ["zap", "sqlmap"]

    def test_resolve_active_tool_selection_legacy_bulk_fallback(self) -> None:
        """States without `approved_tools` fall back to bulk `human_approved`."""
        from agents.detection import _resolve_active_tool_selection

        state = self._base_state(human_approved=True)
        assert "approved_tools" not in state
        approved, rejected = _resolve_active_tool_selection(state)
        assert approved == ["zap", "sqlmap"]
        assert rejected == []

        state = self._base_state(human_approved=False)
        approved, rejected = _resolve_active_tool_selection(state)
        assert approved == []
        assert rejected == ["zap", "sqlmap"]

    @pytest.mark.asyncio
    async def test_run_active_tools_only_runs_approved_sqlmap(self) -> None:
        """Approving sqlmap but rejecting zap should only invoke sqlmap."""
        from agents.detection import run_active_tools
        from tools.zap_tool import ZAPTool
        from tools.sqlmap_tool import SQLMapTool

        state = self._base_state(approved_tools=["sqlmap"])

        mock_sqlmap_result = ToolResult(
            tool_name="sqlmap",
            target="https://authorized.example.com/api?id=1",
            success=True,
            data={"findings": [], "finding_count": 0, "vulnerable": False},
        )

        with patch.object(ZAPTool, "run", AsyncMock()) as mock_zap, \
             patch.object(ZAPTool, "close", return_value=None), \
             patch.object(SQLMapTool, "run_batch", AsyncMock(return_value=mock_sqlmap_result)) as mock_sqlmap:
            findings, errors = await run_active_tools(state)

        mock_zap.assert_not_called()
        mock_sqlmap.assert_called_once()
        assert findings == []
        assert errors == {}

    @pytest.mark.asyncio
    async def test_run_active_tools_sqlmap_caps_to_ten_urls(self) -> None:
        """Only the first 10 injectable URLs are passed to sqlmap.run_batch."""
        from agents.detection import run_active_tools
        from tools.zap_tool import ZAPTool
        from tools.sqlmap_tool import SQLMapTool

        urls = [f"https://authorized.example.com/api?id={i}" for i in range(15)]
        state = self._base_state(
            approved_tools=["sqlmap"],
            recon_results={"hosts": ["authorized.example.com"], "urls": urls, "js_files": []},
        )

        captured: dict[str, Any] = {}

        async def _capture_run_batch(url_batch: list[str], scope: dict[str, Any]) -> ToolResult:
            captured["urls"] = list(url_batch)
            captured["scope"] = dict(scope)
            return ToolResult(
                tool_name="sqlmap",
                target="batch",
                success=True,
                data={"findings": [], "finding_count": 0, "urls_tested": len(url_batch)},
            )

        with patch.object(ZAPTool, "run", AsyncMock()) as mock_zap, \
             patch.object(ZAPTool, "close", return_value=None), \
             patch.object(SQLMapTool, "run_batch", AsyncMock(side_effect=_capture_run_batch)):
            findings, errors = await run_active_tools(state)

        mock_zap.assert_not_called()
        assert findings == []
        assert errors == {}
        assert len(captured["urls"]) == 10
        assert captured["urls"] == urls[:10]

    @pytest.mark.asyncio
    async def test_run_active_tools_only_runs_approved_zap(self) -> None:
        """Approving zap but rejecting sqlmap should only invoke zap."""
        from agents.detection import run_active_tools
        from tools.zap_tool import ZAPTool
        from tools.sqlmap_tool import SQLMapTool

        state = self._base_state(approved_tools=["zap"])

        mock_zap_result = ToolResult(
            tool_name="zap",
            target="https://authorized.example.com",
            success=True,
            data={"findings": [], "finding_count": 0},
        )

        with patch.object(ZAPTool, "run", AsyncMock(return_value=mock_zap_result)) as mock_zap, \
             patch.object(ZAPTool, "close", return_value=None), \
             patch.object(SQLMapTool, "run_batch", AsyncMock()) as mock_sqlmap:
            findings, errors = await run_active_tools(state)

        mock_zap.assert_called_once()
        mock_sqlmap.assert_not_called()
        assert findings == []
        assert errors == {}

    @pytest.mark.asyncio
    async def test_run_active_detection_async_reports_partial_approval_metadata(self) -> None:
        from agents.detection import run_active_detection_async

        state = self._base_state(approved_tools=["sqlmap"])

        with patch(
            "agents.detection.run_active_tools",
            AsyncMock(return_value=([], {})),
        ):
            result = await run_active_detection_async(state)

        metadata = result["detection_metadata"]
        assert metadata["active_tools_run"] is True
        assert metadata["approved_tools"] == ["sqlmap"]
        assert metadata["rejected_tools"] == ["zap"]

    @pytest.mark.asyncio
    async def test_run_active_detection_async_skips_when_all_rejected(self) -> None:
        from agents.detection import run_active_detection_async

        state = self._base_state(approved_tools=[])

        with patch(
            "agents.detection.run_active_tools",
        ) as mock_active:
            result = await run_active_detection_async(state)
            mock_active.assert_not_called()

        metadata = result["detection_metadata"]
        assert metadata["active_tools_run"] is False
        assert metadata["approved_tools"] == []
        assert metadata["rejected_tools"] == ["zap", "sqlmap"]
