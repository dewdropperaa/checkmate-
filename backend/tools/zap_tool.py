"""OWASP ZAP active scanner integration via REST API.

ZAP is an active scanner that performs intrusive security testing.
This wrapper drives ZAP via its REST API (assuming ZAP daemon is running).

ACTIVE TOOL - REQUIRES HUMAN APPROVAL BEFORE EXECUTION

Security considerations:
- Active scanner - performs intrusive tests that may modify application state
- MUST only run with explicit human approval
- Scope re-validated before each scan
- Polls for completion and retrieves alerts
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

from core.config import get_settings
from core.scope import is_target_authorized
from tools.base import ScopeViolationError, ToolResult, validate_scope
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

ZAP_RISK_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

ZAP_CWE_MAP = {
    "Cross Site Scripting": 79,
    "SQL Injection": 89,
    "Path Traversal": 22,
    "Remote File Inclusion": 98,
    "Command Injection": 78,
    "LDAP Injection": 90,
    "XML External Entity": 611,
    "CSRF": 352,
    "Clickjacking": 1021,
    "CORS": 942,
    "HSTS": 319,
    "CSP": 693,
    "Cookie": 614,
    "X-Frame-Options": 1021,
    "X-Content-Type-Options": 16,
}


class ZAPInput(BaseModel):
    """Input schema for ZAP tool with validation."""

    target: str = Field(
        ...,
        description="Target URL to scan (must be a full URL)",
    )
    scan_policy: str | None = Field(
        default=None,
        description="Optional scan policy name to use",
    )
    ajax_spider: bool = Field(
        default=False,
        description="Whether to use AJAX spider before active scan",
    )

    @field_validator("target")
    @classmethod
    def validate_target_in_scope(cls, v: str) -> str:
        """Ensure target is within the authorized scope."""
        parsed = urlparse(v)
        host = parsed.hostname or ""
        if not is_target_authorized(host):
            raise ValueError(
                f"Target '{v}' is not in the authorized scope. "
                "Scan aborted for safety."
            )
        return v


class ZAPTool:
    """
    OWASP ZAP active scanner wrapper.

    Drives ZAP via REST API to perform active vulnerability scanning.

    ACTIVE TOOL - Requires human approval before execution.
    """

    name = "zap"
    description = "OWASP ZAP active vulnerability scanner"
    requires_approval = True

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 600.0,
        poll_interval: float = 5.0,
    ):
        settings = get_settings()
        self.api_url = api_url or getattr(settings, "zap_api_url", "http://zap:8080")
        self.api_key = api_key or getattr(settings, "zap_api_key", "")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                timeout=60.0,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _api_call(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an API call to ZAP."""
        client = await self._get_client()
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key

        response = await client.get(endpoint, params=params)
        response.raise_for_status()
        return response.json()

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Run ZAP active scan against a target.

        This method:
        1. Opens the target URL
        2. Runs spider to discover pages
        3. Runs active scan
        4. Waits for completion
        5. Retrieves and parses alerts

        Args:
            target: Target URL to scan
            scope: Scope metadata with optional configuration

        Returns:
            ToolResult with vulnerability findings
        """
        parsed = urlparse(target)
        host = parsed.hostname or ""
        validate_scope(host)

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        scan_policy = scope.get("scan_policy")
        ajax_spider = scope.get("ajax_spider", False)

        try:
            logger.info(f"Starting ZAP scan against {target}")

            await self._api_call("/JSON/core/action/accessUrl/", {"url": target})

            logger.info("Running ZAP spider...")
            spider_result = await self._api_call(
                "/JSON/spider/action/scan/",
                {"url": target, "maxChildren": "100"},
            )
            spider_id = spider_result.get("scan", "0")

            await self._wait_for_spider(spider_id)

            if ajax_spider:
                logger.info("Running ZAP AJAX spider...")
                await self._api_call("/JSON/ajaxSpider/action/scan/", {"url": target})
                await self._wait_for_ajax_spider()

            logger.info("Running ZAP active scan...")
            scan_params: dict[str, Any] = {"url": target}
            if scan_policy:
                scan_params["scanPolicyName"] = scan_policy

            scan_result = await self._api_call(
                "/JSON/ascan/action/scan/",
                scan_params,
            )
            scan_id = scan_result.get("scan", "0")

            await self._wait_for_active_scan(scan_id)

            logger.info("Retrieving ZAP alerts...")
            alerts = await self._get_alerts(target)
            findings = self._parse_alerts(alerts, target)

            return ToolResult(
                tool_name=self.name,
                target=target,
                success=True,
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "alerts_count": len(alerts),
                    "scan_id": scan_id,
                },
            )

        except httpx.HTTPError as e:
            logger.error(f"ZAP API error: {e}")
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"ZAP API error: {str(e)}",
            )
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"ZAP scan timed out after {self.timeout}s",
                timed_out=True,
            )

    async def _wait_for_spider(self, spider_id: str) -> None:
        """Wait for spider to complete."""
        elapsed = 0.0
        while elapsed < self.timeout:
            result = await self._api_call(
                "/JSON/spider/view/status/",
                {"scanId": spider_id},
            )
            status = int(result.get("status", "100"))
            if status >= 100:
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise asyncio.TimeoutError("Spider timed out")

    async def _wait_for_ajax_spider(self) -> None:
        """Wait for AJAX spider to complete."""
        elapsed = 0.0
        while elapsed < self.timeout:
            result = await self._api_call("/JSON/ajaxSpider/view/status/")
            status = result.get("status", "stopped")
            if status == "stopped":
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise asyncio.TimeoutError("AJAX Spider timed out")

    async def _wait_for_active_scan(self, scan_id: str) -> None:
        """Wait for active scan to complete."""
        elapsed = 0.0
        while elapsed < self.timeout:
            result = await self._api_call(
                "/JSON/ascan/view/status/",
                {"scanId": scan_id},
            )
            status = int(result.get("status", "100"))
            logger.debug(f"ZAP active scan progress: {status}%")
            if status >= 100:
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise asyncio.TimeoutError("Active scan timed out")

    async def _get_alerts(self, target: str) -> list[dict[str, Any]]:
        """Retrieve alerts for the target."""
        result = await self._api_call(
            "/JSON/core/view/alerts/",
            {"baseurl": target},
        )
        return result.get("alerts", [])

    def _parse_alerts(
        self,
        alerts: list[dict[str, Any]],
        target: str,
    ) -> list[Finding]:
        """Parse ZAP alerts into normalized Finding objects."""
        findings: list[Finding] = []

        for alert in alerts:
            try:
                risk = str(alert.get("risk", "0"))
                severity = ZAP_RISK_MAP.get(risk, Severity.INFO)

                alert_name = alert.get("alert", "Unknown")
                cwe_id = alert.get("cweid")
                if cwe_id:
                    try:
                        cwe_id = int(cwe_id)
                    except (ValueError, TypeError):
                        cwe_id = None

                if not cwe_id:
                    for pattern, cwe in ZAP_CWE_MAP.items():
                        if pattern.lower() in alert_name.lower():
                            cwe_id = cwe
                            break

                evidence = alert.get("evidence", "")
                if not evidence:
                    evidence = alert.get("other", "")

                finding = Finding(
                    tool="zap",
                    type=f"zap-{alert.get('pluginId', 'unknown')}",
                    url=alert.get("url", target),
                    param=alert.get("param"),
                    severity=severity,
                    description=f"{alert_name}: {alert.get('description', '')}",
                    evidence=evidence[:500] if evidence else None,
                    cwe_id=cwe_id,
                    raw_data=alert,
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse ZAP alert: {e}")
                continue

        return findings
