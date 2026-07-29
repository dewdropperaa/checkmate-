"""SQLMap SQL injection scanner wrapper.

SQLMap is an active scanner that tests for SQL injection vulnerabilities.
It ONLY runs against specific parameterized URLs flagged by recon as candidates.

ACTIVE TOOL - REQUIRES HUMAN APPROVAL BEFORE EXECUTION

Security considerations:
- Active scanner - performs intrusive tests that may modify database state
- MUST only run with explicit human approval
- NEVER runs against bare domains - only parameterized URLs
- Uses --batch mode to avoid interactive prompts
- Strict --level and --risk caps to limit aggressive testing
- Scope re-validated before each scan
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field, field_validator

from core.config import get_settings
from core.scope import is_target_authorized
from tools.base import (
    BaseSecurityTool,
    ToolResult,
    run_subprocess_safely,
    validate_scope,
)
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

MAX_LEVEL = 2
MAX_RISK = 2


class SQLMapInput(BaseModel):
    """Input schema for SQLMap tool with validation."""

    url: str = Field(
        ...,
        description="Parameterized URL to test (must contain query parameters)",
    )
    level: int = Field(
        default=1,
        ge=1,
        le=MAX_LEVEL,
        description=f"Testing level (1-{MAX_LEVEL})",
    )
    risk: int = Field(
        default=1,
        ge=1,
        le=MAX_RISK,
        description=f"Risk level (1-{MAX_RISK})",
    )
    specific_params: list[str] | None = Field(
        default=None,
        description="Specific parameters to test (tests all if not specified)",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL is in scope and has parameters."""
        parsed = urlparse(v)
        host = parsed.hostname or ""

        if not is_target_authorized(host):
            raise ValueError(
                f"URL '{v}' is not in the authorized scope. "
                "Scan aborted for safety."
            )

        if not parsed.query:
            raise ValueError(
                "SQLMap requires a parameterized URL with query parameters. "
                "Bare domains are not allowed for safety reasons."
            )

        return v

    @field_validator("level")
    @classmethod
    def cap_level(cls, v: int) -> int:
        """Enforce maximum level cap."""
        if v > MAX_LEVEL:
            logger.warning(f"SQLMap level capped from {v} to {MAX_LEVEL}")
            return MAX_LEVEL
        return v

    @field_validator("risk")
    @classmethod
    def cap_risk(cls, v: int) -> int:
        """Enforce maximum risk cap."""
        if v > MAX_RISK:
            logger.warning(f"SQLMap risk capped from {v} to {MAX_RISK}")
            return MAX_RISK
        return v


class SQLMapTool(BaseSecurityTool):
    """
    SQLMap SQL injection scanner wrapper.

    Tests for SQL injection vulnerabilities in parameterized URLs.

    ACTIVE TOOL - Requires human approval before execution.
    """

    name = "sqlmap"
    description = "SQL injection vulnerability scanner"
    requires_approval = True

    def __init__(self, timeout: float | None = None):
        super().__init__(timeout=timeout or 300.0)
        self._max_level = MAX_LEVEL
        self._max_risk = MAX_RISK

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Run SQLMap against a parameterized URL.

        Args:
            target: Parameterized URL to test (must contain query parameters)
            scope: Scope metadata with optional configuration

        Returns:
            ToolResult with SQL injection findings
        """
        parsed = urlparse(target)
        host = parsed.hostname or ""
        validate_scope(host)

        if not parsed.query:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error="SQLMap requires a parameterized URL. Bare domains are not allowed.",
            )

        binary_path = self.get_binary_path()

        level = min(scope.get("level", 1), self._max_level)
        risk = min(scope.get("risk", 1), self._max_risk)
        specific_params = scope.get("specific_params")

        args = [
            "-u", target,
            "--batch",
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir=/tmp/sqlmap-output",
            "--forms",
            "--smart",
            "--threads=1",
        ]

        if specific_params:
            args.extend(["-p", ",".join(specific_params)])

        logger.info(f"Running SQLMap against {target} (level={level}, risk={risk})")

        exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
            binary_path=binary_path,
            args=args,
            timeout=self.timeout,
        )

        if timed_out:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"SQLMap timed out after {self.timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        findings = self._parse_output(stdout, stderr, target)

        if exit_code != 0 and not findings:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=(
                    f"SQLMap exited with code {exit_code}"
                    + (f": {stderr.strip()[:500]}" if stderr.strip() else "")
                ),
                data={
                    "findings": [],
                    "finding_count": 0,
                    "level": level,
                    "risk": risk,
                    "vulnerable": False,
                },
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
            )

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            data={
                "findings": [f.model_dump_for_state() for f in findings],
                "finding_count": len(findings),
                "level": level,
                "risk": risk,
                "vulnerable": len(findings) > 0,
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
            error=(
                f"SQLMap exited with code {exit_code} but reported findings"
                if exit_code != 0
                else None
            ),
        )

    async def run_batch(
        self,
        urls: list[str],
        scope: dict[str, Any],
    ) -> ToolResult:
        """
        Run SQLMap against multiple parameterized URLs.

        Args:
            urls: List of parameterized URLs to test
            scope: Scope metadata

        Returns:
            ToolResult with aggregated findings
        """
        validated_urls = []
        for url in urls:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            validate_scope(host)

            if parsed.query:
                validated_urls.append(url)
            else:
                logger.warning(f"Skipping {url} - no query parameters")

        if not validated_urls:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=True,
                data={
                    "findings": [],
                    "finding_count": 0,
                    "message": "No parameterized URLs to test",
                },
            )

        all_findings: list[Finding] = []
        vulnerable_urls: list[str] = []
        child_failures: list[str] = []
        urls_ok = 0

        for url in validated_urls:
            result = await self.run(url, scope)
            if result.success and result.data:
                urls_ok += 1
                findings_data = result.data.get("findings", [])
                for fd in findings_data:
                    all_findings.append(Finding(**fd))
                if result.data.get("vulnerable"):
                    vulnerable_urls.append(url)
            else:
                child_failures.append(
                    f"{url}: {result.error or f'exit {result.exit_code}'}"
                )

        if child_failures and urls_ok == 0:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error=(
                    "SQLMap failed for all URLs: "
                    + "; ".join(child_failures[:5])
                ),
                data={
                    "findings": [],
                    "finding_count": 0,
                    "urls_tested": len(validated_urls),
                    "vulnerable_urls": [],
                    "child_failures": child_failures,
                },
            )

        return ToolResult(
            tool_name=self.name,
            target="batch",
            success=True,
            data={
                "findings": [f.model_dump_for_state() for f in all_findings],
                "finding_count": len(all_findings),
                "urls_tested": urls_ok,
                "vulnerable_urls": vulnerable_urls,
                "child_failures": child_failures or None,
            },
            error=(
                f"SQLMap partial failures: {len(child_failures)} URL(s)"
                if child_failures
                else None
            ),
        )

    def _parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
    ) -> list[Finding]:
        """Parse SQLMap output into normalized Finding objects."""
        findings: list[Finding] = []
        combined_output = f"{stdout}\n{stderr}"

        injectable_param_pattern = r"Parameter:\s*(\S+)\s*\(([^)]+)\)"
        injectable_matches = re.findall(injectable_param_pattern, combined_output)

        for param_name, injection_types in injectable_matches:
            types_list = [t.strip() for t in injection_types.split(",")]

            for inj_type in types_list:
                severity = self._get_severity_for_injection_type(inj_type)

                finding = Finding(
                    tool="sqlmap",
                    type="sqli",
                    url=target,
                    param=param_name,
                    severity=severity,
                    description=f"SQL Injection vulnerability ({inj_type}) in parameter '{param_name}'",
                    evidence=f"Injection type: {inj_type}",
                    cwe_id=89,
                    raw_data={"param": param_name, "type": inj_type},
                )
                findings.append(finding)

        vulnerable_pattern = r"(GET|POST)\s+parameter\s+'([^']+)'\s+is\s+vulnerable"
        vulnerable_matches = re.findall(vulnerable_pattern, combined_output)

        found_params = {f.param for f in findings}
        for method, param_name in vulnerable_matches:
            if param_name not in found_params:
                finding = Finding(
                    tool="sqlmap",
                    type="sqli",
                    url=target,
                    param=param_name,
                    severity=Severity.HIGH,
                    description=f"SQL Injection vulnerability in {method} parameter '{param_name}'",
                    evidence=f"Method: {method}",
                    cwe_id=89,
                    raw_data={"param": param_name, "method": method},
                )
                findings.append(finding)

        dbms_pattern = r"back-end DBMS:\s*(.+)"
        dbms_match = re.search(dbms_pattern, combined_output)
        if dbms_match and findings:
            dbms = dbms_match.group(1).strip()
            for finding in findings:
                finding.raw_data["dbms"] = dbms

        return findings

    def _get_severity_for_injection_type(self, injection_type: str) -> Severity:
        """Map injection type to severity."""
        high_severity_types = [
            "stacked queries",
            "time-based blind",
            "UNION query",
            "error-based",
        ]

        injection_lower = injection_type.lower()
        for high_type in high_severity_types:
            if high_type.lower() in injection_lower:
                return Severity.CRITICAL

        if "boolean-based blind" in injection_lower:
            return Severity.HIGH

        return Severity.HIGH


def _normalize_recon_url(entry: Any) -> str | None:
    """Extract a URL string from a recon urls/endpoints entry."""
    if isinstance(entry, str):
        url = entry.strip()
        return url or None
    if isinstance(entry, dict):
        url = entry.get("url")
        if isinstance(url, str):
            url = url.strip()
            return url or None
    return None


def find_injectable_urls(
    recon_results: dict[str, Any],
) -> list[str]:
    """
    Extract parameterized URLs from recon results that are candidates for SQLi testing.

    Args:
        recon_results: Results from the recon phase

    Returns:
        List of URLs with query parameters suitable for SQLMap testing
    """
    urls = recon_results.get("urls", []) or []
    endpoints = recon_results.get("endpoints", []) or []

    # Endpoints are dicts ({url, method, ...}); urls are usually strings.
    all_urls: list[str] = []
    seen_urls: set[str] = set()
    for entry in list(urls) + list(endpoints):
        url = _normalize_recon_url(entry)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        all_urls.append(url)

    injectable_candidates: list[str] = []
    seen_injectable: set[str] = set()

    sqli_indicators = [
        r"\bid=\d+",
        r"\buser[_-]?id=",
        r"\buserid=",
        r"\buser=",
        r"\bproduct[_-]?id=",
        r"\bitem[_-]?id=",
        r"\bpage=",
        r"\bsearch=",
        r"\bquery=",
        r"\bq=",
        r"\bcat(egory)?=",
        r"\bsort=",
        r"\border=",
        r"\bfilter=",
        r"\baction=",
    ]

    for url in all_urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue

        for pattern in sqli_indicators:
            if re.search(pattern, parsed.query, re.IGNORECASE):
                if url not in seen_injectable:
                    seen_injectable.add(url)
                    injectable_candidates.append(url)
                break

    return injectable_candidates
