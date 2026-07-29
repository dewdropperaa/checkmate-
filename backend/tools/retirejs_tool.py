"""retire.js JavaScript dependency vulnerability scanner wrapper.

retire.js scans JavaScript files for known vulnerable library versions.
It checks against a vulnerability database maintained by the project.

Security considerations:
- Passive scanner - analyzes JS files from recon crawl
- Scope re-validated before each run
- Uses JSON output for reliable parsing
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from core.scope import is_target_authorized
from tools.base import (
    BaseSecurityTool,
    ToolResult,
    run_subprocess_safely,
    validate_scope,
)
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

RETIREJS_SEVERITY_MAP = {
    "none": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class RetireJSInput(BaseModel):
    """Input schema for retire.js tool with validation."""

    js_urls: list[str] = Field(
        ...,
        description="List of JavaScript file URLs to scan",
        min_length=1,
    )

    @field_validator("js_urls")
    @classmethod
    def validate_urls_in_scope(cls, v: list[str]) -> list[str]:
        """Ensure all URLs are within the authorized scope."""
        for url in v:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.path.split("/")[0]
            if not is_target_authorized(host):
                raise ValueError(
                    f"URL '{url}' is not in the authorized scope. "
                    "Scan aborted for safety."
                )
        return v


class RetireJSTool(BaseSecurityTool):
    """
    retire.js JavaScript vulnerability scanner wrapper.

    Scans JavaScript files for known vulnerable library versions.
    """

    name = "retire"
    description = "JavaScript library vulnerability scanner"

    def __init__(self, timeout: float | None = None):
        super().__init__(timeout=timeout or 180.0)

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Run retire.js against a JavaScript URL.

        Args:
            target: JavaScript file URL to scan
            scope: Scope metadata

        Returns:
            ToolResult with vulnerability findings
        """
        parsed = urlparse(target)
        host = parsed.hostname or ""
        validate_scope(host)

        binary_path = self.get_binary_path()

        args = [
            "--jsuri", target,
            "--outputformat", "json",
        ]

        logger.info(f"Running retire.js against {target}")

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
                error=f"retire.js timed out after {self.timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        findings = self._parse_findings(stdout, target)

        # retire.js: 0 = clean, 13 = vulnerabilities found. Anything else is failure.
        if exit_code not in (0, 13):
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=(
                    f"retire.js exited with code {exit_code}"
                    + (f": {stderr.strip()}" if stderr.strip() else "")
                ),
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "js_url": target,
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
                "js_url": target,
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )

    async def run_batch(
        self,
        js_urls: list[str],
        scope: dict[str, Any],
    ) -> ToolResult:
        """
        Run retire.js against multiple JavaScript URLs.

        Args:
            js_urls: List of JavaScript file URLs to scan
            scope: Scope metadata

        Returns:
            ToolResult with aggregated findings
        """
        for url in js_urls:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            validate_scope(host)

        if not js_urls:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=True,
                data={"findings": [], "finding_count": 0},
            )

        binary_path = self.get_binary_path()

        all_findings: list[Finding] = []
        child_failures: list[str] = []
        urls_scanned = 0

        for js_url in js_urls:
            args = [
                "--jsuri", js_url,
                "--outputformat", "json",
            ]

            logger.info(f"Running retire.js against {js_url}")

            exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
                binary_path=binary_path,
                args=args,
                timeout=self.timeout,
            )

            if timed_out:
                child_failures.append(f"{js_url}: timed out")
                continue

            if exit_code not in (0, 13):
                child_failures.append(f"{js_url}: exit {exit_code}")
                continue

            findings = self._parse_findings(stdout, js_url)
            all_findings.extend(findings)
            urls_scanned += 1

        if child_failures and urls_scanned == 0:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error=(
                    "retire.js failed for all URLs: "
                    + "; ".join(child_failures[:5])
                ),
                data={
                    "findings": [],
                    "finding_count": 0,
                    "js_urls_scanned": 0,
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
                "js_urls_scanned": urls_scanned,
                "child_failures": child_failures or None,
            },
            error=(
                f"retire.js partial failures: {len(child_failures)} URL(s)"
                if child_failures
                else None
            ),
        )

    def _parse_findings(self, output: str, js_url: str) -> list[Finding]:
        """Parse retire.js JSON output into normalized Finding objects."""
        findings: list[Finding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.warning(f"Could not parse retire.js JSON output for {js_url}")
            return findings

        results = data if isinstance(data, list) else data.get("data", [])

        for result in results:
            if not isinstance(result, dict):
                continue

            file_path = result.get("file", js_url)
            vulnerabilities = result.get("results", [])

            for vuln_group in vulnerabilities:
                if not isinstance(vuln_group, dict):
                    continue

                component = vuln_group.get("component", "unknown")
                version = vuln_group.get("version", "unknown")
                vulns = vuln_group.get("vulnerabilities", [])

                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        continue

                    severity_str = vuln.get("severity", "medium")
                    severity = RETIREJS_SEVERITY_MAP.get(
                        severity_str.lower(), Severity.MEDIUM
                    )

                    identifiers = vuln.get("identifiers", {})
                    cve_list = identifiers.get("CVE", [])
                    cve_str = ", ".join(cve_list) if cve_list else None

                    summary = vuln.get("info", [])
                    info_text = summary[0] if summary else f"Vulnerable {component}"

                    cwe_id = None
                    if identifiers.get("CWE"):
                        cwe_entries = identifiers["CWE"]
                        if cwe_entries:
                            try:
                                cwe_id = int(str(cwe_entries[0]).replace("CWE-", ""))
                            except (ValueError, TypeError):
                                pass

                    finding = Finding(
                        tool="retire.js",
                        type=f"vulnerable-js-{component}",
                        url=file_path if file_path.startswith("http") else js_url,
                        severity=severity,
                        description=f"{component} {version}: {info_text}",
                        evidence=f"CVE: {cve_str}" if cve_str else f"Version: {version}",
                        cwe_id=cwe_id,
                        raw_data=vuln,
                    )
                    findings.append(finding)

        return findings
