"""retire.js JavaScript dependency vulnerability scanner wrapper.

retire.js scans JavaScript files for known vulnerable library versions.
It checks against a vulnerability database maintained by the project.

Security considerations:
- Passive scanner - analyzes JS files from recon crawl
- Scope re-validated before each run
- Remote URLs are fetched via the SSRF-safe client into a temp file, then
  scanned with ``--path`` (retire 5.x removed ``--jsuri``)
- Uses JSON output for reliable parsing
"""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from core.scope import is_target_authorized
from core.ssrf import SSRFError, create_safe_async_client, validate_url
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

# Cap individual JS downloads so a huge asset cannot fill the disk.
_MAX_JS_BYTES = 5 * 1024 * 1024


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

    async def _download_js(self, js_url: str) -> bytes:
        """Fetch a JS URL through the SSRF-safe client."""
        validate_url(js_url, resolve_dns=True)
        async with create_safe_async_client(
            timeout=min(self.timeout, 60.0),
            verify=False,
            max_response_bytes=_MAX_JS_BYTES,
        ) as client:
            response = await client.get(js_url)
            response.raise_for_status()
            return response.content

    async def _scan_js_url(
        self,
        js_url: str,
        *,
        binary_path: Path,
    ) -> tuple[list[Finding], str | None]:
        """Download one JS URL and run retire --path against a temp copy.

        Returns (findings, error_detail). error_detail is None on success.
        """
        try:
            content = await self._download_js(js_url)
        except SSRFError as exc:
            return [], f"{js_url}: ssrf blocked: {exc}"
        except Exception as exc:
            detail = str(exc).strip() or repr(exc)
            return [], f"{js_url}: download failed: {type(exc).__name__}: {detail}"

        if not content:
            return [], f"{js_url}: empty response body"

        digest = hashlib.sha256(js_url.encode("utf-8")).hexdigest()[:16]
        with tempfile.TemporaryDirectory(prefix="retirejs-") as tmp:
            js_path = Path(tmp) / f"{digest}.js"
            js_path.write_bytes(content)

            args = [
                "--path",
                str(js_path),
                "--outputformat",
                "json",
            ]
            logger.info("Running retire.js against %s (local path scan)", js_url)
            exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
                binary_path=binary_path,
                args=args,
                timeout=self.timeout,
            )

            if timed_out:
                return [], f"{js_url}: timed out"

            # retire.js: 0 = clean, 13 = vulnerabilities found. Anything else is failure.
            if exit_code not in (0, 13):
                err_tail = (stderr or stdout or "").strip().replace("\n", " ")[:200]
                detail = f"{js_url}: exit {exit_code}"
                if err_tail:
                    detail = f"{detail}: {err_tail}"
                return [], detail

            return self._parse_findings(stdout, js_url), None

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
        findings, error = await self._scan_js_url(target, binary_path=binary_path)

        if error:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=error if error.startswith("retire.js") else f"retire.js failed: {error}",
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "js_url": target,
                },
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
            findings, error = await self._scan_js_url(js_url, binary_path=binary_path)
            if error:
                child_failures.append(error)
                logger.warning("retire.js failed for %s: %s", js_url, error)
                continue
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
                        url=file_path if str(file_path).startswith("http") else js_url,
                        severity=severity,
                        description=f"{component} {version}: {info_text}",
                        evidence=f"CVE: {cve_str}" if cve_str else f"Version: {version}",
                        cwe_id=cwe_id,
                        raw_data=vuln,
                    )
                    findings.append(finding)

        return findings
