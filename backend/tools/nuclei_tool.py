"""Nuclei vulnerability scanner CLI wrapper.

Nuclei is a passive scanner that uses YAML-based templates to detect
vulnerabilities. This wrapper runs nuclei against discovered hosts/URLs
from recon, using the community template set.

Security considerations:
- Rate-limited to avoid hammering targets
- Concurrency capped
- Scope re-validated before each run
- Uses JSON output for reliable parsing
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

from core.config import get_settings
from core.scope import is_target_authorized
from tools.base import (
    BaseSecurityTool,
    ScopeViolationError,
    ToolResult,
    parse_json_output,
    run_subprocess_safely,
    validate_scope,
)
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

NUCLEI_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

NUCLEI_CWE_MAP = {
    "cve": None,
    "misconfig": 16,
    "exposed-panels": 200,
    "default-logins": 798,
    "file": 538,
    "xss": 79,
    "sqli": 89,
    "ssrf": 918,
    "redirect": 601,
    "lfi": 98,
    "rfi": 98,
    "rce": 94,
    "ssti": 94,
    "xxe": 611,
    "cors": 942,
    "crlf": 93,
    "csrf": 352,
}


class NucleiInput(BaseModel):
    """Input schema for Nuclei tool with validation."""

    targets: list[str] = Field(
        ...,
        description="List of target URLs or hosts to scan",
        min_length=1,
    )
    template_tags: list[str] | None = Field(
        default=None,
        description="Template tags to filter (e.g., ['cve', 'misconfig'])",
    )
    severity_filter: list[str] | None = Field(
        default=None,
        description="Severity levels to scan for (e.g., ['high', 'critical'])",
    )
    rate_limit: int = Field(
        default=50,
        ge=1,
        le=150,
        description="Maximum requests per second",
    )
    concurrency: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum concurrent template executions",
    )

    @field_validator("targets")
    @classmethod
    def validate_targets_in_scope(cls, v: list[str]) -> list[str]:
        """Ensure all targets are within the authorized scope."""
        for target in v:
            if not is_target_authorized(target):
                raise ValueError(
                    f"Target '{target}' is not in the authorized scope. "
                    "Scan aborted for safety."
                )
        return v


class NucleiTool(BaseSecurityTool):
    """
    Nuclei vulnerability scanner wrapper.

    Runs nuclei with community templates against provided targets.
    Outputs are parsed into normalized Finding objects.
    """

    name = "nuclei"
    description = "Fast template-based vulnerability scanner"

    def __init__(self, timeout: float | None = None):
        super().__init__(timeout=timeout)
        settings = get_settings()
        self._rate_limit = getattr(settings, "nuclei_rate_limit", 50)
        self._concurrency = getattr(settings, "nuclei_concurrency", 10)

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Run nuclei against a single target.

        For batch scanning multiple targets, use run_batch().

        Args:
            target: URL or host to scan
            scope: Scope metadata with optional configuration

        Returns:
            ToolResult with parsed findings
        """
        validate_scope(target)

        binary_path = self.get_binary_path()

        rate_limit = scope.get("rate_limit", self._rate_limit)
        concurrency = scope.get("concurrency", self._concurrency)
        template_tags = scope.get("template_tags", [])
        severity_filter = scope.get("severity_filter", [])

        args = [
            "-u", target,
            "-json",
            "-silent",
            "-rl", str(rate_limit),
            "-c", str(concurrency),
            "-nc",
        ]

        if template_tags:
            args.extend(["-tags", ",".join(template_tags)])

        if severity_filter:
            args.extend(["-severity", ",".join(severity_filter)])

        logger.info(f"Running nuclei against {target} with rate_limit={rate_limit}")

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
                error=f"Nuclei timed out after {self.timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        raw_results = parse_json_output(stdout, self.name)
        findings = self._parse_findings(raw_results, target)

        if exit_code != 0:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=(
                    f"Nuclei exited with code {exit_code}"
                    + (f": {stderr.strip()}" if stderr.strip() else "")
                ),
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "raw_count": len(raw_results),
                },
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
            )

        # Non-empty stdout that yielded zero parseable records is malformed output.
        if stdout.strip() and not raw_results and not findings:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error="Nuclei produced non-empty output that could not be parsed as JSON",
                data={"findings": [], "finding_count": 0, "raw_count": 0},
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
                "raw_count": len(raw_results),
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )

    async def run_batch(
        self,
        targets: list[str],
        scope: dict[str, Any],
    ) -> ToolResult:
        """
        Run nuclei against multiple targets.

        Uses nuclei's native list input for efficiency.

        Args:
            targets: List of URLs or hosts to scan
            scope: Scope metadata with optional configuration

        Returns:
            ToolResult with aggregated findings
        """
        for target in targets:
            validate_scope(target)

        if not targets:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=True,
                data={"findings": [], "finding_count": 0},
            )

        binary_path = self.get_binary_path()

        rate_limit = scope.get("rate_limit", self._rate_limit)
        concurrency = scope.get("concurrency", self._concurrency)

        args = [
            "-json",
            "-silent",
            "-rl", str(rate_limit),
            "-c", str(concurrency),
            "-nc",
        ]

        for target in targets:
            args.extend(["-u", target])

        logger.info(f"Running nuclei batch scan against {len(targets)} targets")

        exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
            binary_path=binary_path,
            args=args,
            timeout=self.timeout * 2,
        )

        if timed_out:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error=f"Nuclei batch scan timed out",
                timed_out=True,
            )

        raw_results = parse_json_output(stdout, self.name)
        findings: list[Finding] = []
        for result in raw_results:
            matched_at = result.get("matched-at", result.get("host", ""))
            findings.extend(self._parse_findings([result], matched_at))

        if exit_code != 0:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error=(
                    f"Nuclei batch exited with code {exit_code}"
                    + (f": {stderr.strip()}" if stderr.strip() else "")
                ),
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "targets_scanned": len(targets),
                },
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
            )

        if stdout.strip() and not raw_results and not findings:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error="Nuclei batch produced non-empty output that could not be parsed as JSON",
                data={
                    "findings": [],
                    "finding_count": 0,
                    "targets_scanned": len(targets),
                },
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=False,
            )

        return ToolResult(
            tool_name=self.name,
            target="batch",
            success=True,
            data={
                "findings": [f.model_dump_for_state() for f in findings],
                "finding_count": len(findings),
                "targets_scanned": len(targets),
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )

    def _parse_findings(
        self,
        raw_results: list[dict[str, Any]],
        default_target: str,
    ) -> list[Finding]:
        """Parse nuclei JSON output into normalized Finding objects."""
        findings: list[Finding] = []

        for result in raw_results:
            try:
                template_info = result.get("info", {})
                template_id = result.get("template-id", "unknown")
                severity_str = template_info.get("severity", "info")
                severity = NUCLEI_SEVERITY_MAP.get(severity_str.lower(), Severity.INFO)

                matched_at = result.get("matched-at", default_target)
                matcher_name = result.get("matcher-name", "")
                extracted = result.get("extracted-results", [])

                template_tags = template_info.get("tags", [])
                cwe_id = None
                for tag in template_tags:
                    if tag in NUCLEI_CWE_MAP:
                        cwe_id = NUCLEI_CWE_MAP[tag]
                        break

                cwe_from_classification = template_info.get("classification", {}).get("cwe-id")
                if cwe_from_classification:
                    if isinstance(cwe_from_classification, list):
                        cwe_id = cwe_from_classification[0] if cwe_from_classification else cwe_id
                    else:
                        cwe_id = cwe_from_classification

                evidence_parts = []
                if matcher_name:
                    evidence_parts.append(f"Matcher: {matcher_name}")
                if extracted:
                    evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:3])}")

                finding = Finding(
                    tool="nuclei",
                    type=template_id,
                    url=matched_at,
                    severity=severity,
                    description=template_info.get("description", template_info.get("name", template_id)),
                    evidence="; ".join(evidence_parts) if evidence_parts else None,
                    cwe_id=cwe_id,
                    raw_data=result,
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse nuclei result: {e}")
                continue

        return findings
