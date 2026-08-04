"""Nuclei vulnerability scanner CLI wrapper.

Nuclei uses YAML-based templates to detect vulnerabilities. With -dast enabled
it also runs fuzzing templates for XSS, SQLi, SSRF, and related OWASP A03/A10
checks against discovered hosts/URLs from recon.

Security considerations:
- Rate-limited to avoid hammering targets
- Concurrency capped
- Scope re-validated before each run
- Uses JSONL output for reliable parsing
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

from core.config import get_settings
from core.owasp import classify_finding_owasp
from core.scope import is_target_authorized
from tools.base import (
    BaseSecurityTool,
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


def _split_csv(value: str | list[str] | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


class NucleiInput(BaseModel):
    """Input schema for Nuclei tool with validation."""

    targets: list[str] = Field(
        ...,
        description="List of target URLs or hosts to scan",
        min_length=1,
    )
    template_tags: list[str] | None = Field(
        default=None,
        description="Template tags to filter (e.g., ['xss', 'sqli'])",
    )
    severity_filter: list[str] | None = Field(
        default=None,
        description="Severity levels to scan for (e.g., ['high', 'critical'])",
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
        settings = get_settings()
        super().__init__(
            timeout=timeout if timeout is not None else settings.nuclei_timeout
        )
        self._rate_limit = settings.nuclei_rate_limit
        self._concurrency = settings.nuclei_concurrency
        self._enable_dast = settings.nuclei_enable_dast
        self._default_tags = _split_csv(settings.nuclei_template_tags)
        self._default_severity = _split_csv(settings.nuclei_severity_filter)

    def _build_scan_args(self, scope: dict[str, Any]) -> list[str]:
        """Build shared nuclei CLI flags (jsonl, rate, dast, tags, severity)."""
        rate_limit = scope.get("rate_limit", self._rate_limit)
        concurrency = scope.get("concurrency", self._concurrency)
        template_tags = scope.get("template_tags", self._default_tags) or []
        if isinstance(template_tags, str):
            template_tags = _split_csv(template_tags)
        severity_filter = scope.get("severity_filter", self._default_severity) or []
        if isinstance(severity_filter, str):
            severity_filter = _split_csv(severity_filter)
        dast = scope.get("dast", self._enable_dast)

        args = [
            # nuclei v3 removed -json; -jsonl (-j) is the JSONL stdout format.
            "-jsonl",
            "-silent",
            "-rl",
            str(rate_limit),
            "-c",
            str(concurrency),
            "-nc",
        ]
        if dast:
            # Enables DAST/fuzzing templates (XSS, SQLi, SSRF, etc.).
            args.append("-dast")
        if template_tags:
            args.extend(["-tags", ",".join(template_tags)])
        if severity_filter:
            args.extend(["-severity", ",".join(severity_filter)])
        return args

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """Run nuclei against a single target."""
        validate_scope(target)

        binary_path = self.get_binary_path()
        args = self._build_scan_args(scope)
        args.extend(["-u", target])

        logger.info(
            "Running nuclei against %s (dast=%s, tags=%s)",
            target,
            "-dast" in args,
            scope.get("template_tags") or self._default_tags or "all",
        )

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
            detail = (stderr or stdout or "").strip()
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=(
                    f"Nuclei exited with code {exit_code}"
                    + (f": {detail[:500]}" if detail else "")
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

        if stdout.strip() and not raw_results and not findings:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error="Nuclei produced non-empty output that could not be parsed as JSON",
                data={
                    "findings": [],
                    "finding_count": 0,
                    "raw_count": 0,
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
        """Run nuclei against multiple targets (honors dast/tags/severity scope)."""
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
        args = self._build_scan_args(scope)
        for target in targets:
            args.extend(["-u", target])

        logger.info(
            "Running nuclei batch against %s targets (dast=%s, tags=%s)",
            len(targets),
            "-dast" in args,
            scope.get("template_tags") or self._default_tags or "all",
        )

        exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
            binary_path=binary_path,
            args=args,
            timeout=self.timeout,
        )

        if timed_out:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error=f"Nuclei batch scan timed out after {self.timeout}s",
                timed_out=True,
            )

        raw_results = parse_json_output(stdout, self.name)
        findings: list[Finding] = []
        for result in raw_results:
            matched_at = result.get("matched-at", result.get("host", ""))
            findings.extend(self._parse_findings([result], matched_at))

        if exit_code != 0:
            detail = (stderr or stdout or "").strip()
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=False,
                error=(
                    f"Nuclei batch exited with code {exit_code}"
                    + (f": {detail[:500]}" if detail else "")
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
                if isinstance(template_tags, str):
                    template_tags = [template_tags]
                cwe_id: int | None = None
                for tag in template_tags:
                    if tag in NUCLEI_CWE_MAP and NUCLEI_CWE_MAP[tag] is not None:
                        cwe_id = NUCLEI_CWE_MAP[tag]
                        break

                cwe_from_classification = template_info.get("classification", {}).get(
                    "cwe-id"
                )
                if cwe_from_classification:
                    raw_cwe = (
                        cwe_from_classification[0]
                        if isinstance(cwe_from_classification, list)
                        and cwe_from_classification
                        else cwe_from_classification
                    )
                    if isinstance(raw_cwe, str) and raw_cwe.upper().startswith("CWE-"):
                        try:
                            cwe_id = int(raw_cwe.split("-", 1)[1])
                        except ValueError:
                            pass
                    elif isinstance(raw_cwe, int):
                        cwe_id = raw_cwe

                evidence_parts = []
                if matcher_name:
                    evidence_parts.append(f"Matcher: {matcher_name}")
                if extracted:
                    evidence_parts.append(
                        f"Extracted: {', '.join(str(e) for e in extracted[:3])}"
                    )

                owasp_id = classify_finding_owasp(
                    finding_type=template_id,
                    tool="nuclei",
                    tags=[str(t) for t in template_tags],
                    cwe_id=cwe_id,
                )
                raw = dict(result)
                if owasp_id:
                    raw["owasp"] = owasp_id

                finding = Finding(
                    tool="nuclei",
                    type=template_id,
                    url=matched_at,
                    severity=severity,
                    description=template_info.get(
                        "description", template_info.get("name", template_id)
                    ),
                    evidence="; ".join(evidence_parts) if evidence_parts else None,
                    cwe_id=cwe_id,
                    raw_data=raw,
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse nuclei result: {e}")
                continue

        return findings
