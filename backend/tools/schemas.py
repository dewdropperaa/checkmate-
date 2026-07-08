"""Common schemas for security tool findings."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Severity levels for security findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """
    Normalized finding schema for all detection tools.

    All tools must convert their native output into this format
    for consistent reporting and deduplication.
    """

    tool: str = Field(..., description="Name of the tool that produced this finding")
    type: str = Field(..., description="Finding type/category (e.g., 'missing-header', 'sqli')")
    url: str = Field(..., description="URL where the vulnerability was found")
    param: str | None = Field(default=None, description="Affected parameter, if applicable")
    severity: Severity = Field(..., description="Finding severity level")
    description: str = Field(..., description="Human-readable description of the finding")
    evidence: str | None = Field(default=None, description="Evidence supporting the finding")
    cwe_id: int | None = Field(default=None, description="CWE ID if applicable")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence the finding is a true positive (1.0 = unverified default)",
    )
    verification: dict[str, Any] | None = Field(
        default=None,
        description="Corroboration metadata from the verification step, if run",
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Original tool output for reference",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Severity:
        """Normalize severity strings from various tool formats."""
        if isinstance(v, Severity):
            return v

        severity_map = {
            "informational": Severity.INFO,
            "info": Severity.INFO,
            "information": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "moderate": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
            "severe": Severity.CRITICAL,
        }

        normalized = str(v).lower().strip()
        if normalized in severity_map:
            return severity_map[normalized]

        return Severity.INFO

    def dedup_key(self) -> tuple[str, str]:
        """Return the key used for deduplication: (url, type)."""
        return (self.url, self.type)

    def model_dump_for_state(self) -> dict[str, Any]:
        """Convert to dict suitable for ScanState.findings."""
        data = self.model_dump(mode="json")
        data["severity"] = self.severity.value
        return data


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate findings by (url, type) key.

    When multiple tools report the same issue, keep the finding with
    the highest severity. If severities are equal, keep the first one.

    Args:
        findings: List of findings to deduplicate

    Returns:
        Deduplicated list of findings
    """
    severity_order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]

    seen: dict[tuple[str, str], Finding] = {}

    for finding in findings:
        key = finding.dedup_key()
        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            existing_idx = severity_order.index(existing.severity)
            new_idx = severity_order.index(finding.severity)
            if new_idx > existing_idx:
                seen[key] = finding

    return list(seen.values())
