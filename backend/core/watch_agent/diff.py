"""Findings diff for Watch Agent re-scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def finding_key(finding: dict[str, Any]) -> tuple[str, str]:
    """Stable identity matching tools.schemas.Finding.dedup_key."""
    return (str(finding.get("url") or ""), str(finding.get("type") or ""))


def severity_rank(severity: Any) -> int:
    return SEVERITY_RANK.get(str(severity or "info").lower(), 0)


@dataclass
class FindingsDiff:
    newly_appeared: list[dict[str, Any]] = field(default_factory=list)
    severity_increased: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)

    @property
    def should_alert(self) -> bool:
        """Email only on new or worsened findings — never on fixes alone."""
        return bool(self.newly_appeared or self.severity_increased)

    def to_dict(self) -> dict[str, Any]:
        return {
            "newly_appeared": self.newly_appeared,
            "severity_increased": self.severity_increased,
            "fixed": self.fixed,
            "should_alert": self.should_alert,
        }


def diff_findings(
    previous: list[dict[str, Any]] | None,
    current: list[dict[str, Any]] | None,
) -> FindingsDiff:
    """Compare two findings sets.

    - newly_appeared: present now, absent before
    - severity_increased: same key, higher severity than before
    - fixed: present before, absent now
    """
    prev_map = {finding_key(f): f for f in (previous or [])}
    curr_map = {finding_key(f): f for f in (current or [])}

    result = FindingsDiff()

    for key, finding in curr_map.items():
        if key not in prev_map:
            result.newly_appeared.append(finding)
            continue
        old = prev_map[key]
        if severity_rank(finding.get("severity")) > severity_rank(old.get("severity")):
            enriched = dict(finding)
            enriched["previous_severity"] = old.get("severity")
            result.severity_increased.append(enriched)

    for key, finding in prev_map.items():
        if key not in curr_map:
            result.fixed.append(finding)

    return result
