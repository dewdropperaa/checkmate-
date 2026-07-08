"""Finding scoring agent."""

from __future__ import annotations

from typing import Any

from agents.state import ScanState

_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_SEVERITY_TO_SCORE = {
    "info": 1.0,
    "low": 3.0,
    "medium": 5.5,
    "high": 8.0,
    "critical": 9.5,
}

_SCORE_TO_SEVERITY = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (1.0, "low"),
    (0.0, "info"),
)

_RISK_WEIGHTS = {
    "info": 0.5,
    "low": 1.0,
    "medium": 3.0,
    "high": 6.0,
    "critical": 10.0,
}


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    severity_map = {
        "informational": "info",
        "information": "info",
        "info": "info",
        "none": "info",
        "low": "low",
        "moderate": "medium",
        "medium": "medium",
        "med": "medium",
        "high": "high",
        "critical": "critical",
        "severe": "critical",
        "important": "high",
    }
    return severity_map.get(normalized, "info")


def _clamp_score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score < 0:
        return 0.0
    if score > 10:
        return 10.0
    return round(score, 1)


def _clamp_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 1.0
    if confidence < 0.0:
        return 0.0
    if confidence > 1.0:
        return 1.0
    return round(confidence, 2)


def _severity_from_score(score: float) -> str:
    for threshold, severity in _SCORE_TO_SEVERITY:
        if score >= threshold:
            return severity
    return "info"


def _extract_native_score(finding: dict[str, Any]) -> float | None:
    candidates = (
        finding.get("cvss_score"),
        finding.get("cvss"),
        finding.get("score"),
        finding.get("risk_score"),
        finding.get("raw_data", {}).get("cvss_score"),
        finding.get("raw_data", {}).get("cvss"),
    )
    for candidate in candidates:
        score = _clamp_score(candidate)
        if score is not None:
            return score
    return None


def run_scoring(state: ScanState) -> dict[str, Any]:
    """Normalize scoring for all findings and compute overall risk."""
    findings = [dict(f) for f in state.get("findings", [])]

    counts = {k: 0 for k in _SEVERITY_ORDER}
    finding_scores: dict[str, Any] = {}
    likely_false_positives = 0
    weighted_sum = 0.0

    for idx, finding in enumerate(findings):
        native_score = _extract_native_score(finding)
        native_severity = _normalize_severity(finding.get("severity", "info"))

        if native_score is None:
            score = _SEVERITY_TO_SCORE[native_severity]
            severity = native_severity
        else:
            score = native_score
            severity = _severity_from_score(score)
            if native_severity != "info":
                # Keep higher of declared severity and score-derived severity.
                if _SEVERITY_ORDER[native_severity] > _SEVERITY_ORDER[severity]:
                    severity = native_severity
                    score = _SEVERITY_TO_SCORE[native_severity]

        finding["severity"] = severity
        finding["cvss_score"] = score

        # Confidence from the verification step (default 1.0 when not run).
        confidence = _clamp_confidence(finding.get("confidence", 1.0))
        finding["confidence"] = confidence
        if finding.get("likely_false_positive"):
            likely_false_positives += 1

        counts[severity] += 1
        # Confidence-weighted risk contribution: unverified/likely-FP findings
        # contribute proportionally less to the aggregate risk score. With the
        # default confidence of 1.0 this is identical to the unweighted sum.
        weighted_sum += _RISK_WEIGHTS[severity] * confidence

        verification = finding.get("verification") or {}
        fid = str(finding.get("id") or f"{finding.get('tool', 'finding')}-{idx}")
        finding_scores[fid] = {
            "severity": severity,
            "score": score,
            "type": finding.get("type", "unknown"),
            "url": finding.get("url", ""),
            "confidence": confidence,
            "verification_status": verification.get("status"),
        }

    findings.sort(
        key=lambda f: (
            _SEVERITY_ORDER.get(_normalize_severity(f.get("severity")), -1),
            float(f.get("cvss_score", 0.0)),
        ),
        reverse=True,
    )

    total_findings = len(findings)
    if total_findings == 0:
        overall_risk = 0.0
    else:
        max_weighted = total_findings * _RISK_WEIGHTS["critical"]
        overall_risk = round((weighted_sum / max_weighted) * 10.0, 2)

    return {
        "findings": findings,
        "severity_scores": {
            "overall_risk_score": overall_risk,
            "severity_counts": counts,
            "total_findings": total_findings,
            "likely_false_positives": likely_false_positives,
            "per_finding": finding_scores,
        },
        "status": "scored",
    }
