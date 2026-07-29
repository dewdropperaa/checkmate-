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
        finding["id"] = fid
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

    recon = state.get("recon_results") or {}
    recon_modules = sorted(
        k
        for k, v in (recon.get("tool_results") or {}).items()
        if isinstance(v, dict) and v.get("success") and not v.get("skipped")
    )
    recon_skipped = sorted(
        k
        for k, v in (recon.get("tool_results") or {}).items()
        if isinstance(v, dict) and v.get("skipped")
    )
    detection_meta = state.get("detection_metadata") or {}
    detection_errors = detection_meta.get("errors") or {}
    modules_na = set(detection_meta.get("modules_not_applicable") or [])
    passive_modules = ["nuclei", "testssl", "retirejs", "header-checks"]
    detection_modules = [
        m for m in passive_modules
        if m not in detection_errors and m not in modules_na
    ]
    # Only credit active tools that actually executed — never infer both from a flag.
    active_executed = list(detection_meta.get("active_tools_executed") or [])
    if not active_executed and detection_meta.get("active_tools_run"):
        # Backward-compatible fallback for older checkpoints that only set the flag.
        approved = list(detection_meta.get("approved_tools") or [])
        active_executed = [
            t
            for t in approved
            if f"active_{t}" not in detection_errors and t not in modules_na
        ]
    for tool in active_executed:
        if tool not in detection_modules:
            detection_modules.append(tool)

    modules_failed = sorted(
        k for k in detection_errors.keys()
        if not k.startswith("active_")
    )
    active_failed = sorted(
        k.removeprefix("active_")
        for k in detection_errors.keys()
        if k.startswith("active_")
    )
    modules_failed_all = modules_failed + active_failed
    # Recon hard failures also belong in coverage honesty (not mere skips).
    for tool, err in (recon.get("errors") or {}).items():
        if tool not in modules_failed_all and tool not in recon_skipped:
            modules_failed_all.append(tool)
    modules_failed_all = sorted(set(modules_failed_all))

    total_findings = len(findings)
    if total_findings == 0:
        overall_risk = 0.0
    else:
        max_weighted = total_findings * _RISK_WEIGHTS["critical"]
        overall_risk = round((weighted_sum / max_weighted) * 10.0, 2)

    # A partially failed scan should never look "safer" than a clean full-coverage
    # scan purely because fewer modules executed.
    if modules_failed_all:
        coverage_penalty = min(2.0, 0.5 * len(modules_failed_all))
        overall_risk = round(max(overall_risk, coverage_penalty), 2)

    rejected_active = list(detection_meta.get("rejected_tools") or [])
    scan_coverage = {
        "recon_modules_run": recon_modules,
        "detection_modules_run": detection_modules,
        "recon_partial_failure": bool(recon.get("partial_failure")),
        "modules_failed": modules_failed_all,
        "modules_not_applicable": sorted(modules_na),
        "modules_skipped": sorted(set(recon_skipped + rejected_active)),
        "modules_rejected": rejected_active,
        "score_basis": (
            "Score reflects findings from modules that executed successfully. "
            "modules_not_applicable lists tools that had nothing to scan; "
            "modules_failed lists tools that exhausted retries; "
            "modules_skipped lists intentionally disabled/skipped tools "
            "(e.g. Firecrawl off, reviewer-rejected active tools)."
        ),
    }

    detection_meta = dict(state.get("detection_metadata") or {})
    coverage_notes = [
        str(n) for n in (detection_meta.get("coverage_notes") or []) if n
    ]
    if coverage_notes:
        scan_coverage["coverage_notes"] = coverage_notes

    auth_scan = dict(state.get("auth_scan") or {})
    if auth_scan:
        scan_coverage["authenticated_scanning"] = {
            "configured": bool(auth_scan.get("configured")),
            "enabled": bool(auth_scan.get("enabled")),
            "login_succeeded": auth_scan.get("login_succeeded"),
            "username_hint": auth_scan.get("username_hint"),
            "excluded_paths": list(auth_scan.get("excluded_paths") or []),
            "fallback_reason": auth_scan.get("fallback_reason"),
            "warnings": list(auth_scan.get("warnings") or []),
        }
        if (
            auth_scan.get("configured")
            and auth_scan.get("enabled")
            and auth_scan.get("login_succeeded") is False
        ):
            scan_coverage["authenticated_scanning"]["coverage_warning"] = (
                "Login failed; scan proceeded as an unauthenticated visitor."
            )

    return {
        "findings": findings,
        "severity_scores": {
            "overall_risk_score": overall_risk,
            "severity_counts": counts,
            "total_findings": total_findings,
            "likely_false_positives": likely_false_positives,
            "per_finding": finding_scores,
            "scan_coverage": scan_coverage,
        },
        "status": "scored",
    }
