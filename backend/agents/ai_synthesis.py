"""AI Security Copilot — optional synthesis stage after scoring.

Produces a business-facing executive summary, prioritized remediation roadmap,
and deterministic config-fix snippets. Never blocks reporting: missing keys,
timeouts, schema/id/grader failures all fall back cleanly.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

from agents.config_snippets import generate_config_fixes
from agents.state import ScanState
from core.config import Settings, get_settings
from core.llm_providers import (
    DEFAULT_TEMPERATURE,
    LLMCallResult,
    any_llm_configured,
    call_with_fallback,
    provider_coverage_fields,
)
from core.logging import log_scan_event

logger = logging.getLogger(__name__)

_ALLOWED_VERDICTS = frozenset({"confirmed", "tool_attested"})
_EFFORT_VALUES = frozenset({"trivial", "moderate", "significant"})
_FINDING_ID_RE = re.compile(r"\b(?:finding[_-]?id|id)\b[\"'\\s:=]*([A-Za-z0-9_.:/-]+)", re.I)

# Fallback reasons — each becomes a distinct observable metric/log event.
FALLBACK_NO_API_KEY = "no_api_key"
FALLBACK_TIMEOUT = "timeout"
FALLBACK_ALL_PROVIDERS = "all_providers_failed"
FALLBACK_SCHEMA = "schema_validation_failure"
FALLBACK_ID_MISMATCH = "id_mismatch"
FALLBACK_GRADER = "grader_flag"
FALLBACK_EMPTY_RESPONSE = "empty_response"
FALLBACK_CALL_BUDGET = "call_budget_exhausted"


def _log_fallback(
    scan_id: str,
    reason: str,
    **fields: Any,
) -> None:
    """Emit a distinct metric/log event for every hallucination/fallback path."""
    log_scan_event(
        scan_id,
        f"ai_synthesis_fallback_{reason}",
        reason=reason,
        **fields,
    )
    logger.warning(
        "ai_synthesis_fallback",
        extra={
            "scan_id": scan_id,
            "event": f"ai_synthesis_fallback_{reason}",
            "reason": reason,
            **fields,
        },
    )


def ensure_finding_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy findings and ensure each has a stable string id."""
    out: list[dict[str, Any]] = []
    for idx, finding in enumerate(findings):
        item = dict(finding)
        if not item.get("id"):
            item["id"] = f"{item.get('tool', 'finding')}-{idx}"
        else:
            item["id"] = str(item["id"])
        out.append(item)
    return out


def filter_llm_eligible_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Only confirmed / tool_attested findings enter the LLM prompt context."""
    eligible: list[dict[str, Any]] = []
    for finding in findings:
        verification = finding.get("verification") or {}
        status = str(verification.get("status") or "").strip().lower()
        if status in _ALLOWED_VERDICTS:
            eligible.append(finding)
    return eligible


def _compact_finding_for_prompt(finding: dict[str, Any]) -> dict[str, Any]:
    verification = finding.get("verification") or {}
    return {
        "finding_id": finding["id"],
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "url": finding.get("url"),
        "description": finding.get("description"),
        "confidence": finding.get("confidence"),
        "verification_status": verification.get("status"),
        "cvss_score": finding.get("cvss_score"),
    }


def build_deterministic_executive_summary(
    findings: list[dict[str, Any]],
    severity_scores: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Template summary used when LLM is skipped or discarded. Never calls an LLM."""
    scores = severity_scores or {}
    counts = scores.get("severity_counts") or {}
    if not counts:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = str(f.get("severity") or "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

    n = len(findings)
    actionable = [
        f
        for f in findings
        if str(f.get("severity") or "info").lower() not in ("info", "")
    ]
    severities_present = sorted(
        {
            str(f.get("severity") or "info").lower()
            for f in actionable
        }
    )

    if n == 0 or not actionable:
        summary_text = (
            "No significant risks were found in this scan. "
            "The checks that completed did not surface confirmed issues that "
            "require urgent business action. Review the findings table below "
            "for any informational notes."
        )
        impact = "No significant business risk identified from confirmed findings."
        top_id = None
    else:
        sev_label = ", ".join(severities_present) if severities_present else "mixed"
        summary_text = (
            f"This scan found {len(actionable)} confirmed issue(s) across "
            f"{sev_label} severity. See the findings table below for details "
            "and prioritize remediations starting with the highest-impact items."
        )
        impact = (
            f"{len(actionable)} confirmed security issue(s) warrant review "
            "by your engineering team."
        )
        # Highest severity first among actionable.
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        ranked = sorted(
            actionable,
            key=lambda f: (
                order.get(str(f.get("severity") or "info").lower(), 0),
                float(f.get("cvss_score") or 0),
            ),
            reverse=True,
        )
        top_id = ranked[0].get("id") if ranked else None

    return {
        "summary_text": summary_text,
        "top_risk_finding_id": top_id,
        "business_impact_one_liner": impact,
        "source": "deterministic_template",
    }


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from model output, tolerating markdown fences."""
    raw = (text or "").strip()
    if not raw:
        return None
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def extract_referenced_finding_ids(
    payload: dict[str, Any] | str,
    *,
    known_ids: set[str] | None = None,
) -> set[str]:
    """Collect finding ids referenced in structured LLM output (and free text)."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_l = str(key).lower()
                if key_l in {"finding_id", "top_risk_finding_id", "id"} and value is not None:
                    found.add(str(value))
                if key_l in {"finding_ids", "ids"} and isinstance(value, list):
                    for item in value:
                        found.add(str(item))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str) and known_ids:
            for kid in known_ids:
                if kid and kid in node:
                    found.add(kid)

    if isinstance(payload, str):
        if known_ids:
            for kid in known_ids:
                if kid and kid in payload:
                    found.add(kid)
        for match in _FINDING_ID_RE.finditer(payload):
            found.add(match.group(1))
    else:
        walk(payload)
    return found


def validate_referenced_ids(
    referenced: set[str],
    known_ids: set[str],
) -> list[str]:
    """Return referenced ids that are not in the actual findings set."""
    return sorted(rid for rid in referenced if rid and rid not in known_ids)


def _build_synthesis_prompt(
    eligible: list[dict[str, Any]],
    coverage: dict[str, Any],
    overall_risk: float,
) -> str:
    findings_json = json.dumps(
        [_compact_finding_for_prompt(f) for f in eligible],
        indent=2,
        default=str,
    )
    coverage_json = json.dumps(coverage or {}, indent=2, default=str)
    return f"""You are a senior application security consultant writing for a non-technical business owner.

Do not invent, assume, or speculate about any vulnerability not explicitly present in the findings list below. Reference the specific finding_id for every claim you make. If the list is empty or info-severity only, state plainly that no significant risks were found.

Ground every claim strictly in the findings. Do not invent vulnerabilities. Do not speculate beyond what is in the findings.

Overall risk score (0-10): {overall_risk}
Scan coverage metadata:
{coverage_json}

Findings list (JSON):
{findings_json}

Return ONLY valid JSON with this exact shape:
{{
  "executive_summary": {{
    "summary_text": "3-5 sentence plain-language summary in business terms (e.g. attacker could read customer data), not a restatement of counts",
    "top_risk_finding_id": "finding_id of the single most important risk, or null if none",
    "business_impact_one_liner": "one short sentence of business impact"
  }},
  "remediation_roadmap": [
    {{
      "finding_ids": ["id1"],
      "rationale": "why fix this now, including effort vs severity tradeoff",
      "estimated_effort": "trivial|moderate|significant"
    }}
  ]
}}

Roadmap rules:
- Order as "fix this first, then this" — not severity alone. Prefer trivial config/header fixes early even at medium severity; leave complex code fixes (e.g. SQLi) later even if severe when effort is high.
- Every finding_ids entry MUST be an id from the findings list above. Never fabricate ids.
- estimated_effort must be exactly one of: trivial, moderate, significant.
"""


def _build_grader_prompt(
    eligible: list[dict[str, Any]],
    summary_payload: dict[str, Any],
) -> str:
    findings_json = json.dumps(
        [_compact_finding_for_prompt(f) for f in eligible],
        indent=2,
        default=str,
    )
    summary_json = json.dumps(summary_payload, indent=2, default=str)
    return f"""You are a strict factual grader for a security report.

Given the AUTHORITATIVE findings list and a GENERATED summary/roadmap, answer whether the generated text contains ANY claim not supported by the findings.

Findings (JSON):
{findings_json}

Generated content (JSON):
{summary_json}

Return ONLY valid JSON:
{{
  "supported": true|false,
  "unsupported_claims": ["list each unsupported claim, or empty if supported is true"]
}}

supported must be false if any vulnerability, impact, or finding_id is invented or not present in the findings list.
"""


def _normalize_roadmap(
    raw_items: Any,
    known_ids: set[str],
) -> list[dict[str, Any]] | None:
    if not isinstance(raw_items, list):
        return None
    roadmap: list[dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            return None
        ids_raw = item.get("finding_ids") or item.get("ids") or []
        if isinstance(ids_raw, str):
            ids_raw = [ids_raw]
        if not isinstance(ids_raw, list) or not ids_raw:
            return None
        finding_ids = [str(i) for i in ids_raw]
        if any(fid not in known_ids for fid in finding_ids):
            return None
        effort = str(item.get("estimated_effort") or "").strip().lower()
        if effort not in _EFFORT_VALUES:
            return None
        rationale = str(item.get("rationale") or "").strip()
        if not rationale:
            return None
        roadmap.append(
            {
                "finding_ids": finding_ids,
                "rationale": rationale,
                "estimated_effort": effort,
            }
        )
    return roadmap


def _normalize_executive(
    raw: Any,
    known_ids: set[str],
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    summary_text = str(raw.get("summary_text") or "").strip()
    impact = str(raw.get("business_impact_one_liner") or "").strip()
    if not summary_text or not impact:
        return None
    top = raw.get("top_risk_finding_id")
    if top is not None and str(top).strip().lower() not in ("", "null", "none"):
        top_id = str(top)
        if top_id not in known_ids:
            return None
    else:
        top_id = None
    return {
        "summary_text": summary_text,
        "top_risk_finding_id": top_id,
        "business_impact_one_liner": impact,
        "source": "llm",
    }


def generate_executive_summary(
    findings: list[dict[str, Any]],
    *,
    severity_scores: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    llm_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce structured executive summary.

    When ``llm_payload`` is provided (already validated), use it. Otherwise
    return the deterministic template. This function never calls an LLM itself.
    """
    findings = ensure_finding_ids(findings)
    if llm_payload is not None:
        known = {str(f["id"]) for f in findings}
        normalized = _normalize_executive(llm_payload, known)
        if normalized is not None:
            return normalized
    return build_deterministic_executive_summary(findings, severity_scores)


def generate_remediation_roadmap(
    findings: list[dict[str, Any]],
    *,
    llm_roadmap: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Produce ordered remediation roadmap.

    When ``llm_roadmap`` is provided and validates against finding ids, use it.
    Otherwise build a deterministic severity+effort heuristic order. Never calls LLM.
    """
    findings = ensure_finding_ids(findings)
    known = {str(f["id"]) for f in findings}
    if llm_roadmap is not None:
        normalized = _normalize_roadmap(llm_roadmap, known)
        if normalized is not None:
            return normalized

    # Deterministic heuristic: trivial header/CORS first, then by severity.
    trivial_types = {
        "missing-csp",
        "missing-x-frame-options",
        "weak-hsts",
        "weak-hsts-max-age",
        "missing-x-content-type-options",
        "missing-referrer-policy",
        "cors-wildcard",
        "missing-hsts",
        "server-version-disclosure",
        "x-powered-by-disclosure",
    }
    significant_types = {"sqli", "xss", "ssrf", "rce", "idor"}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def effort_for(ftype: str) -> str:
        if ftype in trivial_types:
            return "trivial"
        if ftype in significant_types or ftype.startswith("sqli") or ftype.startswith("xss"):
            return "significant"
        return "moderate"

    actionable = [
        f
        for f in findings
        if str(f.get("severity") or "info").lower() != "info"
        and not f.get("likely_false_positive")
    ]
    actionable.sort(
        key=lambda f: (
            0 if effort_for(str(f.get("type") or "")) == "trivial" else 1,
            -severity_rank.get(str(f.get("severity") or "info").lower(), 0),
        )
    )
    roadmap: list[dict[str, Any]] = []
    for finding in actionable:
        ftype = str(finding.get("type") or "unknown")
        effort = effort_for(ftype)
        rationale = {
            "trivial": f"Quick configuration fix for {ftype}; do this first for fast risk reduction.",
            "moderate": f"Address {ftype} after trivial hardening; requires modest engineering time.",
            "significant": f"Prioritize planning for {ftype}; higher effort but material risk if confirmed.",
        }[effort]
        roadmap.append(
            {
                "finding_ids": [finding["id"]],
                "rationale": rationale,
                "estimated_effort": effort,
            }
        )
    return roadmap


def grade_summary_against_findings(
    findings: list[dict[str, Any]],
    summary_payload: dict[str, Any],
    *,
    settings: Settings | None = None,
    llm_call: Callable[..., LLMCallResult] | None = None,
) -> dict[str, Any]:
    """Ask the LLM grader yes/no whether the summary invents unsupported claims."""
    settings = settings or get_settings()
    eligible = filter_llm_eligible_findings(ensure_finding_ids(findings))
    prompt = _build_grader_prompt(eligible, summary_payload)
    invoker = llm_call or call_with_fallback
    result = invoker(prompt, settings=settings, temperature=DEFAULT_TEMPERATURE)
    if result.response is None:
        return {
            "supported": False,
            "unsupported_claims": ["grader_unavailable"],
            "provider_used": result.provider_used,
            "error": result.error,
        }
    parsed = _extract_json_object(result.response.text)
    if not parsed or "supported" not in parsed:
        return {
            "supported": False,
            "unsupported_claims": ["grader_schema_invalid"],
            "provider_used": result.provider_used,
            "error": "grader_schema_invalid",
        }
    supported = bool(parsed.get("supported"))
    claims = parsed.get("unsupported_claims") or []
    if not isinstance(claims, list):
        claims = [str(claims)]
    return {
        "supported": supported,
        "unsupported_claims": [str(c) for c in claims],
        "provider_used": result.provider_used,
        "error": None,
    }


def _attach_config_snippets_to_findings(
    findings: list[dict[str, Any]],
    config_fixes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, str]] = {}
    for fix in config_fixes:
        snippets = fix.get("snippets") or {}
        for fid in fix.get("finding_ids") or []:
            by_id[str(fid)] = snippets
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        snippets = by_id.get(str(item.get("id") or ""))
        if snippets:
            item["config_snippets"] = snippets
        enriched.append(item)
    return enriched


def run_ai_synthesis(
    state: ScanState,
    *,
    settings: Settings | None = None,
    llm_call: Callable[..., LLMCallResult] | None = None,
    grader_call: Callable[..., LLMCallResult] | None = None,
) -> dict[str, Any]:
    """LangGraph node: synthesize AI report content or skip gracefully."""
    settings = settings or get_settings()
    scan_id = str(state.get("scan_id") or "unknown")
    findings = ensure_finding_ids(list(state.get("findings") or []))
    severity_scores = dict(state.get("severity_scores") or {})
    coverage = dict((severity_scores.get("scan_coverage") or {}))
    overall_risk = float(severity_scores.get("overall_risk_score") or 0.0)

    # Always produce deterministic config fixes (no LLM).
    config_fixes = generate_config_fixes(findings)
    findings_with_snippets = _attach_config_snippets_to_findings(findings, config_fixes)

    base_coverage = {
        "ai_synthesis_status": "skipped",
        "ai_synthesis_provider": "none",
        "ai_synthesis_provider_role": "none",
        "ai_synthesis_fallback_reason": None,
        "ai_synthesis_llm_calls": 0,
    }

    def _finalize(
        *,
        status: str,
        executive: dict[str, Any],
        roadmap: list[dict[str, Any]],
        provider_used: str = "none",
        fallback_reason: str | None = None,
        llm_calls: int = 0,
        grader: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prov = provider_coverage_fields(provider_used, settings=settings)
        ai_cov = {
            **base_coverage,
            "ai_synthesis_status": status,
            "ai_synthesis_provider": provider_used,
            "ai_synthesis_provider_role": prov["provider_role"],
            "ai_synthesis_providers_configured": prov["providers_configured"],
            "ai_synthesis_fallback_reason": fallback_reason,
            "ai_synthesis_llm_calls": llm_calls,
        }
        if grader is not None:
            ai_cov["ai_synthesis_grader"] = {
                "supported": grader.get("supported"),
                "unsupported_claims": grader.get("unsupported_claims") or [],
            }
        merged_coverage = {**coverage, **ai_cov}
        merged_scores = {**severity_scores, "scan_coverage": merged_coverage}
        synthesis = {
            "status": status,
            "provider": provider_used,
            "provider_role": prov["provider_role"],
            "fallback_reason": fallback_reason,
            "llm_calls": llm_calls,
            "executive_summary": executive,
            "remediation_roadmap": roadmap,
            "config_fixes": config_fixes,
        }
        return {
            "findings": findings_with_snippets,
            "severity_scores": merged_scores,
            "ai_synthesis": synthesis,
            "status": state.get("status") or "scored",
        }

    # Soft skip when no key is configured — identical pipeline behavior otherwise.
    if not any_llm_configured(settings):
        _log_fallback(scan_id, FALLBACK_NO_API_KEY)
        executive = build_deterministic_executive_summary(findings, severity_scores)
        # For no-key path, still expose deterministic roadmap but mark AI skipped
        # so templates can omit the "AI Executive Summary" branding if desired.
        roadmap = generate_remediation_roadmap(findings)
        result = _finalize(
            status="skipped",
            executive={**executive, "source": "deterministic_template"},
            roadmap=roadmap,
            provider_used="none",
            fallback_reason=FALLBACK_NO_API_KEY,
            llm_calls=0,
        )
        # Clear LLM-branded fields when skipped so reports stay identical to today
        # aside from optional deterministic config snippets.
        result["ai_synthesis"]["executive_summary"] = None
        result["ai_synthesis"]["remediation_roadmap"] = None
        return result

    eligible = filter_llm_eligible_findings(findings)
    known_ids = {str(f["id"]) for f in eligible}
    # Also allow referencing any scored finding id that is eligible; keep full
    # known set for validation against the prompt input only.
    prompt_known_ids = known_ids

    invoker = llm_call or call_with_fallback
    llm_calls = 0
    max_calls = int(settings.ai_synthesis_max_llm_calls)

    # Zero / info-only eligible set → deterministic "no significant risks" without LLM.
    actionable_eligible = [
        f
        for f in eligible
        if str(f.get("severity") or "info").lower() not in ("info", "")
    ]
    if not actionable_eligible:
        executive = build_deterministic_executive_summary(eligible, severity_scores)
        # Still allowed to call LLM for empty set per tests — but user asked for
        # "no significant risks found" and grounding. Prefer deterministic for empty.
        executive = {
            "summary_text": (
                "No significant risks were found. The confirmed findings set is empty "
                "or informational only, so there is no material business exposure to "
                "prioritize from this scan."
            ),
            "top_risk_finding_id": None,
            "business_impact_one_liner": "No significant business risk identified.",
            "source": "deterministic_template",
        }
        return _finalize(
            status="succeeded",
            executive=executive,
            roadmap=[],
            provider_used="none",
            fallback_reason=None,
            llm_calls=0,
        )

    if llm_calls >= max_calls:
        _log_fallback(scan_id, FALLBACK_CALL_BUDGET)
        return _finalize(
            status="unavailable",
            executive=build_deterministic_executive_summary(findings, severity_scores),
            roadmap=generate_remediation_roadmap(findings),
            fallback_reason=FALLBACK_CALL_BUDGET,
            llm_calls=llm_calls,
        )

    prompt = _build_synthesis_prompt(eligible, coverage, overall_risk)
    call_result = invoker(prompt, settings=settings, temperature=DEFAULT_TEMPERATURE)
    llm_calls += 1

    if call_result.response is None:
        reason = FALLBACK_TIMEOUT if (call_result.error or "").find("timeout") >= 0 else FALLBACK_ALL_PROVIDERS
        if call_result.error == "no_api_key":
            reason = FALLBACK_NO_API_KEY
        _log_fallback(scan_id, reason, error=call_result.error)
        return _finalize(
            status="unavailable",
            executive=build_deterministic_executive_summary(findings, severity_scores),
            roadmap=generate_remediation_roadmap(findings),
            provider_used="none",
            fallback_reason=reason,
            llm_calls=llm_calls,
        )

    provider_used = call_result.provider_used
    parsed = _extract_json_object(call_result.response.text)
    if parsed is None:
        _log_fallback(scan_id, FALLBACK_SCHEMA, provider=provider_used)
        return _finalize(
            status="unavailable",
            executive=build_deterministic_executive_summary(findings, severity_scores),
            roadmap=generate_remediation_roadmap(findings),
            provider_used=provider_used,
            fallback_reason=FALLBACK_SCHEMA,
            llm_calls=llm_calls,
        )

    executive = _normalize_executive(parsed.get("executive_summary"), prompt_known_ids)
    roadmap = _normalize_roadmap(parsed.get("remediation_roadmap"), prompt_known_ids)
    if executive is None or roadmap is None:
        # Also catch id mismatches buried in free text / partial structure.
        referenced = extract_referenced_finding_ids(parsed, known_ids=prompt_known_ids)
        bad = validate_referenced_ids(referenced, prompt_known_ids)
        reason = FALLBACK_ID_MISMATCH if bad else FALLBACK_SCHEMA
        _log_fallback(
            scan_id,
            reason,
            provider=provider_used,
            invalid_ids=bad,
        )
        return _finalize(
            status="unavailable",
            executive=build_deterministic_executive_summary(findings, severity_scores),
            roadmap=generate_remediation_roadmap(findings),
            provider_used=provider_used,
            fallback_reason=reason,
            llm_calls=llm_calls,
        )

    # Programmatic id validation across the whole payload.
    referenced = extract_referenced_finding_ids(parsed, known_ids=prompt_known_ids)
    # top_risk null is fine; filter empty
    referenced = {r for r in referenced if r and r.lower() not in {"null", "none"}}
    bad_ids = validate_referenced_ids(referenced, prompt_known_ids)
    if bad_ids:
        _log_fallback(
            scan_id,
            FALLBACK_ID_MISMATCH,
            provider=provider_used,
            invalid_ids=bad_ids,
        )
        return _finalize(
            status="unavailable",
            executive=build_deterministic_executive_summary(findings, severity_scores),
            roadmap=generate_remediation_roadmap(findings),
            provider_used=provider_used,
            fallback_reason=FALLBACK_ID_MISMATCH,
            llm_calls=llm_calls,
        )

    # Grader call (counts toward the per-scan budget).
    grader: dict[str, Any] | None = None
    if llm_calls < max_calls:
        grade_invoker = grader_call or llm_call or call_with_fallback
        grader = grade_summary_against_findings(
            eligible,
            {
                "executive_summary": executive,
                "remediation_roadmap": roadmap,
            },
            settings=settings,
            llm_call=grade_invoker,
        )
        llm_calls += 1
        if grader.get("error") == "grader_unavailable" or grader.get("unsupported_claims") == ["grader_unavailable"]:
            # Grader failure → discard (safer than showing ungraded content).
            _log_fallback(scan_id, FALLBACK_GRADER, provider=provider_used, grader=grader)
            return _finalize(
                status="unavailable",
                executive=build_deterministic_executive_summary(findings, severity_scores),
                roadmap=generate_remediation_roadmap(findings),
                provider_used=provider_used,
                fallback_reason=FALLBACK_GRADER,
                llm_calls=llm_calls,
                grader=grader,
            )
        if not grader.get("supported", False):
            _log_fallback(scan_id, FALLBACK_GRADER, provider=provider_used, grader=grader)
            return _finalize(
                status="unavailable",
                executive=build_deterministic_executive_summary(findings, severity_scores),
                roadmap=generate_remediation_roadmap(findings),
                provider_used=provider_used,
                fallback_reason=FALLBACK_GRADER,
                llm_calls=llm_calls,
                grader=grader,
            )
    else:
        _log_fallback(scan_id, FALLBACK_CALL_BUDGET)

    return _finalize(
        status="succeeded",
        executive=executive,
        roadmap=roadmap,
        provider_used=provider_used,
        fallback_reason=None,
        llm_calls=llm_calls,
        grader=grader,
    )
