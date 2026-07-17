"""Tests for AI Security Copilot (ai_synthesis) stage."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from agents.ai_synthesis import (
    FALLBACK_GRADER,
    FALLBACK_ID_MISMATCH,
    FALLBACK_NO_API_KEY,
    build_deterministic_executive_summary,
    extract_referenced_finding_ids,
    filter_llm_eligible_findings,
    generate_executive_summary,
    generate_remediation_roadmap,
    run_ai_synthesis,
    validate_referenced_ids,
)
from agents.config_snippets import (
    DETERMINISTIC_FIX_TYPES,
    generate_config_fixes,
    generate_config_snippets_for_type,
)
from agents.reporting import run_reporting
from agents.state import ScanState
from core.config import Settings, get_settings
from core.llm_providers import (
    LLMCallResult,
    LLMProviderError,
    LLMResponse,
    call_with_fallback,
    configured_providers,
)


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _settings(**overrides: Any) -> Settings:
    base = {
        "gemini_api_key": None,
        "groq_api_key": None,
        "openai_api_key": None,
        "anthropic_api_key": None,
        "ai_llm_providers": "gemini,groq",
        "ai_synthesis_timeout_seconds": 15.0,
        "ai_synthesis_max_llm_calls": 2,
    }
    base.update(overrides)
    return Settings(**base)


def _finding(
    fid: str,
    *,
    ftype: str = "missing-csp",
    severity: str = "medium",
    verdict: str = "confirmed",
) -> dict[str, Any]:
    return {
        "id": fid,
        "tool": "header-checks",
        "type": ftype,
        "url": "https://authorized.example.com/",
        "severity": severity,
        "description": f"{ftype} detected",
        "confidence": 0.99,
        "cvss_score": 5.5,
        "verification": {"status": verdict, "method": "header_recheck"},
    }


def _base_state(findings: list[dict[str, Any]] | None = None) -> ScanState:
    findings = findings or []
    return {
        "scan_id": "scan-ai-synthesis",
        "target": "https://authorized.example.com",
        "scope": {},
        "authorized": True,
        "recon_results": {},
        "planned_active_tests": [],
        "findings": findings,
        "severity_scores": {
            "overall_risk_score": 4.0 if findings else 0.0,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
                "info": sum(1 for f in findings if f.get("severity") == "info"),
            },
            "total_findings": len(findings),
            "scan_coverage": {"detection_modules_run": ["header-checks"]},
        },
        "report": None,
        "status": "scored",
        "human_approval_needed": False,
        "human_approved": False,
    }


def _good_llm_payload(finding_ids: list[str]) -> str:
    top = finding_ids[0] if finding_ids else None
    roadmap = [
        {
            "finding_ids": [fid],
            "rationale": f"Fix {fid} next based on effort vs impact.",
            "estimated_effort": "trivial",
        }
        for fid in finding_ids
    ]
    return json.dumps(
        {
            "executive_summary": {
                "summary_text": (
                    "An attacker could more easily inject malicious scripts into pages "
                    "because browser content protections are missing. This raises the "
                    "chance that customer sessions could be stolen. Addressing the "
                    f"confirmed header gaps ({', '.join(finding_ids)}) reduces that risk."
                ),
                "top_risk_finding_id": top,
                "business_impact_one_liner": "Customer session data could be exposed to attackers.",
            },
            "remediation_roadmap": roadmap,
        }
    )


def _grader_ok() -> str:
    return json.dumps({"supported": True, "unsupported_claims": []})


def _grader_flag() -> str:
    return json.dumps(
        {
            "supported": False,
            "unsupported_claims": ["Invented SQLi vulnerability not in findings"],
        }
    )


def test_ai_synthesis_skipped_when_no_api_key() -> None:
    settings = _settings()
    state = _base_state([_finding("f1")])
    result = run_ai_synthesis(state, settings=settings)

    assert result["ai_synthesis"]["status"] == "skipped"
    assert result["ai_synthesis"]["fallback_reason"] == FALLBACK_NO_API_KEY
    assert result["ai_synthesis"]["executive_summary"] is None
    assert result["ai_synthesis"]["remediation_roadmap"] is None
    assert result["severity_scores"]["scan_coverage"]["ai_synthesis_status"] == "skipped"
    assert result["findings"]
    assert result["status"] == "scored"


def test_zero_findings_executive_summary_no_significant_risks() -> None:
    summary = build_deterministic_executive_summary([])
    assert "no significant" in summary["summary_text"].lower()
    assert summary["top_risk_finding_id"] is None

    via_fn = generate_executive_summary([])
    assert "no significant" in via_fn["summary_text"].lower()

    settings = _settings(gemini_api_key="test-gemini")
    result = run_ai_synthesis(_base_state([]), settings=settings)
    exec_summary = result["ai_synthesis"]["executive_summary"]
    assert exec_summary is not None
    assert "no significant" in exec_summary["summary_text"].lower()
    assert result["ai_synthesis"]["llm_calls"] == 0


def test_deterministic_fallback_never_calls_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"n": 0}

    def _boom(*_a: Any, **_k: Any) -> LLMCallResult:
        called["n"] += 1
        raise AssertionError("LLM should not be called for deterministic fallback")

    monkeypatch.setattr("agents.ai_synthesis.call_with_fallback", _boom)
    summary = build_deterministic_executive_summary([_finding("f1")])
    assert "issue" in summary["summary_text"].lower()
    roadmap = generate_remediation_roadmap(
        [_finding("f1"), _finding("f2", ftype="sqli", severity="high")]
    )
    assert roadmap
    assert called["n"] == 0

    result = run_ai_synthesis(_base_state([_finding("f1")]), settings=_settings())
    assert result["ai_synthesis"]["status"] == "skipped"
    assert called["n"] == 0


@pytest.mark.parametrize(
    "finding_type",
    [
        "missing-csp",
        "missing-x-frame-options",
        "weak-hsts",
        "missing-x-content-type-options",
        "missing-referrer-policy",
        "cors-wildcard",
    ],
)
def test_deterministic_config_snippets_for_whitelisted_types(finding_type: str) -> None:
    snippets = generate_config_snippets_for_type(finding_type)
    assert snippets is not None
    assert "add_header" in snippets["nginx"] or "Access-Control" in snippets["nginx"]
    assert "Header always set" in snippets["apache"] or "Access-Control" in snippets["apache"]
    assert "app.use" in snippets["express"] or "setHeader" in snippets["express"]

    if finding_type == "weak-hsts":
        alias = generate_config_snippets_for_type("weak-hsts-max-age")
        assert alias is not None
        assert "Strict-Transport-Security" in alias["nginx"]


def test_config_snippets_not_generated_for_non_whitelisted() -> None:
    assert generate_config_snippets_for_type("sqli") is None
    assert generate_config_snippets_for_type("xss") is None


def test_generate_config_fixes_attaches_finding_ids() -> None:
    findings = [
        _finding("a", ftype="missing-csp"),
        _finding("b", ftype="cors-wildcard"),
        _finding("c", ftype="sqli", severity="high"),
    ]
    fixes = generate_config_fixes(findings)
    types = {f["finding_type"] for f in fixes}
    assert "missing-csp" in types
    assert "cors-wildcard" in types
    assert "sqli" not in types
    assert all(f["source"] == "deterministic_template" for f in fixes)


def test_id_mismatch_triggers_fallback() -> None:
    settings = _settings(gemini_api_key="test-gemini")
    findings = [_finding("real-1"), _finding("real-2", ftype="missing-x-frame-options")]
    state = _base_state(findings)

    hallucinated = json.dumps(
        {
            "executive_summary": {
                "summary_text": "Attackers could exploit finding ghost-99 to steal data.",
                "top_risk_finding_id": "ghost-99",
                "business_impact_one_liner": "Data theft risk.",
            },
            "remediation_roadmap": [
                {
                    "finding_ids": ["ghost-99"],
                    "rationale": "Fix invented finding first",
                    "estimated_effort": "trivial",
                }
            ],
        }
    )

    def _fake_llm(prompt: str, **_k: Any) -> LLMCallResult:
        return LLMCallResult(
            response=LLMResponse(text=hallucinated, provider="gemini", model="gemini-2.5-flash"),
            provider_used="gemini",
        )

    result = run_ai_synthesis(state, settings=settings, llm_call=_fake_llm)
    assert result["ai_synthesis"]["status"] == "unavailable"
    assert result["ai_synthesis"]["fallback_reason"] == FALLBACK_ID_MISMATCH
    assert result["ai_synthesis"]["executive_summary"]["source"] == "deterministic_template"
    assert "ghost-99" not in json.dumps(result["ai_synthesis"]["executive_summary"])


def test_grader_flag_triggers_fallback() -> None:
    settings = _settings(gemini_api_key="test-gemini")
    findings = [_finding("real-1")]
    state = _base_state(findings)
    calls: list[str] = []

    def _fake_llm(prompt: str, **_k: Any) -> LLMCallResult:
        if "strict factual grader" in prompt.lower() or "unsupported_claims" in prompt:
            calls.append("grader")
            return LLMCallResult(
                response=LLMResponse(text=_grader_flag(), provider="gemini", model="m"),
                provider_used="gemini",
            )
        calls.append("synth")
        return LLMCallResult(
            response=LLMResponse(
                text=_good_llm_payload(["real-1"]),
                provider="gemini",
                model="m",
            ),
            provider_used="gemini",
        )

    result = run_ai_synthesis(state, settings=settings, llm_call=_fake_llm)
    assert "grader" in calls
    assert result["ai_synthesis"]["status"] == "unavailable"
    assert result["ai_synthesis"]["fallback_reason"] == FALLBACK_GRADER
    assert result["ai_synthesis"]["executive_summary"]["source"] == "deterministic_template"


def test_validate_referenced_ids_rejects_unknown() -> None:
    bad = validate_referenced_ids({"real-1", "ghost"}, {"real-1"})
    assert bad == ["ghost"]
    refs = extract_referenced_finding_ids(
        {
            "executive_summary": {"top_risk_finding_id": "real-1"},
            "remediation_roadmap": [{"finding_ids": ["x"]}],
        },
    )
    assert "real-1" in refs
    assert "x" in refs


def test_filter_excludes_refuted_and_unreachable() -> None:
    findings = [
        _finding("ok", verdict="confirmed"),
        _finding("attested", verdict="tool_attested"),
        _finding("bad", verdict="refuted"),
        _finding("down", verdict="unreachable"),
    ]
    eligible = filter_llm_eligible_findings(findings)
    ids = {f["id"] for f in eligible}
    assert ids == {"ok", "attested"}


def test_gemini_rate_limit_falls_back_to_groq() -> None:
    settings = _settings(gemini_api_key="gem-key", groq_api_key="groq-key")
    assert configured_providers(settings) == ["gemini", "groq"]

    def _fake_call(provider: str, prompt: str, **_k: Any) -> LLMResponse:
        if provider == "gemini":
            raise LLMProviderError("gemini rate-limited (429): too many requests")
        if provider == "groq":
            return LLMResponse(text="ok-from-groq", provider="groq", model="llama-3.3-70b-versatile")
        raise LLMProviderError(f"unexpected {provider}")

    result = call_with_fallback("hello", settings=settings, call_fn=_fake_call)
    assert result.provider_used == "groq"
    assert result.response is not None
    assert result.response.text == "ok-from-groq"


def test_both_providers_fail_triggers_deterministic_fallback() -> None:
    settings = _settings(gemini_api_key="gem-key", groq_api_key="groq-key")
    state = _base_state([_finding("real-1")])

    def _all_fail(prompt: str, **_k: Any) -> LLMCallResult:
        return LLMCallResult(response=None, provider_used="none", error="all_providers_failed")

    result = run_ai_synthesis(state, settings=settings, llm_call=_all_fail)
    assert result["ai_synthesis"]["status"] == "unavailable"
    assert result["ai_synthesis"]["provider"] == "none"
    assert result["ai_synthesis"]["executive_summary"]["source"] == "deterministic_template"
    assert "findings" in result


def test_httpx_gemini_429_then_groq_success(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(gemini_api_key="gem-key", groq_api_key="groq-key")

    class _FakeResponse:
        def __init__(
            self,
            status_code: int,
            payload: dict[str, Any] | None = None,
            text: str = "",
        ) -> None:
            self.status_code = status_code
            self._payload = payload or {}
            self.text = text or json.dumps(self._payload)

        def json(self) -> dict[str, Any]:
            return self._payload

    class _FakeClient:
        def __init__(self, *a: Any, **k: Any) -> None:
            pass

        def post(self, url: str, **kwargs: Any) -> _FakeResponse:
            if "generativelanguage.googleapis.com" in url:
                return _FakeResponse(429, text="rate limited")
            if "api.groq.com" in url:
                return _FakeResponse(
                    200,
                    {"choices": [{"message": {"content": "groq says hi"}}]},
                )
            return _FakeResponse(500, text="nope")

        def close(self) -> None:
            return None

    monkeypatch.setattr("core.llm_providers.httpx.Client", _FakeClient)
    result = call_with_fallback("prompt", settings=settings)
    assert result.provider_used == "groq"
    assert result.response is not None
    assert "groq" in result.response.text


def test_llm_timeout_marks_ai_unavailable_without_blocking() -> None:
    settings = _settings(
        gemini_api_key="gem-key",
        ai_synthesis_timeout_seconds=0.05,
    )
    state = _base_state([_finding("real-1")])

    def _slow(prompt: str, **_k: Any) -> LLMCallResult:
        return LLMCallResult(
            response=None,
            provider_used="none",
            error="gemini timeout after 0.05s",
        )

    started = time.monotonic()
    result = run_ai_synthesis(state, settings=settings, llm_call=_slow)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert result["ai_synthesis"]["status"] == "unavailable"
    assert result["severity_scores"]["scan_coverage"]["ai_synthesis_status"] == "unavailable"
    assert result["ai_synthesis"]["executive_summary"]["source"] == "deterministic_template"


def test_successful_synthesis_and_report_sections(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(gemini_api_key="gem-key", ai_synthesis_max_llm_calls=2)
    findings = [
        _finding("hdr-csp", ftype="missing-csp"),
        _finding("hdr-xfo", ftype="missing-x-frame-options"),
    ]
    state = _base_state(findings)

    def _fake_llm(prompt: str, **_k: Any) -> LLMCallResult:
        if "strict factual grader" in prompt.lower() or '"supported"' in prompt:
            return LLMCallResult(
                response=LLMResponse(text=_grader_ok(), provider="gemini", model="m"),
                provider_used="gemini",
            )
        return LLMCallResult(
            response=LLMResponse(
                text=_good_llm_payload(["hdr-csp", "hdr-xfo"]),
                provider="gemini",
                model="m",
            ),
            provider_used="gemini",
        )

    synth = run_ai_synthesis(state, settings=settings, llm_call=_fake_llm)
    assert synth["ai_synthesis"]["status"] == "succeeded"
    assert synth["ai_synthesis"]["provider"] == "gemini"
    assert synth["ai_synthesis"]["provider_role"] == "primary"
    assert synth["ai_synthesis"]["executive_summary"]["source"] == "llm"
    assert synth["ai_synthesis"]["remediation_roadmap"]
    assert any(f.get("config_snippets") for f in synth["findings"])

    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", tmp_path)
    report_state = {**state, **synth}
    reported = run_reporting(report_state)
    report = reported["report"]
    assert report["ai_synthesis"]["status"] == "succeeded"
    md = (tmp_path / "scan-ai-synthesis" / "report.md").read_text(encoding="utf-8")
    assert "AI Executive Summary" in md
    assert "Recommended Fix Order" in md
    assert "Copy-paste config fix" in md
    html = (tmp_path / "scan-ai-synthesis" / "report.html").read_text(encoding="utf-8")
    assert "AI Executive Summary" in html
    assert "Recommended Fix Order" in html


def test_whitelist_covers_six_user_types() -> None:
    required = {
        "missing-csp",
        "missing-x-frame-options",
        "weak-hsts",
        "missing-x-content-type-options",
        "missing-referrer-policy",
        "cors-wildcard",
    }
    assert required.issubset(DETERMINISTIC_FIX_TYPES)
