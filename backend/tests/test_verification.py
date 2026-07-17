"""Tests for the active finding-verification agent and confidence-weighted scoring."""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")

from agents.scoring import run_scoring
from agents.state import ScanState
from agents.verification import ActiveVerifier, run_verification_async

_BASE_URL = "https://authorized.example.com/"


def _finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "tool": "header-checks",
        "type": "cors-wildcard",
        "url": _BASE_URL,
        "severity": "low",
        "description": "CORS wildcard",
        "evidence": None,
        "raw_data": {},
    }
    base.update(overrides)
    return base


def _response(
    *,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    text: str = "",
    status_code: int = 200,
) -> httpx.Response:
    header_list: list[tuple[str, str]] = []
    if isinstance(headers, dict):
        header_list = list(headers.items())
    elif isinstance(headers, list):
        header_list = headers
    return httpx.Response(status_code, headers=header_list, text=text)


class FakeClient:
    """Injectable stand-in for httpx.AsyncClient used by ActiveVerifier."""

    def __init__(
        self,
        responses: dict[str, httpx.Response] | None = None,
        *,
        raise_for: set[str] | None = None,
    ) -> None:
        self._responses = responses or {}
        self._raise_for = raise_for or set()
        self.requested: list[str] = []

    async def get(self, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        self.requested.append(url)
        if url in self._raise_for:
            raise httpx.ConnectError("no route to host")
        if url in self._responses:
            return self._responses[url]
        raise httpx.ConnectError("no route to host")

    async def aclose(self) -> None:  # pragma: no cover - not used with injection
        pass


async def _verify_single(finding: dict[str, Any], client: FakeClient) -> dict[str, Any]:
    verifier = ActiveVerifier(client=client)
    result = await verifier.verify([finding])
    return result[0]


class TestHeaderChecks:
    @pytest.mark.asyncio
    async def test_cors_wildcard_confirmed(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )
        result = await _verify_single(_finding(type="cors-wildcard"), client)
        assert result["verification"]["status"] == "confirmed"
        assert result["confidence"] == 0.99
        assert "Access-Control-Allow-Origin: *" in result["verification"]["evidence"]
        assert not result.get("likely_false_positive")

    @pytest.mark.asyncio
    async def test_cors_wildcard_refuted(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "https://trusted.example"})}
        )
        result = await _verify_single(_finding(type="cors-wildcard"), client)
        assert result["verification"]["status"] == "refuted"
        assert result["confidence"] == 0.1
        assert result["likely_false_positive"] is True

    @pytest.mark.asyncio
    async def test_csp_unsafe_inline_confirmed(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"})}
        )
        result = await _verify_single(_finding(type="csp-unsafe-inline"), client)
        assert result["verification"]["status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_missing_csp_confirmed_when_absent(self) -> None:
        client = FakeClient({_BASE_URL: _response(headers={})})
        result = await _verify_single(_finding(type="missing-csp"), client)
        assert result["verification"]["status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_missing_csp_refuted_when_present(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"content-security-policy": "default-src 'self'"})}
        )
        result = await _verify_single(_finding(type="missing-csp"), client)
        assert result["verification"]["status"] == "refuted"

    @pytest.mark.asyncio
    async def test_insecure_cookie_confirmed(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers=[("set-cookie", "sid=abc; Path=/")])}
        )
        finding = _finding(type="insecure-cookie", raw_data={"cookie": "sid"})
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "confirmed"


class TestZapChecks:
    @pytest.mark.asyncio
    async def test_zap_cors_confirmed(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )
        finding = _finding(
            tool="zap",
            type="zap-10098",
            description="Cross-Domain Misconfiguration: ...",
        )
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_zap_cache_confirmed_with_age(self) -> None:
        client = FakeClient({_BASE_URL: _response(headers={"age": "120"})})
        finding = _finding(
            tool="zap", type="zap-10050", description="Retrieved from Cache: ..."
        )
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "confirmed"
        assert "Age: 120" in result["verification"]["evidence"]

    @pytest.mark.asyncio
    async def test_zap_cache_refuted_without_cache_headers(self) -> None:
        client = FakeClient({_BASE_URL: _response(headers={})})
        finding = _finding(
            tool="zap", type="zap-10050", description="Retrieved from Cache: ..."
        )
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "refuted"

    @pytest.mark.asyncio
    async def test_zap_timestamp_confirmed_when_token_in_body(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(text="build stamp 1609459200 here")}
        )
        finding = _finding(
            tool="zap",
            type="zap-10096",
            description="Timestamp Disclosure - Unix",
            evidence="1609459200",
        )
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "confirmed"


class TestToolAttested:
    @pytest.mark.asyncio
    async def test_sqlmap_is_tool_attested(self) -> None:
        client = FakeClient({})
        finding = _finding(tool="sqlmap", type="sqli", url="https://authorized.example.com/item?id=1")
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "tool_attested"
        assert result["confidence"] == 0.95
        # sqlmap findings are not re-fetched.
        assert client.requested == []

    @pytest.mark.asyncio
    async def test_testssl_is_tool_attested(self) -> None:
        client = FakeClient({})
        finding = _finding(tool="testssl", type="tls-weak-cipher")
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "tool_attested"


class TestGenericEvidenceMatch:
    @pytest.mark.asyncio
    async def test_nuclei_confirmed_when_token_in_body(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(text="leaked AKIAEXAMPLESECRETKEY here")}
        )
        finding = _finding(
            tool="nuclei",
            type="exposure-config",
            raw_data={"extracted-results": ["AKIAEXAMPLESECRETKEY"]},
        )
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_nuclei_refuted_when_token_absent(self) -> None:
        client = FakeClient({_BASE_URL: _response(text="nothing sensitive here")})
        finding = _finding(
            tool="nuclei",
            type="exposure-config",
            raw_data={"extracted-results": ["AKIAEXAMPLESECRETKEY"]},
        )
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "refuted"
        assert result["likely_false_positive"] is True

    @pytest.mark.asyncio
    async def test_no_evidence_falls_back_to_tool_attested(self) -> None:
        client = FakeClient({_BASE_URL: _response(text="page")})
        finding = _finding(tool="nuclei", type="some-check", raw_data={}, evidence=None)
        result = await _verify_single(finding, client)
        assert result["verification"]["status"] == "tool_attested"


class TestUnreachable:
    @pytest.mark.asyncio
    async def test_unreachable_when_fetch_fails(self) -> None:
        client = FakeClient(raise_for={_BASE_URL})
        result = await _verify_single(_finding(type="cors-wildcard"), client)
        assert result["verification"]["status"] == "unreachable"
        assert result["confidence"] == 0.5
        assert not result.get("likely_false_positive")

    @pytest.mark.asyncio
    async def test_http_404_is_treated_as_unreachable_not_refuted(self) -> None:
        client = FakeClient({_BASE_URL: _response(status_code=404, text="not found")})
        result = await _verify_single(_finding(type="missing-csp"), client)
        assert result["verification"]["status"] == "unreachable"
        assert result["confidence"] == 0.5
        assert not result.get("likely_false_positive")


class TestResponseCaching:
    @pytest.mark.asyncio
    async def test_same_url_fetched_once(self) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )
        verifier = ActiveVerifier(client=client)
        await verifier.verify(
            [
                _finding(type="cors-wildcard"),
                _finding(type="missing-csp"),
            ]
        )
        assert client.requested.count(_BASE_URL) == 1


class TestConfidenceWeightedScoring:
    """Scoring must down-weight low-confidence findings without hiding them."""

    def _state_with(self, findings: list[dict[str, Any]]) -> ScanState:
        return {
            "scan_id": "s",
            "target": "https://authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {},
            "planned_active_tests": [],
            "findings": findings,
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": False,
            "human_approved": False,
        }

    def test_default_confidence_is_backward_compatible(self) -> None:
        findings = [_finding(severity="high")]
        result = run_scoring(self._state_with(findings))
        assert result["severity_scores"]["overall_risk_score"] == 6.0
        assert result["severity_scores"]["likely_false_positives"] == 0

    def test_low_confidence_reduces_overall_risk(self) -> None:
        high_conf = _finding(severity="high", confidence=1.0)
        low_conf = _finding(
            severity="high",
            confidence=0.1,
            likely_false_positive=True,
            verification={"status": "refuted"},
        )

        base = run_scoring(self._state_with([high_conf]))
        lowered = run_scoring(self._state_with([low_conf]))

        assert (
            lowered["severity_scores"]["overall_risk_score"]
            < base["severity_scores"]["overall_risk_score"]
        )
        assert lowered["severity_scores"]["likely_false_positives"] == 1
        assert lowered["severity_scores"]["total_findings"] == 1
        assert lowered["severity_scores"]["severity_counts"]["high"] == 1


class TestVerificationNode:
    @pytest.mark.asyncio
    async def test_run_verification_async_enriches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )

        # Inject the fake client into the verifier the node creates.
        import agents.verification as verification_module

        real_init = verification_module.ActiveVerifier.__init__

        def _patched_init(self: Any, client_arg: Any = None) -> None:
            real_init(self, client=client)

        monkeypatch.setattr(
            verification_module.ActiveVerifier, "__init__", _patched_init
        )

        state = {"findings": [_finding(type="cors-wildcard")], "recon_results": {}}
        result = await run_verification_async(state)  # type: ignore[arg-type]
        assert result["status"] == "verifying"
        assert result["findings"][0]["verification"]["status"] == "confirmed"
        assert result["_verification_metadata"]["confirmed"] == 1

    @pytest.mark.asyncio
    async def test_empty_findings_short_circuits(self) -> None:
        result = await run_verification_async({"findings": [], "recon_results": {}})  # type: ignore[arg-type]
        assert result["findings"] == []
        assert result["status"] == "verifying"
