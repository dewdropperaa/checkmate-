"""Tests for the finding-verification agent and confidence-weighted scoring."""

from __future__ import annotations

import os
from typing import Any

import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")

from agents.scoring import run_scoring
from agents.state import ScanState
from agents.verification import FindingVerifier, run_verification_async


def _finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "tool": "nuclei",
        "type": "exposure-config",
        "url": "https://authorized.example.com/config",
        "severity": "high",
        "description": "Exposed config",
        "evidence": None,
        "raw_data": {},
    }
    base.update(overrides)
    return base


def _page(url: str, markdown: str) -> dict[str, str]:
    return {"url": url, "markdown": markdown}


class FakeFirecrawl:
    """Stand-in FirecrawlTool exposing an async scrape_content."""

    def __init__(self, content_by_url: dict[str, str | None]) -> None:
        self._content = content_by_url
        self.scraped: list[str] = []

    async def scrape_content(self, url: str, timeout: float | None = None) -> str | None:
        self.scraped.append(url)
        return self._content.get(url)


class TestClassification:
    """Only content-based findings are corroborated; others untouched."""

    @pytest.mark.asyncio
    async def test_header_finding_not_applicable(self) -> None:
        findings = [
            _finding(tool="header-checks", type="missing-csp", raw_data={}, evidence="No CSP")
        ]
        verifier = FindingVerifier(pages=[])
        result = await verifier.verify(findings)
        assert result[0]["verification"]["status"] == "not_applicable"
        assert result[0]["confidence"] == 1.0
        assert "likely_false_positive" not in result[0]

    @pytest.mark.asyncio
    async def test_tls_and_sqli_not_applicable(self) -> None:
        findings = [
            _finding(tool="testssl", type="tls-weak-cipher"),
            _finding(tool="sqlmap", type="sqli"),
            _finding(tool="retirejs", type="vulnerable-js-jquery"),
        ]
        verifier = FindingVerifier(pages=[])
        result = await verifier.verify(findings)
        assert all(f["verification"]["status"] == "not_applicable" for f in result)
        assert all(f["confidence"] == 1.0 for f in result)


class TestCorroboration:
    """Content-based findings are confirmed/denied against page content."""

    @pytest.mark.asyncio
    async def test_confirmed_when_token_in_cached_page(self) -> None:
        findings = [
            _finding(
                raw_data={"extracted-results": ["AKIAEXAMPLESECRETKEY"]},
                evidence="Extracted: AKIAEXAMPLESECRETKEY",
            )
        ]
        pages = [
            _page(
                "https://authorized.example.com/config",
                "Config dump: AKIAEXAMPLESECRETKEY is here",
            )
        ]
        verifier = FindingVerifier(pages=pages)
        result = await verifier.verify(findings)
        v = result[0]["verification"]
        assert v["status"] == "confirmed"
        assert "AKIAEXAMPLESECRETKEY" in v["matched"]
        assert result[0]["confidence"] == 0.98
        assert not result[0].get("likely_false_positive")

    @pytest.mark.asyncio
    async def test_unconfirmed_flags_likely_false_positive(self) -> None:
        findings = [
            _finding(raw_data={"extracted-results": ["AKIAEXAMPLESECRETKEY"]})
        ]
        pages = [
            _page(
                "https://authorized.example.com/config",
                "This page has nothing sensitive at all",
            )
        ]
        verifier = FindingVerifier(pages=pages)
        result = await verifier.verify(findings)
        assert result[0]["verification"]["status"] == "unconfirmed"
        assert result[0]["likely_false_positive"] is True
        assert result[0]["confidence"] == 0.4

    @pytest.mark.asyncio
    async def test_unverified_when_no_content_available(self) -> None:
        # Firecrawl disabled in conftest and no page cache -> content is None.
        findings = [
            _finding(raw_data={"extracted-results": ["AKIAEXAMPLESECRETKEY"]})
        ]
        verifier = FindingVerifier(
            pages=[], firecrawl=FakeFirecrawl({})  # returns None for the URL
        )
        result = await verifier.verify(findings)
        assert result[0]["verification"]["status"] == "unverified"
        assert result[0]["confidence"] == 0.8
        assert not result[0].get("likely_false_positive")

    @pytest.mark.asyncio
    async def test_no_signature_when_no_tokens(self) -> None:
        findings = [_finding(raw_data={}, evidence="Matcher: status")]
        verifier = FindingVerifier(pages=[])
        result = await verifier.verify(findings)
        assert result[0]["verification"]["status"] == "no_signature"
        assert result[0]["confidence"] == 1.0

    @pytest.mark.asyncio
    async def test_scrapes_url_when_not_cached(self) -> None:
        url = "https://authorized.example.com/config"
        findings = [
            _finding(raw_data={"extracted-results": ["SENSITIVE_TOKEN_XYZ"]})
        ]
        fake = FakeFirecrawl({url: "leaked SENSITIVE_TOKEN_XYZ found"})
        verifier = FindingVerifier(pages=[], firecrawl=fake)
        result = await verifier.verify(findings)
        assert fake.scraped == [url]
        assert result[0]["verification"]["status"] == "confirmed"


class TestScrapeBudget:
    """On-demand scraping must respect the configured budget."""

    @pytest.mark.asyncio
    async def test_budget_limits_scrapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agents.verification as verification_module

        settings = verification_module.get_settings()
        monkeypatch.setattr(settings, "firecrawl_verify_max_urls", 1, raising=False)

        findings = [
            _finding(url="https://authorized.example.com/a", raw_data={"extracted-results": ["TOKENAAAA"]}),
            _finding(url="https://authorized.example.com/b", raw_data={"extracted-results": ["TOKENBBBB"]}),
        ]
        fake = FakeFirecrawl(
            {
                "https://authorized.example.com/a": "has TOKENAAAA",
                "https://authorized.example.com/b": "has TOKENBBBB",
            }
        )
        verifier = FindingVerifier(pages=[], firecrawl=fake)
        result = await verifier.verify(findings)

        # Only one URL scraped due to budget; second is unverified.
        assert len(fake.scraped) == 1
        statuses = {f["verification"]["status"] for f in result}
        assert "confirmed" in statuses
        assert "unverified" in statuses


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
        # high weight 6.0, confidence 1.0, max 1*10 -> 6.0
        assert result["severity_scores"]["overall_risk_score"] == 6.0
        assert result["severity_scores"]["likely_false_positives"] == 0

    def test_low_confidence_reduces_overall_risk(self) -> None:
        high_conf = _finding(severity="high", confidence=1.0)
        low_conf = _finding(
            severity="high",
            confidence=0.4,
            likely_false_positive=True,
            verification={"status": "unconfirmed"},
        )

        base = run_scoring(self._state_with([high_conf]))
        lowered = run_scoring(self._state_with([low_conf]))

        assert lowered["severity_scores"]["overall_risk_score"] < base["severity_scores"]["overall_risk_score"]
        assert lowered["severity_scores"]["likely_false_positives"] == 1
        # The finding is still present and counted (not hidden).
        assert lowered["severity_scores"]["total_findings"] == 1
        assert lowered["severity_scores"]["severity_counts"]["high"] == 1


class TestVerificationNode:
    """The graph-node wrapper returns enriched findings."""

    @pytest.mark.asyncio
    async def test_run_verification_async_enriches(self) -> None:
        state = {
            "findings": [_finding(raw_data={"extracted-results": ["MARKERTOKEN"]})],
            "recon_results": {
                "pages": [_page("https://authorized.example.com/config", "MARKERTOKEN present")]
            },
        }
        result = await run_verification_async(state)  # type: ignore[arg-type]
        assert result["status"] == "verifying"
        assert result["findings"][0]["verification"]["status"] == "confirmed"
        assert result["_verification_metadata"]["confirmed"] == 1

    @pytest.mark.asyncio
    async def test_empty_findings_short_circuits(self) -> None:
        result = await run_verification_async({"findings": [], "recon_results": {}})  # type: ignore[arg-type]
        assert result["findings"] == []
        assert result["status"] == "verifying"
