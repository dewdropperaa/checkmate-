"""Finding verification agent - corroborates findings against scraped content.

This LangGraph node runs after detection and before scoring. Its job is to
reduce false positives by checking whether content-based findings are actually
reflected in the target's live page content (fetched via Firecrawl).

Principles (deliberately conservative for a security tool):

- **Never delete findings.** Verification only annotates and adjusts a
  ``confidence`` score. A human still sees every finding.
- **Only corroborate content-based findings.** Nuclei/ZAP findings that carry
  body-extracted evidence tokens are checkable against page content. Header,
  TLS, SQLi, and JS-dependency findings are inferred from headers/handshakes/
  metadata, not page body, so they are marked ``not_applicable`` and left
  untouched.
- **Match against rich content.** Verification searches markdown + HTML +
  links so evidence living in scripts/attributes is not lost, which prevents
  wrongly flagging real findings as false positives.

Outcomes recorded per finding under ``verification.status``:

- ``confirmed``      - evidence token found in page content (confidence up).
- ``unconfirmed``    - content retrieved but no evidence token found; flagged
                       ``likely_false_positive`` with reduced confidence.
- ``unverified``     - content could not be retrieved (no penalty).
- ``no_signature``   - content-based finding without extractable tokens.
- ``not_applicable`` - finding type is not corroboratable via page body.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

from agents.state import ScanState
from core.config import get_settings
from tools.firecrawl_tool import FirecrawlTool

logger = logging.getLogger(__name__)

# Confidence assigned to each verification outcome.
_CONFIDENCE = {
    "confirmed": 0.98,
    "unconfirmed": 0.4,
    "unverified": 0.8,
    "no_signature": 1.0,
    "not_applicable": 1.0,
}

# Tools whose findings are matched against HTTP response content.
_CONTENT_TOOLS = frozenset({"nuclei", "zap"})

# Minimum token length to search for (avoids trivial/noisy matches).
_MIN_TOKEN_LEN = 4


def _normalize_url(url: str) -> str:
    """Normalize a URL for content-cache keying (drop fragment)."""
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _verification_mode(finding: dict[str, Any]) -> str:
    """Return 'content' if a finding is corroboratable, else 'not_applicable'."""
    tool = str(finding.get("tool", "")).lower()
    ftype = str(finding.get("type", "")).lower()

    if tool in ("header-checks", "testssl", "retirejs", "sqlmap"):
        return "not_applicable"
    if ftype.startswith(("tls-", "vulnerable-js-")) or ftype == "sqli":
        return "not_applicable"
    if tool in _CONTENT_TOOLS:
        return "content"
    return "not_applicable"


def _signature_tokens(finding: dict[str, Any]) -> list[str]:
    """Extract body-derived evidence tokens from a finding for matching."""
    tokens: list[str] = []
    raw = finding.get("raw_data") or {}

    extracted = raw.get("extracted-results") or raw.get("extracted_results")
    if isinstance(extracted, (list, tuple)):
        tokens.extend(str(x) for x in extracted)
    elif isinstance(extracted, str):
        tokens.append(extracted)

    for key in ("evidence", "attack", "other"):
        value = raw.get(key)
        if isinstance(value, str):
            tokens.append(value)

    evidence = finding.get("evidence")
    if isinstance(evidence, str) and "Extracted:" in evidence:
        after = evidence.split("Extracted:", 1)[1]
        tokens.extend(part.strip() for part in after.split(","))

    seen: set[str] = set()
    cleaned: list[str] = []
    for token in tokens:
        token = token.strip()
        if len(token) < _MIN_TOKEN_LEN:
            continue
        low = token.lower()
        if low in seen:
            continue
        seen.add(low)
        cleaned.append(token)
    return cleaned


class FindingVerifier:
    """Corroborates content-based findings against scraped page content."""

    def __init__(
        self,
        pages: list[dict[str, Any]] | None = None,
        firecrawl: FirecrawlTool | None = None,
    ) -> None:
        settings = get_settings()
        self._settings = settings
        self._firecrawl = firecrawl or FirecrawlTool(
            timeout=settings.firecrawl_verify_timeout
        )
        self._scrape_budget = settings.firecrawl_verify_max_urls
        self._allow_scrape = settings.firecrawl_verify_findings

        # Content cache: normalized URL -> lowercased searchable text.
        self._cache: dict[str, str | None] = {}
        for page in pages or []:
            url = page.get("url")
            text = page.get("markdown") or page.get("content") or ""
            if url and text:
                self._cache[_normalize_url(url)] = text.lower()

    async def _content_for(self, url: str) -> str | None:
        """Return lowercased page content for a URL (cache, then scrape)."""
        key = _normalize_url(url)
        if key in self._cache:
            return self._cache[key]

        if not self._allow_scrape or self._scrape_budget <= 0:
            self._cache[key] = None
            return None

        self._scrape_budget -= 1
        text = await self._firecrawl.scrape_content(
            key, timeout=self._settings.firecrawl_verify_timeout
        )
        lowered = text.lower() if text else None
        self._cache[key] = lowered
        return lowered

    async def verify(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return findings enriched with verification metadata + confidence."""
        verified: list[dict[str, Any]] = []
        stats = {
            "confirmed": 0,
            "unconfirmed": 0,
            "unverified": 0,
            "no_signature": 0,
            "not_applicable": 0,
        }

        for original in findings:
            finding = dict(original)
            mode = _verification_mode(finding)

            if mode == "not_applicable":
                status = "not_applicable"
                finding["verification"] = {
                    "status": status,
                    "method": "n/a",
                    "reason": "Finding type is not corroboratable via page body",
                }
                finding.setdefault("confidence", _CONFIDENCE[status])
                stats[status] += 1
                verified.append(finding)
                continue

            tokens = _signature_tokens(finding)
            if not tokens:
                status = "no_signature"
                finding["verification"] = {
                    "status": status,
                    "method": "content-corroboration",
                    "reason": "No body-derived evidence tokens to match",
                }
                finding["confidence"] = _CONFIDENCE[status]
                stats[status] += 1
                verified.append(finding)
                continue

            url = finding.get("url", "")
            content = await self._content_for(url) if url else None

            if content is None:
                status = "unverified"
                finding["verification"] = {
                    "status": status,
                    "method": "content-corroboration",
                    "checked_url": _normalize_url(url) if url else None,
                    "tokens_checked": len(tokens),
                    "reason": "Page content could not be retrieved",
                }
            else:
                matched = [t for t in tokens if t.lower() in content]
                if matched:
                    status = "confirmed"
                    finding["verification"] = {
                        "status": status,
                        "method": "content-corroboration",
                        "checked_url": _normalize_url(url),
                        "tokens_checked": len(tokens),
                        "matched": matched[:5],
                    }
                else:
                    status = "unconfirmed"
                    finding["likely_false_positive"] = True
                    finding["verification"] = {
                        "status": status,
                        "method": "content-corroboration",
                        "checked_url": _normalize_url(url),
                        "tokens_checked": len(tokens),
                        "matched": [],
                        "reason": (
                            "Evidence tokens absent from retrieved page content"
                        ),
                    }

            finding["confidence"] = _CONFIDENCE[status]
            stats[status] += 1
            verified.append(finding)

        logger.info(
            "Verification complete: %s confirmed, %s unconfirmed (likely FP), "
            "%s unverified, %s no-signature, %s not-applicable",
            stats["confirmed"],
            stats["unconfirmed"],
            stats["unverified"],
            stats["no_signature"],
            stats["not_applicable"],
        )
        self._stats = stats
        return verified


async def run_verification_async(state: ScanState) -> dict[str, Any]:
    """Async implementation of the verification node."""
    findings = state.get("findings", [])
    if not findings:
        return {"findings": findings, "status": "verifying"}

    recon_results = state.get("recon_results", {})
    pages = recon_results.get("pages", [])

    verifier = FindingVerifier(pages=pages)
    verified = await verifier.verify(findings)

    return {
        "findings": verified,
        "status": "verifying",
        "_verification_metadata": getattr(verifier, "_stats", {}),
    }


def run_verification(state: ScanState) -> dict[str, Any]:
    """LangGraph node entry point for finding verification."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        import nest_asyncio

        nest_asyncio.apply()
        return loop.run_until_complete(run_verification_async(state))
    return asyncio.run(run_verification_async(state))
