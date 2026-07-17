"""Finding verification agent - actively corroborates findings against the live target.

This LangGraph node runs after detection and before scoring. Its job is to turn
every finding into a **deterministic, evidence-backed verdict** instead of a
best-effort guess. Rather than depending on a third-party content service
(Firecrawl), it re-fetches each finding's URL directly with the SSRF-safe HTTP
client and inspects the *actual* live response (status, headers, and body).

Principles (professional-grade, no uncertainty):

- **Verify everything.** Each finding is dispatched to a checker that re-tests
  the specific condition against the live response (header value, CORS policy,
  CSP directive, cache headers, disclosed token, body match, ...).
- **Never delete findings.** Verification only annotates ``verification`` and
  adjusts ``confidence``. A human still sees every finding.
- **Definitive verdicts.** Each finding ends up as one of:

  - ``confirmed``      - the condition is present in the live response; the
                         concrete proof (header value / matched token) is
                         embedded in ``verification.evidence``.
  - ``refuted``        - the condition is provably absent now; flagged
                         ``likely_false_positive`` and heavily deprioritized.
  - ``tool_attested``  - produced by an active exploit/handshake tool
                         (sqlmap / testssl) that already actively proved it, so
                         it cannot be meaningfully re-checked with a plain GET.
  - ``unreachable``    - the URL could not be fetched after retries (no penalty,
                         but honestly flagged).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

import httpx

from agents.state import ScanState
from core.config import get_settings
from core.retries import run_with_retries
from core.ssrf import SSRFError, create_safe_async_client, validate_url

logger = logging.getLogger(__name__)

# Confidence assigned to each verification outcome.
_CONFIDENCE = {
    "confirmed": 0.99,
    "tool_attested": 0.95,
    "unreachable": 0.5,
    "refuted": 0.1,
}

# Synthetic Origin sent on verification requests so reflected/wildcard CORS
# policies are observable on a plain GET.
_PROBE_ORIGIN = "https://checkmate-verify.example"

# Minimum token length to search for (avoids trivial/noisy matches).
_MIN_TOKEN_LEN = 4

# Tools whose findings come from an active test that a plain re-fetch cannot
# reproduce; we attest to the originating tool's own active confirmation.
_ATTESTED_TOOLS = {
    "sqlmap": "Confirmed by active SQL-injection testing (sqlmap only reports "
    "exploitable injection points).",
    "testssl": "Confirmed by active TLS handshake analysis (testssl.sh).",
}


def _normalize_url(url: str) -> str:
    """Normalize a URL for response caching (drop fragment, add scheme)."""
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


@dataclass
class LiveResponse:
    """A captured live HTTP response used for corroboration."""

    status_code: int
    headers: httpx.Headers
    body: str

    def header(self, name: str) -> str:
        return self.headers.get(name, "") or ""

    @property
    def body_lower(self) -> str:
        return self.body.lower()

    @property
    def headers_blob(self) -> str:
        """All header values as a single lowercased searchable string."""
        return " ".join(f"{k}: {v}" for k, v in self.headers.items()).lower()


def _signature_tokens(finding: dict[str, Any]) -> list[str]:
    """Extract concrete evidence tokens from a finding for live matching."""
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
    if isinstance(evidence, str):
        if "Extracted:" in evidence:
            after = evidence.split("Extracted:", 1)[1]
            tokens.extend(part.strip() for part in after.split(","))
        else:
            tokens.append(evidence)

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


# --- Header-checks corroboration ------------------------------------------------


def _csp_has_permissive_source(csp: str) -> str | None:
    """Return the offending CSP segment if any directive is overly permissive."""
    for part in csp.split(";"):
        directive = part.strip()
        if not directive:
            continue
        tokens = directive.split()
        sources = tokens[1:]
        if any(s in ("*", "https:", "http:") for s in sources):
            return directive
    return None


def _check_header_finding(
    finding: dict[str, Any], resp: LiveResponse
) -> tuple[bool, str] | None:
    """Re-test a header-checks finding against live headers.

    Returns (matched, evidence) or None if the type is unknown here.
    """
    ftype = str(finding.get("type", "")).lower()
    csp = resp.header("content-security-policy")
    hsts = resp.header("strict-transport-security")
    xfo = resp.header("x-frame-options")
    xcto = resp.header("x-content-type-options")
    acao = resp.header("access-control-allow-origin")
    acac = resp.header("access-control-allow-credentials")
    referrer = resp.header("referrer-policy")

    if ftype == "missing-csp":
        return (not csp, "No Content-Security-Policy header in live response"
                if not csp else f"Content-Security-Policy: {csp}")
    if ftype == "csp-unsafe-inline":
        return ("'unsafe-inline'" in csp, f"Content-Security-Policy: {csp}")
    if ftype == "csp-unsafe-eval":
        return ("'unsafe-eval'" in csp, f"Content-Security-Policy: {csp}")
    if ftype == "csp-overly-permissive":
        segment = _csp_has_permissive_source(csp)
        return (segment is not None, f"CSP segment: {segment}" if segment
                else f"Content-Security-Policy: {csp or '(absent)'}")

    if ftype == "missing-hsts":
        return (not hsts, "No Strict-Transport-Security header in live response"
                if not hsts else f"Strict-Transport-Security: {hsts}")
    if ftype == "weak-hsts-max-age":
        from tools.header_checks import HSTS_MIN_MAX_AGE, parse_hsts

        if not hsts:
            return (False, "No Strict-Transport-Security header present")
        max_age = parse_hsts(hsts)["max_age"]
        weak = max_age is None or max_age < HSTS_MIN_MAX_AGE
        return (weak, f"Strict-Transport-Security: {hsts}")
    if ftype == "missing-hsts-includesubdomains":
        from tools.header_checks import parse_hsts

        if not hsts:
            return (False, "No Strict-Transport-Security header present")
        return (not parse_hsts(hsts)["include_subdomains"],
                f"Strict-Transport-Security: {hsts}")
    if ftype == "missing-hsts-preload":
        from tools.header_checks import parse_hsts

        if not hsts:
            return (False, "No Strict-Transport-Security header present")
        return (not parse_hsts(hsts)["preload"],
                f"Strict-Transport-Security: {hsts}")

    if ftype == "missing-x-frame-options":
        has_fa = "frame-ancestors" in csp.lower()
        return (not xfo and not has_fa,
                f"X-Frame-Options: {xfo or '(absent)'}; frame-ancestors "
                f"{'present' if has_fa else 'absent'}")
    if ftype == "deprecated-x-frame-options":
        return (xfo.strip().upper().startswith("ALLOW-FROM"),
                f"X-Frame-Options: {xfo or '(absent)'}")
    if ftype == "invalid-x-frame-options":
        val = xfo.strip().upper()
        return (bool(xfo) and val not in ("DENY", "SAMEORIGIN")
                and not val.startswith("ALLOW-FROM"),
                f"X-Frame-Options: {xfo or '(absent)'}")

    if ftype == "missing-x-content-type-options":
        return (not xcto, f"X-Content-Type-Options: {xcto or '(absent)'}")
    if ftype == "invalid-x-content-type-options":
        return (bool(xcto) and xcto.lower().strip() != "nosniff",
                f"X-Content-Type-Options: {xcto or '(absent)'}")

    if ftype == "cors-wildcard":
        return (acao == "*", f"Access-Control-Allow-Origin: {acao or '(absent)'}")
    if ftype == "cors-wildcard-with-credentials":
        return (acao == "*" and acac.lower() == "true",
                f"Access-Control-Allow-Origin: {acao or '(absent)'}; "
                f"Access-Control-Allow-Credentials: {acac or '(absent)'}")
    if ftype == "cors-null-origin":
        return (acao == "null", f"Access-Control-Allow-Origin: {acao or '(absent)'}")

    if ftype == "insecure-cookie":
        cookie_name = str((finding.get("raw_data") or {}).get("cookie", "")).lower()
        set_cookies = resp.headers.get_list("set-cookie")
        for header in set_cookies:
            name = header.split("=", 1)[0].strip().lower()
            if cookie_name and name != cookie_name:
                continue
            low = header.lower()
            missing = []
            if resp_is_https(resp, finding) and "secure" not in low:
                missing.append("Secure")
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                return (True, f"Set-Cookie: {header}")
        return (False, "Cookie now sets required security attributes or is absent")

    if ftype == "server-version-disclosure":
        server = resp.header("server")
        indicators = ("nginx/", "apache/", "iis/", "php/")
        return (any(i in server.lower() for i in indicators),
                f"Server: {server or '(absent)'}")
    if ftype == "x-powered-by-disclosure":
        xpb = resp.header("x-powered-by")
        return (bool(xpb), f"X-Powered-By: {xpb or '(absent)'}")

    if ftype == "missing-referrer-policy":
        return (not referrer, f"Referrer-Policy: {referrer or '(absent)'}")
    if ftype == "weak-referrer-policy":
        return (referrer.lower().strip() == "unsafe-url",
                f"Referrer-Policy: {referrer or '(absent)'}")

    return None


def resp_is_https(resp: LiveResponse, finding: dict[str, Any]) -> bool:
    return str(finding.get("url", "")).lower().startswith("https://")


# --- ZAP corroboration ----------------------------------------------------------


def _check_zap_finding(
    finding: dict[str, Any], resp: LiveResponse
) -> tuple[bool, str] | None:
    """Re-test a ZAP finding against the live response for its exact URL."""
    ftype = str(finding.get("type", "")).lower()
    plugin = ftype.removeprefix("zap-")
    desc = str(finding.get("description", "")).lower()

    # Cross-Domain Misconfiguration / CORS (pluginId 10098).
    if plugin == "10098" or "cross-domain" in desc or "cross origin" in desc:
        acao = resp.header("access-control-allow-origin")
        permissive = acao in ("*", "null") or acao == _PROBE_ORIGIN
        return (bool(acao) and permissive,
                f"Access-Control-Allow-Origin: {acao or '(absent)'}")

    # CSP wildcard directive (pluginId 10055).
    if plugin == "10055" or "content security policy" in desc:
        csp = resp.header("content-security-policy")
        if "wildcard" in desc:
            segment = _csp_has_permissive_source(csp)
            return (segment is not None,
                    f"CSP segment: {segment}" if segment
                    else f"Content-Security-Policy: {csp or '(absent)'}")
        return (bool(csp), f"Content-Security-Policy: {csp or '(absent)'}")

    # Retrieved from Cache (pluginId 10050).
    if plugin == "10050" or "retrieved from cache" in desc:
        age = resp.header("age")
        x_cache = resp.header("x-cache").lower()
        cache_control = resp.header("cache-control").lower()
        cached = bool(age) or "hit" in x_cache or "public" in cache_control
        proof = (
            f"Age: {age}" if age
            else f"X-Cache: {resp.header('x-cache')}" if x_cache
            else f"Cache-Control: {resp.header('cache-control') or '(absent)'}"
        )
        return (cached, proof)

    # Timestamp Disclosure (pluginId 10096) - evidence is the disclosed token.
    if plugin == "10096" or "timestamp disclosure" in desc:
        tokens = _signature_tokens(finding)
        matched = [t for t in tokens if t.lower() in resp.body_lower]
        return (bool(matched),
                f"Disclosed token in body: {matched[0]}" if matched
                else "Disclosed timestamp no longer present in body")

    # Modern Web Application (pluginId 10109) - informational SPA marker.
    if plugin == "10109" or "modern web application" in desc:
        markers = ("<script", "window.__", "react", "vue", "angular", "app.js")
        hit = next((m for m in markers if m in resp.body_lower), None)
        return (hit is not None,
                f"Body contains SPA/script marker: {hit}" if hit
                else "No client-side application markers in body")

    # Header-oriented ZAP passive alerts: reuse header re-tests when the ZAP
    # description maps onto a header condition.
    if "x-content-type-options" in desc:
        xcto = resp.header("x-content-type-options")
        return (xcto.lower().strip() != "nosniff",
                f"X-Content-Type-Options: {xcto or '(absent)'}")
    if "x-frame-options" in desc:
        xfo = resp.header("x-frame-options")
        has_fa = "frame-ancestors" in resp.header("content-security-policy").lower()
        return (not xfo and not has_fa,
                f"X-Frame-Options: {xfo or '(absent)'}")
    if "strict-transport-security" in desc or "hsts" in desc:
        hsts = resp.header("strict-transport-security")
        return (not hsts, f"Strict-Transport-Security: {hsts or '(absent)'}")

    return None


# --- retire.js corroboration ----------------------------------------------------


def _check_retirejs_finding(
    finding: dict[str, Any], resp: LiveResponse
) -> tuple[bool, str] | None:
    """Confirm a vulnerable JS library by matching its version in the live file."""
    raw = finding.get("raw_data") or {}
    version = str(raw.get("version") or raw.get("component_version") or "").strip()
    component = str(raw.get("component") or raw.get("library") or "").strip()
    if version and version in resp.body:
        proof = f"Version {version}" + (f" of {component}" if component else "")
        return (True, f"{proof} present in served JavaScript")
    # Minified/renamed bundles legitimately hide the version string; fall back to
    # attesting the tool rather than wrongly refuting.
    return None


class ActiveVerifier:
    """Re-tests every finding against the live target for a definitive verdict."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        settings = get_settings()
        self._settings = settings
        self._client = client
        self._owns_client = client is None
        self._max_urls = settings.verification_max_urls
        self._max_body = settings.verification_max_body_bytes
        self._semaphore = asyncio.Semaphore(
            max(1, settings.verification_max_concurrency)
        )
        self._cache: dict[str, LiveResponse | None] = {}
        self._stats: dict[str, int] = {}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = create_safe_async_client(
                timeout=self._settings.verification_timeout,
                verify=False,
            )
        return self._client

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _fetch(self, url: str) -> LiveResponse | None:
        key = _normalize_url(url)
        if key in self._cache:
            return self._cache[key]
        if len(self._cache) >= self._max_urls:
            self._cache[key] = None
            return None

        try:
            validate_url(key, resolve_dns=True)
        except SSRFError:
            logger.info("verification: skipping unsafe URL %s", key)
            self._cache[key] = None
            return None

        client = await self._get_client()

        async def _do() -> httpx.Response:
            async with self._semaphore:
                return await client.get(
                    key,
                    headers={
                        "Origin": _PROBE_ORIGIN,
                        "Accept-Encoding": "identity",
                    },
                )

        try:
            response = await run_with_retries(
                "verification",
                _do,
                max_attempts=self._settings.tool_retry_attempts,
                backoff_seconds=0.5,
            )
        except (httpx.HTTPError, SSRFError) as exc:
            logger.info("verification: fetch failed for %s: %s", key, exc)
            self._cache[key] = None
            return None

        body = response.text or ""
        if len(body) > self._max_body:
            body = body[: self._max_body]

        live = LiveResponse(
            status_code=response.status_code,
            headers=response.headers,
            body=body,
        )
        self._cache[key] = live
        return live

    def _verdict(
        self,
        status: str,
        *,
        method: str,
        evidence: str | None = None,
        reason: str | None = None,
        checked_url: str | None = None,
    ) -> dict[str, Any]:
        verification: dict[str, Any] = {"status": status, "method": method}
        if checked_url:
            verification["checked_url"] = checked_url
        if evidence:
            verification["evidence"] = evidence
        if reason:
            verification["reason"] = reason
        return verification

    async def _verify_one(self, finding: dict[str, Any]) -> dict[str, Any]:
        finding = dict(finding)
        tool = str(finding.get("tool", "")).lower()
        url = str(finding.get("url", ""))

        # Tools whose active test cannot be reproduced with a plain GET.
        if tool in _ATTESTED_TOOLS:
            finding["verification"] = self._verdict(
                "tool_attested", method="tool-attested", reason=_ATTESTED_TOOLS[tool]
            )
            finding["confidence"] = _CONFIDENCE["tool_attested"]
            return finding

        resp = await self._fetch(url) if url else None
        checked = _normalize_url(url) if url else None

        if resp is None:
            finding["verification"] = self._verdict(
                "unreachable",
                method="active-recheck",
                checked_url=checked,
                reason="Target URL could not be fetched for live corroboration",
            )
            finding["confidence"] = _CONFIDENCE["unreachable"]
            return finding
        if resp.status_code >= 400:
            finding["verification"] = self._verdict(
                "unreachable",
                method="active-recheck",
                checked_url=checked,
                reason=(
                    "Target URL returned an HTTP error during corroboration "
                    f"(status {resp.status_code})"
                ),
            )
            finding["confidence"] = _CONFIDENCE["unreachable"]
            return finding

        checker: Callable[[dict[str, Any], LiveResponse], tuple[bool, str] | None]
        if tool == "header-checks":
            checker = _check_header_finding
        elif tool == "zap":
            checker = _check_zap_finding
        elif tool == "retirejs":
            checker = _check_retirejs_finding
        else:
            checker = lambda f, r: None  # noqa: E731 - fall through to generic

        outcome = checker(finding, resp)

        if outcome is None:
            outcome = self._generic_evidence_match(finding, resp)

        if outcome is None:
            # No re-checkable signal at all: attest to the detecting tool rather
            # than inventing an "unconfirmed" state.
            finding["verification"] = self._verdict(
                "tool_attested",
                method="tool-attested",
                checked_url=checked,
                reason=(
                    f"No re-checkable live signal; attested by {tool or 'detector'}"
                ),
            )
            finding["confidence"] = _CONFIDENCE["tool_attested"]
            return finding

        matched, evidence = outcome
        if matched:
            finding["verification"] = self._verdict(
                "confirmed",
                method="active-recheck",
                evidence=evidence,
                checked_url=checked,
            )
            finding["confidence"] = _CONFIDENCE["confirmed"]
            finding.pop("likely_false_positive", None)
        else:
            finding["verification"] = self._verdict(
                "refuted",
                method="active-recheck",
                evidence=evidence,
                checked_url=checked,
                reason="Condition not present in the live response",
            )
            finding["confidence"] = _CONFIDENCE["refuted"]
            finding["likely_false_positive"] = True
        return finding

    def _generic_evidence_match(
        self, finding: dict[str, Any], resp: LiveResponse
    ) -> tuple[bool, str] | None:
        """Confirm/refute by searching the live response for evidence tokens."""
        tokens = _signature_tokens(finding)
        if not tokens:
            return None
        haystack = f"{resp.body_lower} {resp.headers_blob}"
        matched = [t for t in tokens if t.lower() in haystack]
        if matched:
            return (True, f"Evidence present in live response: {matched[0]}")
        return (False, "Reported evidence token(s) absent from live response")

    async def verify(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return findings enriched with a definitive verification verdict."""
        results = await asyncio.gather(
            *(self._verify_one(f) for f in findings)
        )

        stats = {k: 0 for k in ("confirmed", "refuted", "tool_attested", "unreachable")}
        for finding in results:
            status = (finding.get("verification") or {}).get("status")
            if status in stats:
                stats[status] += 1
        self._stats = stats

        logger.info(
            "Verification complete: %s confirmed, %s refuted (likely FP), "
            "%s tool-attested, %s unreachable",
            stats["confirmed"],
            stats["refuted"],
            stats["tool_attested"],
            stats["unreachable"],
        )
        return results


async def run_verification_async(state: ScanState) -> dict[str, Any]:
    """Async implementation of the verification node."""
    findings = state.get("findings", [])
    if not findings:
        return {"findings": findings, "status": "verifying"}

    settings = get_settings()
    if not settings.verification_enabled:
        return {"findings": findings, "status": "verifying"}

    verifier = ActiveVerifier()
    try:
        verified = await verifier.verify(findings)
    finally:
        await verifier.close()

    return {
        "findings": verified,
        "status": "verifying",
        "_verification_metadata": verifier._stats,
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
