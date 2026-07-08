"""Pure Python HTTP security header and cookie checker.

This module checks for common security header misconfigurations:
- Missing or weak Content-Security-Policy (CSP)
- Missing or incomplete Strict-Transport-Security (HSTS)
- Missing X-Frame-Options
- Missing X-Content-Type-Options
- Cookie security flags (Secure, HttpOnly, SameSite)
- CORS misconfigurations

Security headers are attributed once per origin (scheme + host), not once
per crawled path, to avoid duplicate findings.

No subprocess calls - uses httpx for HTTP requests.

Security considerations:
- Passive checks only - just reads headers
- Scope re-validated before each request
- Rate-limited to avoid hammering targets
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

from core.scope import is_target_authorized
from tools.base import ToolResult, validate_scope
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

# One year in seconds — minimum recommended HSTS max-age.
HSTS_MIN_MAX_AGE = 31536000
# Two years — preferred max-age for HSTS preload readiness.
HSTS_IDEAL_MAX_AGE = 63072000

_MAX_AGE_RE = re.compile(r"(?:^|;)\s*max-age\s*=\s*(\d+)", re.IGNORECASE)


def normalize_origin(url: str) -> str:
    """Return scheme://host[:port], ignoring path/query/fragment."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc
    if not netloc and parsed.path:
        # Bare host passed without scheme handling quirks.
        netloc = parsed.path.split("/")[0]
    return f"{scheme}://{netloc}"


def parse_hsts(header_value: str) -> dict[str, Any]:
    """Parse Strict-Transport-Security into structured fields."""
    value = header_value.strip()
    lower = value.lower()
    max_age: int | None = None
    match = _MAX_AGE_RE.search(value)
    if match:
        try:
            max_age = int(match.group(1))
        except ValueError:
            max_age = None

    # Directive tokens are semicolon-separated; avoid substring false positives.
    directives = {part.strip().lower().split("=", 1)[0] for part in lower.split(";") if part.strip()}
    return {
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in directives,
        "preload": "preload" in directives,
        "raw": value,
    }


class HeaderCheckInput(BaseModel):
    """Input schema for header checks with validation."""

    urls: list[str] = Field(
        ...,
        description="List of URLs to check",
        min_length=1,
    )

    @field_validator("urls")
    @classmethod
    def validate_urls_in_scope(cls, v: list[str]) -> list[str]:
        """Ensure all URLs are within the authorized scope."""
        for url in v:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not is_target_authorized(host):
                raise ValueError(
                    f"URL '{url}' is not in the authorized scope. "
                    "Scan aborted for safety."
                )
        return v


class HeaderChecker:
    """
    HTTP security header and cookie analyzer.

    Pure Python implementation - no subprocess calls.
    Header findings are emitted once per unique origin per scan.
    """

    name = "header-checks"
    description = "HTTP security header and cookie analyzer"

    def __init__(self, timeout: float = 30.0, rate_limit_delay: float = 0.5):
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _group_urls_by_origin(self, urls: list[str]) -> dict[str, list[str]]:
        """Collapse crawled URLs to unique origins with a seen-at history."""
        groups: dict[str, list[str]] = {}
        for raw in urls:
            url = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
            origin = normalize_origin(url)
            groups.setdefault(origin, [])
            if url not in groups[origin]:
                groups[origin].append(url)
        return groups

    def _with_seen_at(
        self,
        findings: list[Finding],
        seen_at: list[str],
    ) -> list[Finding]:
        """Attach optional seen-at URL list without emitting extra rows."""
        if not seen_at:
            return findings
        for finding in findings:
            raw = dict(finding.raw_data or {})
            raw["seen_at"] = list(seen_at)
            finding.raw_data = raw
        return findings

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Check security headers for a single URL (analyzed at origin scope).

        Args:
            target: URL to check
            scope: Scope metadata

        Returns:
            ToolResult with header findings
        """
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        origin = normalize_origin(target)
        parsed = urlparse(origin)
        host = parsed.hostname or ""
        validate_scope(host)

        try:
            client = await self._get_client()
            response = await client.get(origin)
            findings = self._analyze_response(origin, response)
            findings = self._with_seen_at(findings, [target] if target != origin else [origin])

            return ToolResult(
                tool_name=self.name,
                target=origin,
                success=True,
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "status_code": response.status_code,
                    "headers_checked": list(response.headers.keys()),
                    "origin": origin,
                },
            )

        except httpx.TimeoutException:
            return ToolResult(
                tool_name=self.name,
                target=origin,
                success=False,
                error=f"Request timed out after {self.timeout}s",
                timed_out=True,
            )
        except httpx.RequestError as e:
            return ToolResult(
                tool_name=self.name,
                target=origin,
                success=False,
                error=f"Request failed: {str(e)}",
            )

    async def run_batch(
        self,
        urls: list[str],
        scope: dict[str, Any],
    ) -> ToolResult:
        """
        Check security headers for multiple URLs, once per unique origin.

        Paths/query strings under the same origin are collapsed so duplicate
        header findings are not emitted for "/", /sitemap.xml, etc.
        """
        for url in urls:
            parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
            host = parsed.hostname or ""
            validate_scope(host)

        if not urls:
            return ToolResult(
                tool_name=self.name,
                target="batch",
                success=True,
                data={"findings": [], "finding_count": 0, "origins_checked": 0},
            )

        origin_groups = self._group_urls_by_origin(urls)
        all_findings: list[Finding] = []
        errors: dict[str, str] = {}

        for origin, seen_at in origin_groups.items():
            try:
                result = await self.run(origin, scope)
                if result.success and result.data:
                    findings_data = result.data.get("findings", [])
                    for fd in findings_data:
                        finding = Finding(**fd)
                        raw = dict(finding.raw_data or {})
                        raw["seen_at"] = list(seen_at)
                        finding.raw_data = raw
                        # Attribute to the origin, not a random crawled path.
                        finding.url = origin
                        all_findings.append(finding)
                elif result.error:
                    errors[origin] = result.error
            except Exception as e:
                errors[origin] = str(e)

            await asyncio.sleep(self.rate_limit_delay)

        return ToolResult(
            tool_name=self.name,
            target="batch",
            success=True,
            data={
                "findings": [f.model_dump_for_state() for f in all_findings],
                "finding_count": len(all_findings),
                "urls_submitted": len(urls),
                "origins_checked": len(origin_groups),
                "errors": errors if errors else None,
            },
        )

    def _analyze_response(
        self,
        url: str,
        response: httpx.Response,
    ) -> list[Finding]:
        """Analyze HTTP response for security issues."""
        findings: list[Finding] = []

        findings.extend(self._check_csp(url, response))
        findings.extend(self._check_hsts(url, response))
        findings.extend(self._check_x_frame_options(url, response))
        findings.extend(self._check_x_content_type_options(url, response))
        findings.extend(self._check_cors(url, response))
        findings.extend(self._check_cookies(url, response))
        findings.extend(self._check_other_headers(url, response))

        return findings

    def _check_csp(self, url: str, response: httpx.Response) -> list[Finding]:
        """Check Content-Security-Policy header with directive-specific findings."""
        findings: list[Finding] = []
        csp = response.headers.get("content-security-policy", "")

        if not csp:
            findings.append(Finding(
                tool="header-checks",
                type="missing-csp",
                url=url,
                severity=Severity.MEDIUM,
                description="Content-Security-Policy header is missing entirely",
                evidence="No Content-Security-Policy header found in response",
                cwe_id=693,
                raw_data={
                    "remediation": (
                        "Add a Content-Security-Policy header with restrictive defaults "
                        "(e.g. default-src 'self') and explicit allowlists for scripts/styles."
                    ),
                },
            ))
            return findings

        if "'unsafe-inline'" in csp:
            findings.append(Finding(
                tool="header-checks",
                type="csp-unsafe-inline",
                url=url,
                severity=Severity.MEDIUM,
                description=(
                    "Content-Security-Policy includes 'unsafe-inline', which disables "
                    "XSS protections for inline scripts/styles."
                ),
                evidence="CSP directive contains 'unsafe-inline'",
                cwe_id=693,
                raw_data={
                    "csp": csp,
                    "missing_or_weak": "unsafe-inline",
                    "remediation": (
                        "Remove 'unsafe-inline' and prefer nonces or hashes for any "
                        "required inline scripts/styles."
                    ),
                },
            ))

        if "'unsafe-eval'" in csp:
            findings.append(Finding(
                tool="header-checks",
                type="csp-unsafe-eval",
                url=url,
                severity=Severity.MEDIUM,
                description=(
                    "Content-Security-Policy includes 'unsafe-eval', which allows "
                    "string-to-code evaluation (eval, new Function, etc.)."
                ),
                evidence="CSP directive contains 'unsafe-eval'",
                cwe_id=693,
                raw_data={
                    "csp": csp,
                    "missing_or_weak": "unsafe-eval",
                    "remediation": (
                        "Remove 'unsafe-eval' from script-src/default-src and avoid "
                        "runtime code generation from strings."
                    ),
                },
            ))

        # Flag bare scheme-source wildcards / host wildcards that are overly broad.
        for part in csp.split(";"):
            directive = part.strip()
            if not directive:
                continue
            tokens = directive.split()
            name = tokens[0].lower() if tokens else ""
            sources = tokens[1:]
            permissive = [s for s in sources if s in ("*", "https:", "http:")]
            if permissive:
                findings.append(Finding(
                    tool="header-checks",
                    type="csp-overly-permissive",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Content-Security-Policy directive '{name}' uses an overly "
                        f"permissive source ({', '.join(permissive)})."
                    ),
                    evidence=f"CSP segment: {directive.strip()}",
                    cwe_id=693,
                    raw_data={
                        "csp": csp,
                        "directive": name,
                        "remediation": (
                            f"Tighten '{name}' to explicit trusted hosts/nonces instead of "
                            "broad wildcards or scheme-only sources."
                        ),
                    },
                ))
                break

        return findings

    def _check_hsts(self, url: str, response: httpx.Response) -> list[Finding]:
        """Check Strict-Transport-Security with granular sub-checks."""
        findings: list[Finding] = []

        if not url.startswith("https://"):
            return findings

        hsts = response.headers.get("strict-transport-security", "")

        if not hsts:
            findings.append(Finding(
                tool="header-checks",
                type="missing-hsts",
                url=url,
                severity=Severity.MEDIUM,
                description="Strict-Transport-Security header is missing entirely",
                evidence="No HSTS header found in HTTPS response",
                cwe_id=319,
                raw_data={
                    "remediation": (
                        "Set Strict-Transport-Security: max-age=63072000; includeSubDomains; "
                        "preload (after confirming all subdomains support HTTPS)."
                    ),
                },
            ))
            return findings

        parsed = parse_hsts(hsts)
        max_age = parsed["max_age"]
        include_subdomains = parsed["include_subdomains"]
        preload = parsed["preload"]

        if max_age is None:
            findings.append(Finding(
                tool="header-checks",
                type="weak-hsts-max-age",
                url=url,
                severity=Severity.LOW,
                description=(
                    "Strict-Transport-Security is present but max-age is missing or "
                    "unparseable; max-age should be >= 31536000 (ideally 63072000 for 2 years)."
                ),
                evidence=f"HSTS header: {hsts}",
                cwe_id=319,
                raw_data={
                    "hsts": hsts,
                    "max_age": None,
                    "remediation": (
                        f"Add max-age>={HSTS_MIN_MAX_AGE} (ideally {HSTS_IDEAL_MAX_AGE}) to "
                        "Strict-Transport-Security."
                    ),
                },
            ))
        elif max_age < HSTS_MIN_MAX_AGE:
            findings.append(Finding(
                tool="header-checks",
                type="weak-hsts-max-age",
                url=url,
                severity=Severity.LOW,
                description=(
                    f"HSTS max-age is too short ({max_age}s); it should be >= "
                    f"{HSTS_MIN_MAX_AGE} (ideally {HSTS_IDEAL_MAX_AGE} for 2 years)."
                ),
                evidence=f"max-age={max_age}",
                cwe_id=319,
                raw_data={
                    "hsts": hsts,
                    "max_age": max_age,
                    "remediation": (
                        f"Increase max-age to at least {HSTS_MIN_MAX_AGE} seconds "
                        f"(recommend {HSTS_IDEAL_MAX_AGE})."
                    ),
                },
            ))

        max_age_strong = max_age is not None and max_age >= HSTS_MIN_MAX_AGE

        if max_age_strong and not include_subdomains:
            findings.append(Finding(
                tool="header-checks",
                type="missing-hsts-includesubdomains",
                url=url,
                severity=Severity.LOW,
                description=(
                    f"HSTS max-age is sufficiently strong ({max_age}s) but "
                    "includeSubDomains directive is missing, leaving subdomains unprotected."
                ),
                evidence=f"HSTS header: {hsts}",
                cwe_id=319,
                raw_data={
                    "hsts": hsts,
                    "max_age": max_age,
                    "include_subdomains": False,
                    "remediation": (
                        "Add the includeSubDomains directive to Strict-Transport-Security "
                        "after confirming all subdomains are HTTPS-capable."
                    ),
                },
            ))
        elif not include_subdomains and not max_age_strong:
            # Still note the missing directive when max-age itself is also weak.
            findings.append(Finding(
                tool="header-checks",
                type="missing-hsts-includesubdomains",
                url=url,
                severity=Severity.LOW,
                description=(
                    "HSTS includeSubDomains directive is missing, leaving subdomains "
                    "unprotected by HSTS."
                ),
                evidence=f"HSTS header: {hsts}",
                cwe_id=319,
                raw_data={
                    "hsts": hsts,
                    "max_age": max_age,
                    "include_subdomains": False,
                    "remediation": (
                        "Add includeSubDomains to Strict-Transport-Security after confirming "
                        "HTTPS coverage for all subdomains."
                    ),
                },
            ))

        if not preload:
            findings.append(Finding(
                tool="header-checks",
                type="missing-hsts-preload",
                url=url,
                severity=Severity.INFO,
                description=(
                    "HSTS preload directive is absent. Preload is optional but recommended "
                    "for maximum protection; it requires includeSubDomains and "
                    f"max-age >= {HSTS_MIN_MAX_AGE} first."
                ),
                evidence=f"HSTS header: {hsts}",
                cwe_id=319,
                raw_data={
                    "hsts": hsts,
                    "preload": False,
                    "include_subdomains": include_subdomains,
                    "max_age": max_age,
                    "remediation": (
                        f"Once max-age >= {HSTS_MIN_MAX_AGE} and includeSubDomains are set, "
                        "add the preload directive and submit the domain to the HSTS preload list."
                    ),
                },
            ))

        return findings

    def _check_x_frame_options(
        self,
        url: str,
        response: httpx.Response,
    ) -> list[Finding]:
        """Check X-Frame-Options / CSP frame-ancestors clickjacking controls."""
        findings: list[Finding] = []
        xfo = response.headers.get("x-frame-options", "")
        csp = response.headers.get("content-security-policy", "")

        has_csp_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_csp_frame_ancestors:
            findings.append(Finding(
                tool="header-checks",
                type="missing-x-frame-options",
                url=url,
                severity=Severity.MEDIUM,
                description=(
                    "Clickjacking protection is missing: neither X-Frame-Options nor "
                    "CSP frame-ancestors is set."
                ),
                evidence="No X-Frame-Options header and no CSP frame-ancestors directive",
                cwe_id=1021,
                raw_data={
                    "remediation": (
                        "Set X-Frame-Options: DENY (or SAMEORIGIN), or add "
                        "frame-ancestors 'none'/'self' to Content-Security-Policy."
                    ),
                },
            ))
            return findings

        if xfo:
            normalized = xfo.strip().upper()
            if normalized.startswith("ALLOW-FROM"):
                findings.append(Finding(
                    tool="header-checks",
                    type="deprecated-x-frame-options",
                    url=url,
                    severity=Severity.LOW,
                    description=(
                        "X-Frame-Options uses deprecated ALLOW-FROM, which modern browsers "
                        "ignore; prefer DENY/SAMEORIGIN or CSP frame-ancestors."
                    ),
                    evidence=f"X-Frame-Options: {xfo}",
                    cwe_id=1021,
                    raw_data={
                        "value": xfo,
                        "remediation": (
                            "Replace ALLOW-FROM with X-Frame-Options: DENY/SAMEORIGIN "
                            "and/or CSP frame-ancestors with an explicit allowlist."
                        ),
                    },
                ))
            elif normalized not in ("DENY", "SAMEORIGIN"):
                findings.append(Finding(
                    tool="header-checks",
                    type="invalid-x-frame-options",
                    url=url,
                    severity=Severity.LOW,
                    description=(
                        f"X-Frame-Options has unrecognized value '{xfo}'; "
                        "expected DENY or SAMEORIGIN."
                    ),
                    evidence=f"X-Frame-Options: {xfo}",
                    cwe_id=1021,
                    raw_data={
                        "value": xfo,
                        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
                    },
                ))

        return findings

    def _check_x_content_type_options(
        self,
        url: str,
        response: httpx.Response,
    ) -> list[Finding]:
        """Check X-Content-Type-Options header."""
        findings: list[Finding] = []
        xcto = response.headers.get("x-content-type-options", "")

        if not xcto:
            findings.append(Finding(
                tool="header-checks",
                type="missing-x-content-type-options",
                url=url,
                severity=Severity.LOW,
                description=(
                    "X-Content-Type-Options header is missing entirely "
                    "(nosniff not enforced)."
                ),
                evidence="No X-Content-Type-Options header found",
                cwe_id=16,
                raw_data={
                    "remediation": "Set X-Content-Type-Options: nosniff on all responses.",
                },
            ))
        elif xcto.lower().strip() != "nosniff":
            findings.append(Finding(
                tool="header-checks",
                type="invalid-x-content-type-options",
                url=url,
                severity=Severity.LOW,
                description=(
                    f"X-Content-Type-Options is set to '{xcto}' instead of the only "
                    "valid value 'nosniff'."
                ),
                evidence=f"X-Content-Type-Options: {xcto}",
                cwe_id=16,
                raw_data={
                    "value": xcto,
                    "remediation": "Change X-Content-Type-Options to exactly 'nosniff'.",
                },
            ))

        return findings

    def _check_cors(self, url: str, response: httpx.Response) -> list[Finding]:
        """Check CORS configuration, including wildcard + credentials combo."""
        findings: list[Finding] = []
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                findings.append(Finding(
                    tool="header-checks",
                    type="cors-wildcard-with-credentials",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=(
                        "CORS is misconfigured: Access-Control-Allow-Origin is '*' while "
                        "Access-Control-Allow-Credentials is true. This combination is "
                        "invalid per the Fetch CORS specification and indicates a serious "
                        "misconfiguration if honored by clients."
                    ),
                    evidence=(
                        "Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true"
                    ),
                    cwe_id=942,
                    raw_data={
                        "acao": acao,
                        "acac": acac,
                        "remediation": (
                            "Never combine ACAO '*' with Allow-Credentials: true. Reflect "
                            "an explicit allowlisted origin and keep credentials disabled "
                            "unless strictly required."
                        ),
                    },
                ))
            else:
                findings.append(Finding(
                    tool="header-checks",
                    type="cors-wildcard",
                    url=url,
                    severity=Severity.LOW,
                    description=(
                        "CORS Access-Control-Allow-Origin is set to wildcard '*', allowing "
                        "any origin to read the response (without credentials)."
                    ),
                    evidence="Access-Control-Allow-Origin: *",
                    cwe_id=942,
                    raw_data={
                        "acao": acao,
                        "remediation": (
                            "Replace wildcard Access-Control-Allow-Origin with an explicit "
                            "allowlist of trusted origins."
                        ),
                    },
                ))

        if acao == "null":
            findings.append(Finding(
                tool="header-checks",
                type="cors-null-origin",
                url=url,
                severity=Severity.MEDIUM,
                description=(
                    "CORS Access-Control-Allow-Origin is 'null', which can be abused via "
                    "sandboxed frames / opaque origins."
                ),
                evidence="Access-Control-Allow-Origin: null",
                cwe_id=942,
                raw_data={
                    "acao": acao,
                    "remediation": (
                        "Do not allow the 'null' origin; use an explicit allowlist of "
                        "trusted HTTPS origins."
                    ),
                },
            ))

        return findings

    def _check_cookies(self, url: str, response: httpx.Response) -> list[Finding]:
        """Check cookie security attributes with flag-specific descriptions."""
        findings: list[Finding] = []
        set_cookie_headers = response.headers.get_list("set-cookie")

        for cookie_header in set_cookie_headers:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()

            is_session_cookie = any(
                indicator in cookie_name.lower()
                for indicator in ["session", "sid", "auth", "token", "jwt"]
            )

            issues: list[str] = []

            if url.startswith("https://") and "secure" not in cookie_lower:
                issues.append("Secure")
            if "httponly" not in cookie_lower:
                issues.append("HttpOnly")
            if "samesite" not in cookie_lower:
                issues.append("SameSite")
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                issues.append("SameSite=None requires Secure")

            if issues:
                severity = Severity.MEDIUM if is_session_cookie else Severity.LOW
                missing = ", ".join(issues)
                findings.append(Finding(
                    tool="header-checks",
                    type="insecure-cookie",
                    url=url,
                    severity=severity,
                    description=(
                        f"Cookie '{cookie_name}' is missing or misconfigured security "
                        f"attribute(s): {missing}."
                    ),
                    evidence=f"Set-Cookie: {cookie_header}",
                    cwe_id=614,
                    raw_data={
                        "cookie": cookie_name,
                        "issues": issues,
                        "remediation": (
                            f"For cookie '{cookie_name}', set Secure; HttpOnly; and "
                            "SameSite=Strict or Lax (SameSite=None only with Secure)."
                        ),
                    },
                ))

        return findings

    def _check_other_headers(
        self,
        url: str,
        response: httpx.Response,
    ) -> list[Finding]:
        """Check Referrer-Policy and version-disclosure headers."""
        findings: list[Finding] = []

        server = response.headers.get("server", "")
        if server:
            version_indicators = ["nginx/", "apache/", "iis/", "php/"]
            for indicator in version_indicators:
                if indicator in server.lower():
                    findings.append(Finding(
                        tool="header-checks",
                        type="server-version-disclosure",
                        url=url,
                        severity=Severity.INFO,
                        description=(
                            f"Server header discloses software/version information: {server}."
                        ),
                        evidence=f"Server: {server}",
                        cwe_id=200,
                        raw_data={
                            "server": server,
                            "remediation": (
                                "Remove or generalize the Server banner so it does not "
                                "include product/version details."
                            ),
                        },
                    ))
                    break

        x_powered_by = response.headers.get("x-powered-by", "")
        if x_powered_by:
            findings.append(Finding(
                tool="header-checks",
                type="x-powered-by-disclosure",
                url=url,
                severity=Severity.INFO,
                description=(
                    f"X-Powered-By header discloses technology stack: {x_powered_by}."
                ),
                evidence=f"X-Powered-By: {x_powered_by}",
                cwe_id=200,
                raw_data={
                    "x_powered_by": x_powered_by,
                    "remediation": "Remove the X-Powered-By header in production.",
                },
            ))

        referrer_policy = response.headers.get("referrer-policy", "")
        if not referrer_policy:
            findings.append(Finding(
                tool="header-checks",
                type="missing-referrer-policy",
                url=url,
                severity=Severity.INFO,
                description="Referrer-Policy header is missing entirely",
                evidence="No Referrer-Policy header found",
                cwe_id=200,
                raw_data={
                    "remediation": (
                        "Set Referrer-Policy to a restrictive value such as "
                        "strict-origin-when-cross-origin or no-referrer."
                    ),
                },
            ))
        elif referrer_policy.lower().strip() == "unsafe-url":
            findings.append(Finding(
                tool="header-checks",
                type="weak-referrer-policy",
                url=url,
                severity=Severity.LOW,
                description=(
                    "Referrer-Policy is set to 'unsafe-url', which leaks full URLs "
                    "(including path/query) on cross-origin requests."
                ),
                evidence=f"Referrer-Policy: {referrer_policy}",
                cwe_id=200,
                raw_data={
                    "value": referrer_policy,
                    "remediation": (
                        "Replace 'unsafe-url' with strict-origin-when-cross-origin, "
                        "strict-origin, or no-referrer."
                    ),
                },
            ))

        return findings
