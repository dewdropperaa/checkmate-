"""Report generation agent."""

from __future__ import annotations

import base64
import html
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.state import ScanState
from core.config import get_settings
from core.scan_disclaimer import (
    COVERAGE_LIMITATIONS_HEADING,
    COVERAGE_SECTION_TITLE,
    SCAN_COVERAGE_DISCLAIMER,
)
from core.pdf_design import (
    COLORS,
    SPACING,
    TYPOGRAPHY,
    severity_color,
    severity_light_color,
    risk_score_color,
    RGB,
)
from fpdf import FPDF

_REPORTS_ROOT = Path(__file__).resolve().parent.parent / "reports"
_LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo.png"
_DEFAULT_BRAND_NAME = "Checkmate"
_DEFAULT_TAGLINE = "Checkmate Vulnerability Assessment"
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def build_coverage_section(report: dict[str, Any]) -> dict[str, Any]:
    """Structured coverage + fixed disclaimer for all report formats and the UI."""
    coverage = (report.get("severity_scores") or {}).get("scan_coverage") or {}
    modules_run = list(
        dict.fromkeys(
            list(coverage.get("recon_modules_run") or [])
            + list(coverage.get("detection_modules_run") or [])
        )
    )
    return {
        "title": COVERAGE_SECTION_TITLE,
        "limitations_heading": COVERAGE_LIMITATIONS_HEADING,
        "disclaimer": SCAN_COVERAGE_DISCLAIMER,
        "modules_run": modules_run,
        "modules_failed": list(coverage.get("modules_failed") or []),
        "modules_failed_detail": dict(coverage.get("modules_failed_detail") or {}),
        "modules_skipped": list(coverage.get("modules_skipped") or []),
        "modules_not_applicable": list(coverage.get("modules_not_applicable") or []),
        "modules_rejected": list(coverage.get("modules_rejected") or []),
        "coverage_notes": list(coverage.get("coverage_notes") or []),
        "owasp_top10": dict(coverage.get("owasp_top10") or {}),
        "score_basis": coverage.get("score_basis"),
        "authenticated_scanning": coverage.get("authenticated_scanning") or {},
        "recon_partial_failure": bool(coverage.get("recon_partial_failure")),
    }


def _format_module_list(items: list[Any]) -> str:
    if not items:
        return "_None_"
    return ", ".join(f"`{m}`" for m in items)


def _coverage_markdown(report: dict[str, Any]) -> list[str]:
    cov = build_coverage_section(report)
    lines = [
        f"## {cov['title']}",
        "",
        f"- **Modules run successfully:** {_format_module_list(cov['modules_run'])}",
        f"- **Modules failed:** {_format_module_list(cov['modules_failed'])}",
    ]
    detail = cov.get("modules_failed_detail") or {}
    if detail:
        for name, err in sorted(detail.items()):
            lines.append(f"  - `{name}`: {err}")
    lines.extend([
        f"- **Modules skipped:** {_format_module_list(cov['modules_skipped'])}",
        f"- **Modules not applicable:** {_format_module_list(cov['modules_not_applicable'])}",
    ])
    owasp = cov.get("owasp_top10") or {}
    if owasp.get("categories_covered"):
        labels = owasp.get("labels") or {}
        covered = ", ".join(
            f"`{cid}` {labels.get(cid, '')}".strip()
            for cid in owasp["categories_covered"]
        )
        lines.append(f"- **OWASP Top 10 categories exercised:** {covered}")
        if owasp.get("note"):
            lines.append(f"- **OWASP note:** {_md_escape(str(owasp['note']))}")
    if cov["modules_rejected"]:
        lines.append(
            f"- **Active modules rejected:** {_format_module_list(cov['modules_rejected'])}"
        )
    if cov["score_basis"]:
        lines.append(f"- **Score basis:** {_md_escape(str(cov['score_basis']))}")
    for note in cov["coverage_notes"]:
        lines.append(f"- **Note:** {_md_escape(str(note))}")
    auth = cov["authenticated_scanning"] or {}
    if auth.get("coverage_warning"):
        lines.append(f"- **Authenticated scanning:** {_md_escape(str(auth['coverage_warning']))}")
    elif auth.get("enabled"):
        lines.append("- **Authenticated scanning:** enabled for the configured account/paths")
    lines.extend(
        [
            "",
            f"### {cov['limitations_heading']}",
            "",
            cov["disclaimer"],
            "",
        ]
    )
    return lines


def _coverage_html(report: dict[str, Any]) -> str:
    cov = build_coverage_section(report)

    def esc(value: Any) -> str:
        return html.escape(str(value))

    def chips(items: list[Any], empty: str = "None") -> str:
        if not items:
            return f"<span class='muted'>{esc(empty)}</span>"
        return " ".join(f"<code>{esc(m)}</code>" for m in items)

    auth = cov["authenticated_scanning"] or {}
    auth_row = ""
    if auth.get("coverage_warning"):
        auth_row = (
            f"<li><strong>Authenticated scanning:</strong> "
            f"{esc(auth['coverage_warning'])}</li>"
        )
    elif auth.get("enabled"):
        auth_row = (
            "<li><strong>Authenticated scanning:</strong> "
            "enabled for the configured account/paths</li>"
        )
    notes = "".join(
        f"<li><strong>Note:</strong> {esc(n)}</li>" for n in cov["coverage_notes"]
    )
    rejected = ""
    if cov["modules_rejected"]:
        rejected = (
            f"<li><strong>Active modules rejected:</strong> "
            f"{chips(cov['modules_rejected'])}</li>"
        )
    score = ""
    if cov["score_basis"]:
        score = f"<li><strong>Score basis:</strong> {esc(cov['score_basis'])}</li>"

    return f"""
  <section class="coverage" id="scan-coverage">
    <h2>{esc(cov['title'])}</h2>
    <ul class="coverage-list">
      <li><strong>Modules run successfully:</strong> {chips(cov['modules_run'])}</li>
      <li><strong>Modules failed:</strong> {chips(cov['modules_failed'])}</li>
      <li><strong>Modules skipped:</strong> {chips(cov['modules_skipped'])}</li>
      <li><strong>Modules not applicable:</strong> {chips(cov['modules_not_applicable'])}</li>
      {rejected}
      {score}
      {notes}
      {auth_row}
    </ul>
    <div class="callout callout-warning coverage-disclaimer">
      <div class="callout-icon">&#9888;</div>
      <div class="callout-content">
        <h4>{esc(cov['limitations_heading'])}</h4>
        <p>{esc(cov['disclaimer'])}</p>
      </div>
    </div>
  </section>
"""


def _draw_coverage_pdf(pdf: "CheckmatePDF", report: dict[str, Any], y: float) -> float:
    """Render the mandatory coverage & limitations section; returns new y."""
    cov = build_coverage_section(report)
    content_width = pdf.epw

    if y > 240:
        pdf.add_page()
        y = SPACING.MARGIN_TOP

    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H2)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(content_width, 8, _pdf_safe_text(cov["title"]), align="L")
    y += 10

    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_text_color(55, 65, 81)

    def _line(label: str, items: list[Any]) -> float:
        nonlocal y
        text = ", ".join(str(m) for m in items) if items else "None"
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.multi_cell(
            content_width,
            5,
            _pdf_safe_text(f"{label}: {text}"),
        )
        y = pdf.get_y() + 1
        return y

    _line("Modules run successfully", cov["modules_run"])
    _line("Modules failed", cov["modules_failed"])
    _line("Modules skipped", cov["modules_skipped"])
    _line("Modules not applicable", cov["modules_not_applicable"])
    if cov["modules_rejected"]:
        _line("Active modules rejected", cov["modules_rejected"])

    y += 4
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H3)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(content_width, 6, _pdf_safe_text(cov["limitations_heading"]), align="L")
    y += 8

    # Mandatory disclaimer — never omit.
    callout_height = _draw_info_callout(
        pdf,
        "Important",
        [cov["disclaimer"]],
        SPACING.MARGIN_LEFT,
        y,
        content_width,
    )
    return y + callout_height + 8


@dataclass(frozen=True)
class ReportBranding:
    """Resolved report chrome (default Checkmate or Agency white-label)."""

    brand_name: str
    tagline: str
    logo_path: Path | None
    white_label: bool


def resolve_report_branding(org_id: str | None) -> ReportBranding:
    """Return Checkmate defaults, or Agency brand name/logo when gated + set."""
    default_logo = _LOGO_PATH if _LOGO_PATH.is_file() else None
    default = ReportBranding(
        brand_name=_DEFAULT_BRAND_NAME,
        tagline=_DEFAULT_TAGLINE,
        logo_path=default_logo,
        white_label=False,
    )
    if not org_id:
        return default
    try:
        from core.accounts import get_organization
        from core.plans import can_use_white_label_reports
    except ImportError:
        return default
    if not can_use_white_label_reports(org_id):
        return default
    org = get_organization(org_id)
    if org is None:
        return default
    brand_name = (org.brand_name or org.name or "").strip() or _DEFAULT_BRAND_NAME
    logo_path = default_logo
    if org.brand_logo_path:
        candidate = Path(org.brand_logo_path)
        if candidate.is_file():
            logo_path = candidate
    return ReportBranding(
        brand_name=brand_name,
        tagline=f"{brand_name} Vulnerability Assessment",
        logo_path=logo_path,
        white_label=True,
    )

_USER_FACING_ERRORS: dict[str, str] = {
    "scan_timeout": (
        "The scan timed out before completing. Please try again later."
    ),
    "scan_error": (
        "The scan failed due to an unexpected error. Please try again later."
    ),
    "invalid_scan_target": (
        "The scan target could not be validated. Check the URL and try again."
    ),
    "target_not_authorized": (
        "This target is not authorized for scanning."
    ),
    "target_unreachable": (
        "The target could not be reached. Check DNS, connectivity, and TLS."
    ),
}

REMEDIATION_GUIDANCE: dict[str, str] = {
    "xss": "Apply strict output encoding, validate/normalize input, and deploy a restrictive CSP without unsafe-inline/unsafe-eval.",
    "sqli": "Use parameterized queries or prepared statements everywhere; remove string-built SQL and enforce least DB privileges.",
    "missing-csp": "Add a Content-Security-Policy header with restrictive defaults (default-src 'self') and explicit allowlists for scripts/styles.",
    "weak-csp": "Remove weak directives such as unsafe-inline/unsafe-eval and broad wildcards; use nonce/hash-based script controls.",
    "csp-unsafe-inline": "Remove 'unsafe-inline' from CSP and prefer nonces or hashes for any required inline scripts/styles.",
    "csp-unsafe-eval": "Remove 'unsafe-eval' from script-src/default-src and avoid runtime code generation from strings.",
    "csp-overly-permissive": "Tighten the flagged CSP directive to explicit trusted hosts/nonces instead of broad wildcards or scheme-only sources.",
    "missing-hsts": "Set Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (after confirming all subdomains support HTTPS).",
    "weak-hsts": "Increase max-age and include includeSubDomains; ensure HTTPS-only behavior across the full application surface.",
    "weak-hsts-max-age": "Increase Strict-Transport-Security max-age to at least 31536000 seconds (ideally 63072000 for 2 years).",
    "missing-hsts-includesubdomains": "Add the includeSubDomains directive to Strict-Transport-Security after confirming HTTPS coverage for all subdomains.",
    "missing-hsts-preload": "Once max-age >= 31536000 and includeSubDomains are set, add preload and submit the domain to the HSTS preload list.",
    "missing-x-frame-options": "Set X-Frame-Options: DENY (or SAMEORIGIN), or add frame-ancestors 'none'/'self' to Content-Security-Policy.",
    "deprecated-x-frame-options": "Replace ALLOW-FROM with X-Frame-Options: DENY/SAMEORIGIN and/or CSP frame-ancestors with an explicit allowlist.",
    "invalid-x-frame-options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    "missing-x-content-type-options": "Set X-Content-Type-Options: nosniff on all responses to reduce MIME confusion attacks.",
    "invalid-x-content-type-options": "Change X-Content-Type-Options to exactly 'nosniff'.",
    "cors-wildcard-with-credentials": "Never combine Access-Control-Allow-Origin '*' with Allow-Credentials: true. Use an explicit origin allowlist and keep credentials disabled unless strictly required.",
    "cors-wildcard": "Replace wildcard Access-Control-Allow-Origin with a vetted allowlist of trusted origins.",
    "cors-null-origin": "Do not allow the 'null' origin; use an explicit allowlist of trusted HTTPS origins.",
    "insecure-cookie": "Set Secure, HttpOnly, and SameSite attributes for session/auth cookies; review expiration and path/domain scoping.",
    "server-version-disclosure": "Suppress server/framework version banners and minimize fingerprinting details in response headers.",
    "x-powered-by-disclosure": "Remove X-Powered-By and similar framework disclosure headers in production.",
    "missing-referrer-policy": "Add Referrer-Policy (e.g., strict-origin-when-cross-origin) to limit sensitive URL leakage.",
    "weak-referrer-policy": "Replace 'unsafe-url' with strict-origin-when-cross-origin, strict-origin, or no-referrer.",
}

# Plain-language explanations so the report is readable by non-technical
# stakeholders (owners, managers) as well as engineers. Each entry provides a
# friendly title, a "what this is" sentence, and a "why it matters" sentence
# written without jargon. Technical detail is preserved separately in the report.
PLAIN_LANGUAGE: dict[str, dict[str, str]] = {
    "xss": {
        "title": "Malicious scripts could run in visitors' browsers (XSS)",
        "what": "A page can be tricked into running code that an attacker supplies.",
        "why": "An attacker could steal logged-in sessions, capture what users type, or tamper with what visitors see.",
    },
    "sqli": {
        "title": "The database can be manipulated through the website (SQL injection)",
        "what": "Input from the page reaches the database without being safely separated from commands.",
        "why": "An attacker could read, change, or delete data such as customer records or credentials.",
    },
    "missing-csp": {
        "title": "Missing browser 'allow-list' for content (Content Security Policy)",
        "what": "The site does not tell browsers which sources of scripts, styles, and images are trusted.",
        "why": "Without this safety net, an injected script is more likely to run and cause harm.",
    },
    "weak-csp": {
        "title": "Weak browser 'allow-list' for content (Content Security Policy)",
        "what": "The site's content rules include loose settings that weaken the protection.",
        "why": "Loose rules make it easier for malicious scripts to slip through if one is ever injected.",
    },
    "csp-unsafe-inline": {
        "title": "Browser content rules still allow inline code",
        "what": "The Content Security Policy permits scripts/styles written directly in the page ('unsafe-inline').",
        "why": "This turns off one of the browser's built-in defenses against injected scripts.",
    },
    "csp-unsafe-eval": {
        "title": "Browser content rules allow code built at runtime",
        "what": "The Content Security Policy permits turning text into executable code ('unsafe-eval').",
        "why": "It makes certain script-injection attacks easier to pull off.",
    },
    "csp-overly-permissive": {
        "title": "Browser content rules are too broad",
        "what": "A Content Security Policy rule allows content from a very wide range of sources.",
        "why": "Broad rules make it easier for unwanted or malicious content to load on your pages.",
    },
    "missing-hsts": {
        "title": "Browsers aren't forced to use a secure (HTTPS) connection",
        "what": "The site doesn't tell browsers to always connect over HTTPS (missing HSTS).",
        "why": "A visitor's first request could be downgraded to an insecure connection and intercepted.",
    },
    "weak-hsts": {
        "title": "Secure-connection enforcement is weaker than recommended",
        "what": "The HTTPS-only setting (HSTS) is present but configured below best practice.",
        "why": "It leaves a smaller-but-real window where a connection could be intercepted.",
    },
    "weak-hsts-max-age": {
        "title": "Secure-connection enforcement expires too soon",
        "what": "The HTTPS-only rule (HSTS) is remembered by browsers for too short a time.",
        "why": "The protection lapses sooner than it should, widening the window for interception.",
    },
    "missing-hsts-includesubdomains": {
        "title": "Secure-connection rule doesn't cover subdomains",
        "what": "The HTTPS-only rule (HSTS) is not applied to subdomains.",
        "why": "Subdomains could still be reached over an insecure connection.",
    },
    "missing-hsts-preload": {
        "title": "Site isn't on the browser HTTPS 'preload' list",
        "what": "The domain hasn't opted into browsers' built-in always-HTTPS list.",
        "why": "The very first visit isn't fully protected until this is enabled.",
    },
    "missing-x-frame-options": {
        "title": "The site can be embedded in other pages (clickjacking risk)",
        "what": "Nothing stops another website from loading your page inside a hidden frame.",
        "why": "Attackers can trick users into clicking things they didn't intend to (clickjacking).",
    },
    "deprecated-x-frame-options": {
        "title": "Outdated clickjacking protection setting",
        "what": "The anti-framing setting uses an obsolete option browsers ignore.",
        "why": "The intended clickjacking protection may not actually be applied.",
    },
    "invalid-x-frame-options": {
        "title": "Invalid clickjacking protection setting",
        "what": "The anti-framing setting has a value browsers don't understand.",
        "why": "The intended clickjacking protection may not actually be applied.",
    },
    "missing-x-content-type-options": {
        "title": "Browsers may guess file types (MIME sniffing)",
        "what": "The site doesn't tell browsers to stop guessing the type of a file.",
        "why": "A file could be treated as a script and executed in ways you didn't intend.",
    },
    "invalid-x-content-type-options": {
        "title": "Invalid MIME-sniffing protection setting",
        "what": "The header meant to stop file-type guessing has the wrong value.",
        "why": "Browsers may still guess file types, which can be abused.",
    },
    "cors-wildcard-with-credentials": {
        "title": "Any website can read logged-in responses (dangerous CORS)",
        "what": "The server allows any origin to read responses AND to send credentials.",
        "why": "This combination can let a malicious site read a signed-in user's private data.",
    },
    "cors-wildcard": {
        "title": "Any website is allowed to read the responses (open CORS)",
        "what": "The server tells browsers that any other website may read its responses.",
        "why": "Harmless for public content, but risky if any response ever contains private data.",
    },
    "cors-null-origin": {
        "title": "The 'null' origin is trusted for cross-site reads",
        "what": "The server accepts requests marked with a 'null' origin.",
        "why": "The 'null' origin is easy for attackers to spoof, so it shouldn't be trusted.",
    },
    "insecure-cookie": {
        "title": "Session cookies aren't fully protected",
        "what": "Login/session cookies are missing safety flags (Secure, HttpOnly, SameSite).",
        "why": "Cookies could be stolen or misused, potentially hijacking a user's session.",
    },
    "server-version-disclosure": {
        "title": "The server reveals its software version",
        "what": "Response headers advertise the exact server/framework version in use.",
        "why": "It helps attackers look up known weaknesses for that specific version.",
    },
    "x-powered-by-disclosure": {
        "title": "The site reveals which technology powers it",
        "what": "An 'X-Powered-By' header discloses the underlying technology.",
        "why": "It gives attackers a head start on targeting known weaknesses.",
    },
    "missing-referrer-policy": {
        "title": "Full page addresses may leak to other sites",
        "what": "No Referrer-Policy is set, so browsers may share the full URL when leaving the site.",
        "why": "Sensitive information contained in URLs could leak to third parties.",
    },
    "weak-referrer-policy": {
        "title": "Referrer settings leak more than necessary",
        "what": "The Referrer-Policy is set to a value that shares full URLs.",
        "why": "Sensitive information contained in URLs could leak to third parties.",
    },
}

# ZAP alerts are reported as "zap-<pluginId>"; map the common ones to plain text.
_ZAP_PLAIN: dict[str, dict[str, str]] = {
    "10055": {
        "title": "Browser content rules include a broad wildcard (CSP)",
        "what": "A Content Security Policy directive allows a very wide range of sources.",
        "why": "Broad rules weaken protection against injected scripts and unwanted content.",
    },
    "10098": {
        "title": "Any website is allowed to read the responses (open CORS)",
        "what": "The server tells browsers that other websites may read certain responses.",
        "why": "Harmless for public files, but should be tightened if a response ever holds private data.",
    },
    "10109": {
        "title": "The site is a modern JavaScript app (informational)",
        "what": "The scanner simply noted this is a modern single-page application.",
        "why": "No action needed — it's a note that affects how the site should be crawled.",
    },
    "10050": {
        "title": "A page was served from a shared cache",
        "what": "A response came from a caching layer shared between users.",
        "why": "Only a concern if the cached content is private or user-specific; public files are fine.",
    },
    "10096": {
        "title": "A build timestamp is visible in a file",
        "what": "A file contains a date/time value (a Unix timestamp).",
        "why": "Harmless by itself; it only reveals when a file was built.",
    },
    "10096-unix": {
        "title": "A build timestamp is visible in a file",
        "what": "A file contains a date/time value (a Unix timestamp).",
        "why": "Harmless by itself; it only reveals when a file was built.",
    },
}

_VERIFICATION_PLAIN: dict[str, str] = {
    "confirmed": "Confirmed — independently reproduced on the live site.",
    "unverified": "Not confirmed — the page couldn't be re-fetched to double-check, so treat with some caution.",
    "unconfirmed": "Likely a false positive — the automated double-check found no supporting evidence.",
    "not_applicable": "Verified by inspecting the response headers directly (no separate page check applies).",
    "n/a": "Not applicable.",
}

_SEVERITY_PLAIN: dict[str, str] = {
    "critical": "Urgent — fix as soon as possible; direct, serious impact is likely.",
    "high": "Important — plan a fix soon; meaningful impact is possible.",
    "medium": "Worth fixing — hardening that reduces real risk over time.",
    "low": "Minor — low impact; fix when convenient.",
    "info": "Informational — no action usually required; included for awareness.",
}


def _humanize_type(finding_type: str) -> str:
    return finding_type.replace("-", " ").replace("_", " ").strip().capitalize()


def _plain_language(finding: dict[str, Any]) -> dict[str, str]:
    """Return {title, what, why} in plain language for a finding."""
    finding_type = str(finding.get("type", "unknown"))
    if finding_type in PLAIN_LANGUAGE:
        return PLAIN_LANGUAGE[finding_type]
    if finding_type.startswith("zap-"):
        plugin_id = finding_type.removeprefix("zap-")
        if plugin_id in _ZAP_PLAIN:
            return _ZAP_PLAIN[plugin_id]
        raw = finding.get("raw_data") or {}
        alert = raw.get("alert") or raw.get("name") if isinstance(raw, dict) else None
        return {
            "title": str(alert) if alert else _humanize_type(finding_type),
            "what": str(finding.get("description") or "An automated scanner raised this alert."),
            "why": "Review the details below to decide whether this needs action for your site.",
        }
    if finding_type.startswith("tls-"):
        return {
            "title": "Outdated or weak encryption settings (TLS)",
            "what": "The site supports encryption options that are older or weaker than recommended.",
            "why": "Weak encryption can, in the worst case, let a determined attacker read traffic.",
        }
    if finding_type.startswith("vulnerable-js-"):
        return {
            "title": "A known-vulnerable JavaScript library is in use",
            "what": "A third-party script on the site has a publicly documented weakness.",
            "why": "Attackers can use published details of that weakness against your site.",
        }
    return {
        "title": _humanize_type(finding_type),
        "what": str(finding.get("description") or "See the technical details below."),
        "why": "Review the details below to decide whether this needs action for your site.",
    }


def _verification_plain(finding: dict[str, Any]) -> str:
    verification = finding.get("verification") or {}
    status = str(verification.get("status") or "").lower()
    text = _VERIFICATION_PLAIN.get(status, "Not checked.")
    if finding.get("likely_false_positive") and status not in ("confirmed",):
        text = "Likely a false positive — deprioritized. " + text
    return text


def _risk_severity(score: float) -> str:
    """Map an overall 0-10 risk score to a severity keyword for styling."""
    if score >= 7.0:
        return "critical"
    if score >= 4.0:
        return "high"
    if score >= 2.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _risk_interpretation(score: float) -> tuple[str, str]:
    """Map an overall 0-10 risk score to a plain (label, sentence)."""
    if score <= 0:
        return (
            "No measurable risk",
            "Nothing that needs action was found in the checks that ran.",
        )
    if score < 2.0:
        return (
            "Low risk",
            "Mostly informational or minor hardening items; no urgent problems were found.",
        )
    if score < 4.0:
        return (
            "Moderate risk",
            "Some issues are worth fixing, but nothing points to an immediate breach.",
        )
    if score < 7.0:
        return (
            "Elevated risk",
            "There are issues that should be addressed in the near term.",
        )
    return (
        "High risk",
        "Serious issues were found and should be addressed as a priority.",
    )


def _executive_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Build a plain-language overview for non-technical readers."""
    scores = report.get("severity_scores", {})
    counts = scores.get("severity_counts", {})
    overall = float(scores.get("overall_risk_score", 0.0) or 0.0)
    label, sentence = _risk_interpretation(overall)
    likely_fp = int(scores.get("likely_false_positives", 0) or 0)
    actionable = counts.get("critical", 0) + counts.get("high", 0) + counts.get("medium", 0) + counts.get("low", 0)

    if report.get("outcome") == "rejected":
        headline = (
            "Only passive checks ran because the deeper (active) tests were not approved."
        )
    elif report.get("outcome") == "failed":
        headline = "The scan did not finish successfully, so results may be incomplete."
    elif actionable == 0:
        headline = (
            "No action-worthy security issues were found. The remaining items are "
            "informational notes."
        )
    else:
        headline = (
            f"We found {actionable} item(s) worth reviewing"
            + (f", plus {counts.get('info', 0)} informational note(s)." if counts.get("info", 0) else ".")
        )

    # Top priorities: highest-severity, confirmed-first, capped for readability.
    priorities: list[dict[str, str]] = []
    for severity in ("critical", "high", "medium", "low"):
        for finding in report.get("findings_by_severity", {}).get(severity, []):
            if finding.get("likely_false_positive"):
                continue
            plain = _plain_language(finding)
            priorities.append(
                {
                    "severity": severity,
                    "title": plain["title"],
                    "action": str(finding.get("remediation", "")),
                }
            )
    priorities = priorities[:5]

    notes: list[str] = []
    if likely_fp:
        notes.append(
            f"{likely_fp} finding(s) look like false positives and were deprioritized "
            "(kept in the report for transparency)."
        )
    coverage = scores.get("scan_coverage", {})
    failed = coverage.get("modules_failed") or []
    if failed:
        notes.append(
            "Some tools did not complete: " + ", ".join(str(m) for m in failed) + "."
        )
    auth_cov = coverage.get("authenticated_scanning") or {}
    if auth_cov.get("coverage_warning"):
        notes.append(str(auth_cov["coverage_warning"]))
    for warning in auth_cov.get("warnings") or []:
        if warning and warning not in notes:
            notes.append(str(warning))
    if auth_cov.get("configured") and auth_cov.get("excluded_paths"):
        notes.append(
            "Excluded destructive paths: "
            + ", ".join(str(p) for p in auth_cov["excluded_paths"])
            + "."
        )

    return {
        "risk_label": label,
        "risk_sentence": sentence,
        "overall_risk_score": overall,
        "headline": headline,
        "priorities": priorities,
        "notes": notes,
    }


def _user_summary(state: ScanState, findings_count: int) -> str:
    error = state.get("error") or {}
    if error:
        code = error.get("code", "")
        return error.get("message") or _USER_FACING_ERRORS.get(
            code,
            "The scan did not complete successfully.",
        )
    outcome = state.get("status")
    if outcome == "rejected":
        return (
            "Active/intrusive tests were not approved. "
            "Passive detection findings are included; active tools were skipped."
        )
    if findings_count == 0:
        coverage = (state.get("severity_scores") or {}).get("scan_coverage") or {}
        failed = coverage.get("modules_failed") or []
        risk = (state.get("severity_scores") or {}).get("overall_risk_score", 0.0)
        if failed:
            return (
                "No security findings were detected in the modules that completed, "
                f"but coverage was incomplete ({', '.join(str(m) for m in failed)}). "
                f"Overall risk score is {risk} (uncertainty floor applied)."
            )
        return (
            "No security findings were detected in the modules that ran "
            f"for this scan. Overall risk score is {risk}."
        )
    return "Scan completed with findings. Review severity sections below."


def _truncate_findings(
    findings: list[dict[str, Any]],
    max_findings: int,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if len(findings) <= max_findings:
        return findings, None
    severity_rank = {sev: idx for idx, sev in enumerate(_SEVERITY_ORDER)}
    prioritized = sorted(
        findings,
        key=lambda f: (
            severity_rank.get(_normalize_severity(f.get("severity")), len(_SEVERITY_ORDER)),
            -float(f.get("cvss_score", 0.0) or 0.0),
        ),
    )
    return prioritized[:max_findings], {
        "truncated": True,
        "total_findings": len(findings),
        "rendered_findings": max_findings,
        "message": (
            f"Showing highest-severity {max_findings} of {len(findings)} findings. "
            "Lower-severity entries were truncated first. "
            "findings_count reflects the full scan; rendered sections are capped."
        ),
    }


def _truncate_deduplicated_groups(
    groups: list[dict[str, Any]],
    max_groups: int,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Cap deduplicated finding groups after collapse so unique types are preserved."""
    if len(groups) <= max_groups:
        return groups, None
    severity_rank = {sev: idx for idx, sev in enumerate(_SEVERITY_ORDER)}
    prioritized = sorted(
        groups,
        key=lambda g: (
            severity_rank.get(_normalize_severity(g.get("severity")), len(_SEVERITY_ORDER)),
            -int(
                g.get("instance_count")
                or len(g.get("affected_urls") or [])
                or 1
            ),
        ),
    )
    return prioritized[:max_groups], {
        "truncated": True,
        "total_groups": len(groups),
        "rendered_groups": max_groups,
        "message": (
            f"Showing highest-severity {max_groups} of {len(groups)} unique "
            "finding groups after deduplication."
        ),
    }


def _normalize_severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in _SEVERITY_ORDER:
        return normalized
    if normalized in {"informational", "information"}:
        return "info"
    return "info"


def _remediation_for_finding_type(finding_type: str, finding: dict[str, Any] | None = None) -> str:
    if finding:
        raw = finding.get("raw_data") or {}
        if isinstance(raw, dict) and raw.get("remediation"):
            return str(raw["remediation"])
    if finding_type in REMEDIATION_GUIDANCE:
        return REMEDIATION_GUIDANCE[finding_type]
    if finding_type.startswith("tls-"):
        return (
            "Disable weak protocols/ciphers, prefer modern TLS versions, and align the TLS policy with current OWASP/NIST guidance."
        )
    if finding_type.startswith("vulnerable-js-"):
        return (
            "Upgrade the vulnerable JavaScript dependency to a patched version and enforce SCA checks in CI to prevent reintroduction."
        )
    if finding_type.startswith("zap-"):
        return (
            "Review the specific OWASP ZAP alert details and implement targeted remediation and verification for the affected endpoint."
        )
    return "Review this finding manually and apply least-privilege, input validation, output encoding, and secure-by-default controls."


def _logo_data_uri(logo_path: Path | None = None) -> str:
    path = logo_path if logo_path is not None else _LOGO_PATH
    if path is None or not path.is_file():
        return ""
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    suffix = path.suffix.lower()
    mime = "image/png"
    if suffix in {".jpg", ".jpeg"}:
        mime = "image/jpeg"
    elif suffix == ".webp":
        mime = "image/webp"
    elif suffix == ".gif":
        mime = "image/gif"
    return f"data:{mime};base64,{encoded}"


def _pdf_safe_text(value: Any) -> str:
    return str(value).encode("latin-1", errors="replace").decode("latin-1")


def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Aggregate findings by (type, tool) combination.

    Instead of repeating the full description/remediation for each URL where
    an issue was found, this collapses duplicates into a single entry with:
    - The shared description, remediation, and severity shown once
    - A list of affected URLs underneath
    - Per-URL evidence preserved only where it actually differs

    Returns a list of deduplicated finding groups.
    """
    # Group by (type, tool) - these are the fields that define a "same" finding
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        key = (
            str(finding.get("type", "unknown")),
            str(finding.get("tool", "unknown")),
        )
        groups[key].append(finding)

    deduplicated: list[dict[str, Any]] = []
    for (finding_type, tool), instances in groups.items():
        if len(instances) == 1:
            # Single instance - no deduplication needed, preserve as-is
            deduplicated.append(instances[0])
            continue

        # Multiple instances of the same finding type from the same tool
        # Use the first instance as the template for shared fields
        template = instances[0]

        # Collect all affected URLs
        affected_urls: list[str] = []
        url_evidence: dict[str, str] = {}
        has_varying_evidence = False
        first_evidence = template.get("evidence")

        for inst in instances:
            url = str(inst.get("url", "n/a"))
            if url not in affected_urls:
                affected_urls.append(url)

            # Check if evidence varies across instances
            inst_evidence = inst.get("evidence")
            if inst_evidence:
                url_evidence[url] = str(inst_evidence)
                if inst_evidence != first_evidence:
                    has_varying_evidence = True

        # Build the collapsed finding
        collapsed: dict[str, Any] = {
            "id": template.get("id", f"{finding_type}-{tool}"),
            "type": finding_type,
            "tool": tool,
            "severity": template.get("severity", "info"),
            "cvss_score": template.get("cvss_score"),
            "confidence": template.get("confidence", 1.0),
            "cwe_id": template.get("cwe_id"),
            "description": template.get("description"),
            "remediation": template.get("remediation"),
            "raw_data": template.get("raw_data"),
            "config_snippets": template.get("config_snippets"),
            "verification": template.get("verification"),
            "likely_false_positive": template.get("likely_false_positive", False),
            # New fields for collapsed findings
            "is_collapsed": True,
            "instance_count": len(instances),
            "affected_urls": affected_urls,
        }

        # Include per-URL evidence only if it varies
        if has_varying_evidence and url_evidence:
            collapsed["url_evidence"] = url_evidence
        elif first_evidence:
            collapsed["evidence"] = first_evidence

        # Use first URL as the primary URL for backward compatibility
        collapsed["url"] = affected_urls[0] if affected_urls else "n/a"

        deduplicated.append(collapsed)

    return deduplicated


def _group_findings_by_severity_deduplicated(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group findings by severity after deduplication."""
    deduplicated = _deduplicate_findings(findings)
    return _group_findings_by_severity_from_groups(deduplicated)


def _group_findings_by_severity_from_groups(
    groups: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group already-deduplicated finding groups by severity."""
    grouped: dict[str, list[dict[str, Any]]] = {
        severity: [] for severity in _SEVERITY_ORDER
    }
    for finding in groups:
        severity = _normalize_severity(finding.get("severity"))
        enriched = dict(finding)
        enriched["severity"] = severity
        enriched["remediation"] = _remediation_for_finding_type(
            str(finding.get("type", "unknown")),
            finding,
        )
        if finding.get("config_snippets"):
            enriched["config_snippets"] = finding["config_snippets"]
        grouped[severity].append(enriched)
    return grouped


class CheckmatePDF(FPDF):
    """Custom PDF class with Checkmate or Agency white-label branding."""

    def __init__(
        self,
        scan_id: str,
        target: str,
        *,
        branding: ReportBranding | None = None,
    ) -> None:
        super().__init__()
        self.scan_id = scan_id
        self.target = target
        self.branding = branding or ReportBranding(
            brand_name=_DEFAULT_BRAND_NAME,
            tagline=_DEFAULT_TAGLINE,
            logo_path=_LOGO_PATH if _LOGO_PATH.is_file() else None,
            white_label=False,
        )
        self._is_cover_page = True

    def header(self) -> None:
        """Render page header on all pages except cover."""
        if self._is_cover_page:
            return
        # Dark header bar
        self.set_fill_color(*COLORS.HEADER_BG)
        self.rect(0, 0, 210, 12, style="F")
        # Logo (small)
        logo = self.branding.logo_path
        if logo is not None and logo.is_file():
            self.image(str(logo), x=5, y=2, h=8)
        # Scan ID
        self.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_TINY)
        self.set_text_color(*COLORS.FG_MUTED)
        self.set_xy(18, 3)
        self.cell(0, 6, _pdf_safe_text(f"Scan: {self.scan_id[:20]}..."), align="L")

    def footer(self) -> None:
        """Render page footer with page number and timestamp."""
        if self._is_cover_page:
            return
        self.set_y(-10)
        self.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_TINY)
        self.set_text_color(*COLORS.FG_DIM)
        # Page number centered
        self.cell(0, 6, f"Page {self.page_no()}", align="C")


def _draw_severity_badge(
    pdf: FPDF,
    severity: str,
    x: float,
    y: float,
) -> float:
    """Draw a colored severity badge and return its width."""
    color = severity_color(severity)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 8)
    text = severity.upper()
    width = pdf.get_string_width(text) + 6
    pdf.set_xy(x, y)
    pdf.cell(width, 5, text, fill=True, align="C")
    return width


def _draw_risk_gauge(
    pdf: FPDF,
    score: float,
    x: float,
    y: float,
    width: float = 60,
    height: float = 12,
) -> None:
    """Draw a visual risk score gauge."""
    # Background
    pdf.set_fill_color(229, 231, 235)  # gray-200
    pdf.rect(x, y, width, height, style="F")

    # Filled portion based on score (0-10)
    fill_width = max(0, min(width, (score / 10.0) * width))
    if fill_width > 0:
        color = risk_score_color(score)
        pdf.set_fill_color(*color)
        pdf.rect(x, y, fill_width, height, style="F")

    # Score text overlay
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 10)
    pdf.set_text_color(31, 41, 55)  # gray-800
    pdf.set_xy(x, y)
    pdf.cell(width, height, f"{score:.1f} / 10", align="C")


def _draw_severity_summary_bar(
    pdf: FPDF,
    counts: dict[str, int],
    x: float,
    y: float,
    width: float,
) -> float:
    """Draw horizontal severity summary with colored cards. Returns height used."""
    card_width = (width - 16) / 5  # 5 severities, 4 gaps of 4mm
    card_height = 14
    gap = 4

    for idx, severity in enumerate(_SEVERITY_ORDER):
        card_x = x + idx * (card_width + gap)
        count = counts.get(severity, 0)

        # Card background
        bg_color = severity_light_color(severity)
        pdf.set_fill_color(*bg_color)
        pdf.rect(card_x, y, card_width, card_height, style="F")

        # Left accent border
        accent_color = severity_color(severity)
        pdf.set_fill_color(*accent_color)
        pdf.rect(card_x, y, 2, card_height, style="F")

        # Severity label
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 7)
        pdf.set_text_color(*accent_color)
        pdf.set_xy(card_x + 4, y + 2)
        pdf.cell(card_width - 6, 4, severity.upper(), align="L")

        # Count
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 12)
        pdf.set_text_color(31, 41, 55)
        pdf.set_xy(card_x + 4, y + 6)
        pdf.cell(card_width - 6, 6, str(count), align="L")

    return card_height


def _draw_info_callout(
    pdf: FPDF,
    title: str,
    content: list[str],
    x: float,
    y: float,
    width: float,
    border_color: RGB = COLORS.GOOD_TO_KNOW_BORDER,
    bg_color: RGB = COLORS.GOOD_TO_KNOW_BG,
) -> float:
    """Draw a highlighted info callout box. Returns height used."""
    # Calculate content height
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    line_height = 5
    title_height = 7
    padding = 6
    content_height = sum(
        pdf.get_string_width(_pdf_safe_text(line)) // (width - padding * 2 - 4) + 1
        for line in content
    ) * line_height
    total_height = title_height + content_height + padding * 2

    # Background
    pdf.set_fill_color(*bg_color)
    pdf.rect(x, y, width, total_height, style="F")

    # Left accent border
    pdf.set_fill_color(*border_color)
    pdf.rect(x, y, 3, total_height, style="F")

    # Title
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_BODY)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(x + padding + 2, y + padding)
    pdf.cell(width - padding * 2 - 2, title_height, _pdf_safe_text(title), align="L")

    # Content
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(x + padding + 2, y + padding + title_height)
    for line in content:
        pdf.multi_cell(width - padding * 2 - 4, line_height, _pdf_safe_text(f"- {line}"))

    return total_height


def _draw_finding_card(
    pdf: FPDF,
    finding: dict[str, Any],
    x: float,
    y: float,
    width: float,
) -> float:
    """Draw a finding card with all details. Returns height used."""
    severity = _normalize_severity(finding.get("severity"))
    plain = _plain_language(finding)
    start_y = y

    # Check if we need a new page
    if y > 250:
        pdf.add_page()
        y = pdf.get_y()
        start_y = y

    # Card border (left accent)
    border_color = severity_color(severity)

    # Title row with severity badge
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H3)
    pdf.set_text_color(31, 41, 55)

    # Draw severity badge first
    badge_width = _draw_severity_badge(pdf, severity, x, y)

    # Title text
    title = plain["title"]
    if finding.get("likely_false_positive"):
        title += " (likely false positive)"
    if finding.get("is_collapsed"):
        title += f" [{finding.get('instance_count', 1)} instances]"

    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H3)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(x + badge_width + 4, y)
    # Use multi_cell for long titles to prevent truncation
    title_width = width - badge_width - 4
    pdf.multi_cell(title_width, 6, _pdf_safe_text(title))
    y = pdf.get_y() + 2

    # Plain English explanation (in a light background box)
    pdf.set_fill_color(248, 250, 252)  # slate-50
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_text_color(55, 65, 81)  # gray-700
    explanation = f"{plain['what']} {plain['why']}"
    # Calculate lines needed
    lines = pdf.get_string_width(_pdf_safe_text(explanation)) / (width - 8) + 1
    box_height = max(12, int(lines) * 5 + 6)
    pdf.rect(x, y, width, box_height, style="F")
    pdf.set_xy(x + 4, y + 3)
    pdf.multi_cell(width - 8, 5, _pdf_safe_text(explanation))
    y = pdf.get_y() + 3

    # Affected URLs section (handles both single and collapsed findings)
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_SMALL)
    pdf.set_text_color(75, 85, 99)
    pdf.set_xy(x, y)

    if finding.get("is_collapsed") and finding.get("affected_urls"):
        affected_urls = finding["affected_urls"]
        url_count = len(affected_urls)
        pdf.multi_cell(width, 5, _pdf_safe_text(f"Found on {url_count} pages:"))
        y = pdf.get_y()
        pdf.set_font(TYPOGRAPHY.FONT_MONO, "", 8)
        pdf.set_text_color(107, 114, 128)
        # Show URLs (limit display to avoid overflow)
        display_urls = affected_urls[:8]
        for url in display_urls:
            pdf.set_xy(x + 4, y)
            # Truncate very long URLs in display
            display_url = url if len(url) <= 80 else url[:77] + "..."
            pdf.multi_cell(width - 8, 4, _pdf_safe_text(display_url))
            y = pdf.get_y()
        if len(affected_urls) > 8:
            pdf.set_xy(x + 4, y)
            pdf.multi_cell(width - 8, 4, _pdf_safe_text(f"...and {len(affected_urls) - 8} more"))
            y = pdf.get_y()

        # Per-URL evidence if it varies
        if finding.get("url_evidence"):
            y += 2
            pdf.set_font(TYPOGRAPHY.FONT_SANS, "I", 8)
            pdf.set_text_color(107, 114, 128)
            pdf.set_xy(x, y)
            pdf.multi_cell(width, 4, _pdf_safe_text("Evidence varies per URL (see JSON report for details)"))
            y = pdf.get_y()
    else:
        # Single finding
        url = finding.get("url", "n/a")
        pdf.multi_cell(width, 5, _pdf_safe_text("Where:"))
        y = pdf.get_y()
        pdf.set_font(TYPOGRAPHY.FONT_MONO, "", 8)
        pdf.set_text_color(107, 114, 128)
        pdf.set_xy(x + 4, y)
        pdf.multi_cell(width - 8, 4, _pdf_safe_text(url))
        y = pdf.get_y()

    y += 2

    # Remediation
    remediation = finding.get("remediation", "")
    if remediation:
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_SMALL)
        pdf.set_text_color(6, 95, 70)  # emerald-800
        pdf.set_xy(x, y)
        pdf.multi_cell(width, 5, _pdf_safe_text("How to fix it:"))
        y = pdf.get_y()
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_SMALL)
        pdf.set_xy(x + 4, y)
        pdf.multi_cell(width - 8, 4, _pdf_safe_text(remediation))
        y = pdf.get_y() + 2

    # Confidence
    confidence_text = _verification_plain(finding)
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_SMALL)
    pdf.set_text_color(75, 85, 99)
    pdf.set_xy(x, y)
    pdf.multi_cell(width, 4, _pdf_safe_text(f"Confidence: {confidence_text}"))
    y = pdf.get_y() + 2

    # Technical details (smaller, monospace, visually secondary)
    pdf.set_fill_color(241, 245, 249)  # slate-100
    tech_start_y = y
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 8)
    pdf.set_text_color(100, 116, 139)  # slate-500
    pdf.set_xy(x + 4, y + 2)
    pdf.cell(width - 8, 4, "Technical Details", align="L")
    y += 6

    pdf.set_font(TYPOGRAPHY.FONT_MONO, "", 7)
    pdf.set_text_color(71, 85, 105)  # slate-600
    tech_lines = [
        f"Type: {finding.get('type', 'unknown')}",
        f"Tool: {finding.get('tool', 'unknown')}",
        f"Score: {finding.get('cvss_score', 'n/a')}/10",
    ]
    if finding.get("cwe_id") not in (None, "", -1):
        tech_lines.append(f"CWE: {finding.get('cwe_id')}")
    if finding.get("evidence") and not finding.get("url_evidence"):
        evidence = str(finding["evidence"])
        if len(evidence) > 100:
            evidence = evidence[:97] + "..."
        tech_lines.append(f"Evidence: {evidence}")

    for line in tech_lines:
        pdf.set_xy(x + 4, y)
        pdf.multi_cell(width - 8, 3.5, _pdf_safe_text(line))
        y = pdf.get_y()

    # Draw background for tech section
    tech_height = y - tech_start_y + 2
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(x, tech_start_y, width, tech_height, style="F")

    # Re-draw text over background (fpdf limitation)
    y = tech_start_y
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 8)
    pdf.set_text_color(100, 116, 139)
    pdf.set_xy(x + 4, y + 2)
    pdf.cell(width - 8, 4, "Technical Details", align="L")
    y += 6
    pdf.set_font(TYPOGRAPHY.FONT_MONO, "", 7)
    pdf.set_text_color(71, 85, 105)
    for line in tech_lines:
        pdf.set_xy(x + 4, y)
        pdf.multi_cell(width - 8, 3.5, _pdf_safe_text(line))
        y = pdf.get_y()

    y += 4

    # Left accent border for the entire card
    total_height = y - start_y
    pdf.set_fill_color(*border_color)
    pdf.rect(x - 2, start_y, 2, total_height, style="F")

    return total_height


def _write_pdf_report(report: dict[str, Any], pdf_path: Path) -> None:
    """Generate a professionally designed PDF report."""
    branding = report.get("_branding")
    if not isinstance(branding, ReportBranding):
        branding = resolve_report_branding(report.get("org_id"))
    pdf = CheckmatePDF(report["scan_id"], report["target"], branding=branding)
    pdf.set_margins(SPACING.MARGIN_LEFT, SPACING.MARGIN_TOP, SPACING.MARGIN_RIGHT)
    pdf.set_auto_page_break(auto=True, margin=SPACING.MARGIN_BOTTOM)

    # =========================================================================
    # COVER PAGE
    # =========================================================================
    pdf.add_page()
    pdf._is_cover_page = True
    content_width = pdf.epw

    # Dark header background
    pdf.set_fill_color(*COLORS.HEADER_BG)
    pdf.rect(0, 0, 210, 80, style="F")

    # Logo centered
    logo = branding.logo_path
    if logo is not None and logo.is_file():
        logo_x = (210 - SPACING.COVER_LOGO_SIZE) / 2
        pdf.image(str(logo), x=logo_x, y=15, h=SPACING.COVER_LOGO_SIZE)

    # Title
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_TITLE)
    pdf.set_text_color(*COLORS.FG_LIGHT)
    pdf.set_xy(SPACING.MARGIN_LEFT, 55)
    pdf.cell(content_width, 10, "Security Scan Report", align="C")

    # Tagline
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_text_color(*COLORS.FG_MUTED)
    pdf.set_xy(SPACING.MARGIN_LEFT, 66)
    pdf.cell(content_width, 6, _pdf_safe_text(branding.tagline), align="C")

    # Metadata section
    y = 90
    pdf.set_text_color(31, 41, 55)

    # Scan ID
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(35, 6, "Scan ID:", align="L")
    pdf.set_font(TYPOGRAPHY.FONT_MONO, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT + 35, y)
    pdf.multi_cell(content_width - 35, 6, _pdf_safe_text(report["scan_id"]))
    y = pdf.get_y() + 2

    # Target
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(35, 6, "Target:", align="L")
    pdf.set_font(TYPOGRAPHY.FONT_MONO, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT + 35, y)
    pdf.multi_cell(content_width - 35, 6, _pdf_safe_text(report["target"]))
    y = pdf.get_y() + 2

    # Generated at
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(35, 6, "Generated:", align="L")
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT + 35, y)
    pdf.multi_cell(content_width - 35, 6, _pdf_safe_text(report["generated_at"]))
    y = pdf.get_y() + 2

    # Status
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(35, 6, "Status:", align="L")
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_xy(SPACING.MARGIN_LEFT + 35, y)
    pdf.multi_cell(content_width - 35, 6, _pdf_safe_text(report["status"]))
    y = pdf.get_y() + 8

    # Overall Risk Score with visual gauge
    overall_score = float(report["severity_scores"].get("overall_risk_score", 0.0) or 0.0)
    exec_summary = _executive_summary(report)

    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H2)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(content_width, 8, "Overall Risk Assessment", align="L")
    y += 10

    # Risk label
    risk_color = risk_score_color(overall_score)
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", 16)
    pdf.set_text_color(*risk_color)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(80, 8, _pdf_safe_text(exec_summary["risk_label"]), align="L")

    # Risk gauge
    _draw_risk_gauge(pdf, overall_score, SPACING.MARGIN_LEFT + 85, y, 80, 10)
    y += 14

    # Risk explanation
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_text_color(75, 85, 99)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.multi_cell(content_width, 5, _pdf_safe_text(exec_summary["risk_sentence"]))
    y = pdf.get_y() + 8

    # Severity Summary bar
    counts = report["severity_scores"].get("severity_counts", {})
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H3)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(content_width, 6, "Findings by Severity", align="L")
    y += 8
    _draw_severity_summary_bar(pdf, counts, SPACING.MARGIN_LEFT, y, content_width)

    # =========================================================================
    # EXECUTIVE SUMMARY PAGE
    # =========================================================================
    pdf.add_page()
    pdf._is_cover_page = False
    y = pdf.get_y() + 5

    # AI Executive Summary (if available)
    ai = _ai_synthesis_block(report)
    if ai["show_ai_summary"]:
        exec_ai = ai["executive_summary"]

        # AI Summary card with distinct styling
        pdf.set_fill_color(*COLORS.AI_CARD_BG)
        pdf.set_draw_color(*COLORS.AI_CARD_BORDER)

        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H2)
        pdf.set_text_color(30, 64, 175)  # blue-800
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.cell(content_width - 50, 8, "AI Executive Summary", align="L")

        # AI-generated tag
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "", 7)
        pdf.set_fill_color(191, 219, 254)  # blue-200
        pdf.set_text_color(30, 64, 175)
        pdf.set_xy(SPACING.MARGIN_LEFT + content_width - 45, y + 1)
        pdf.cell(40, 5, "AI-Generated", fill=True, align="C")
        y += 12

        # Summary content in a box
        pdf.set_fill_color(*COLORS.AI_CARD_BG)
        summary_text = exec_ai.get("summary_text", "")
        lines = pdf.get_string_width(_pdf_safe_text(summary_text)) / (content_width - 16) + 1
        box_height = max(20, int(lines) * 5 + 12)
        pdf.rect(SPACING.MARGIN_LEFT, y, content_width, box_height, style="FD")

        pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
        pdf.set_text_color(31, 41, 55)
        pdf.set_xy(SPACING.MARGIN_LEFT + 8, y + 6)
        pdf.multi_cell(content_width - 16, 5, _pdf_safe_text(summary_text))
        y = pdf.get_y() + 4

        if exec_ai.get("business_impact_one_liner"):
            pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_SMALL)
            pdf.set_text_color(75, 85, 99)
            pdf.set_xy(SPACING.MARGIN_LEFT + 8, y)
            pdf.multi_cell(
                content_width - 16,
                5,
                _pdf_safe_text(f"Business Impact: {exec_ai['business_impact_one_liner']}"),
            )
        y = pdf.get_y() + 8

    elif ai["unavailable"]:
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H2)
        pdf.set_text_color(107, 114, 128)
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.cell(content_width, 8, "AI Executive Summary", align="L")
        y += 10
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "I", TYPOGRAPHY.SIZE_BODY)
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.multi_cell(content_width, 5, "AI summary unavailable for this scan.")
        y = pdf.get_y() + 8

    # Recommended Fix Order (if available)
    if ai["show_roadmap"]:
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H2)
        pdf.set_text_color(31, 41, 55)
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.cell(content_width, 8, "Recommended Fix Order", align="L")
        y += 10

        pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
        for idx, item in enumerate(ai["remediation_roadmap"], start=1):
            effort = item.get("estimated_effort", "moderate")
            rationale = item.get("rationale", "")
            finding_ids = ", ".join(str(fid) for fid in item.get("finding_ids") or [])

            pdf.set_text_color(31, 41, 55)
            pdf.set_xy(SPACING.MARGIN_LEFT, y)
            pdf.multi_cell(
                content_width,
                5,
                _pdf_safe_text(f"{idx}. [{effort.upper()}] {rationale}"),
            )
            y = pdf.get_y()
            if finding_ids:
                pdf.set_text_color(107, 114, 128)
                pdf.set_font(TYPOGRAPHY.FONT_MONO, "", 8)
                pdf.set_xy(SPACING.MARGIN_LEFT + 8, y)
                pdf.multi_cell(content_width - 8, 4, _pdf_safe_text(f"Findings: {finding_ids}"))
                pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
                y = pdf.get_y()
            y += 2

        y += 6

    # Plain Language Executive Summary
    pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H2)
    pdf.set_text_color(31, 41, 55)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.cell(content_width, 8, "Executive Summary", align="L")
    y += 10

    pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
    pdf.set_text_color(55, 65, 81)
    pdf.set_xy(SPACING.MARGIN_LEFT, y)
    pdf.multi_cell(content_width, 5, _pdf_safe_text(exec_summary["headline"]))
    y = pdf.get_y() + 4

    # Priority items
    if exec_summary["priorities"]:
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H3)
        pdf.set_text_color(31, 41, 55)
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.cell(content_width, 6, "What to tackle first:", align="L")
        y += 8

        for idx, item in enumerate(exec_summary["priorities"], start=1):
            sev = item["severity"]
            sev_color = severity_color(sev)

            pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_BODY)
            pdf.set_text_color(*sev_color)
            pdf.set_xy(SPACING.MARGIN_LEFT, y)
            pdf.cell(8, 5, f"{idx}.", align="L")

            # Severity badge
            _draw_severity_badge(pdf, sev, SPACING.MARGIN_LEFT + 8, y)

            pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
            pdf.set_text_color(31, 41, 55)
            pdf.set_xy(SPACING.MARGIN_LEFT + 30, y)
            pdf.multi_cell(content_width - 32, 5, _pdf_safe_text(item["title"]))
            y = pdf.get_y() + 2

        y += 4

    # Good to know callout
    if exec_summary["notes"]:
        callout_height = _draw_info_callout(
            pdf,
            "Good to know",
            exec_summary["notes"],
            SPACING.MARGIN_LEFT,
            y,
            content_width,
        )
        y += callout_height + 8

    # Truncation notice if applicable
    if report.get("truncation"):
        trunc = report["truncation"]
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "I", TYPOGRAPHY.SIZE_SMALL)
        pdf.set_text_color(180, 83, 9)  # amber-700
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.multi_cell(
            content_width,
            5,
            _pdf_safe_text(
                f"Note: Showing {trunc['rendered_findings']} of {trunc['total_findings']} "
                f"findings. Lower-severity entries truncated. See JSON report for full data."
            ),
        )

    # Mandatory coverage & limitations (before findings — always present).
    y = pdf.get_y() + 6
    y = _draw_coverage_pdf(pdf, report, y)

    # =========================================================================
    # FINDINGS BY SEVERITY
    # =========================================================================
    findings_by_severity = report.get("findings_by_severity_deduplicated") or report["findings_by_severity"]

    for severity in _SEVERITY_ORDER:
        severity_findings = findings_by_severity.get(severity, [])

        # Start new page for each severity section
        pdf.add_page()
        y = pdf.get_y() + 5

        # Section header with severity color
        sev_color = severity_color(severity)
        pdf.set_fill_color(*sev_color)
        pdf.rect(SPACING.MARGIN_LEFT - 2, y, content_width + 4, 12, style="F")

        pdf.set_font(TYPOGRAPHY.FONT_SANS, "B", TYPOGRAPHY.SIZE_H1)
        pdf.set_text_color(255, 255, 255)
        pdf.set_xy(SPACING.MARGIN_LEFT + 4, y + 2)
        pdf.cell(
            content_width - 8,
            8,
            f"{severity.upper()} ({len(severity_findings)})",
            align="L",
        )
        y += 16

        # Severity explanation
        pdf.set_font(TYPOGRAPHY.FONT_SANS, "I", TYPOGRAPHY.SIZE_SMALL)
        pdf.set_text_color(75, 85, 99)
        pdf.set_xy(SPACING.MARGIN_LEFT, y)
        pdf.multi_cell(content_width, 5, _pdf_safe_text(_SEVERITY_PLAIN[severity]))
        y = pdf.get_y() + 6

        if not severity_findings:
            # Clean state for zero findings - show as positive
            pdf.set_fill_color(240, 253, 244)  # green-50
            pdf.rect(SPACING.MARGIN_LEFT, y, content_width, 20, style="F")
            pdf.set_fill_color(34, 197, 94)  # green-500
            pdf.rect(SPACING.MARGIN_LEFT, y, 3, 20, style="F")

            pdf.set_font(TYPOGRAPHY.FONT_SANS, "", TYPOGRAPHY.SIZE_BODY)
            pdf.set_text_color(22, 101, 52)  # green-800
            pdf.set_xy(SPACING.MARGIN_LEFT + 10, y + 6)
            checkmark = "No findings in this severity tier"
            pdf.cell(content_width - 12, 8, _pdf_safe_text(checkmark), align="L")
            continue

        # Render each finding
        for finding in severity_findings:
            # Check page break
            if y > 230:
                pdf.add_page()
                y = pdf.get_y() + 5

            card_height = _draw_finding_card(pdf, finding, SPACING.MARGIN_LEFT, y, content_width)
            y += card_height + 6

    pdf.output(str(pdf_path))


def _group_findings_by_severity(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {severity: [] for severity in _SEVERITY_ORDER}
    for finding in findings:
        severity = _normalize_severity(finding.get("severity"))
        enriched = dict(finding)
        enriched["severity"] = severity
        enriched["remediation"] = _remediation_for_finding_type(
            str(finding.get("type", "unknown")),
            finding,
        )
        # Preserve deterministic config snippets attached by ai_synthesis.
        if finding.get("config_snippets"):
            enriched["config_snippets"] = finding["config_snippets"]
        grouped[severity].append(enriched)
    return grouped


def _ai_synthesis_block(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize AI copilot fields for template rendering."""
    ai = report.get("ai_synthesis") or {}
    coverage = (report.get("severity_scores") or {}).get("scan_coverage") or {}
    status = (
        ai.get("status")
        or coverage.get("ai_synthesis_status")
        or "skipped"
    )
    executive = ai.get("executive_summary")
    roadmap = ai.get("remediation_roadmap")
    return {
        "status": status,
        "provider": ai.get("provider") or coverage.get("ai_synthesis_provider") or "none",
        "provider_role": ai.get("provider_role")
        or coverage.get("ai_synthesis_provider_role")
        or "none",
        "fallback_reason": ai.get("fallback_reason")
        or coverage.get("ai_synthesis_fallback_reason"),
        "executive_summary": executive if isinstance(executive, dict) else None,
        "remediation_roadmap": roadmap if isinstance(roadmap, list) else None,
        "config_fixes": ai.get("config_fixes") or [],
        "show_ai_summary": bool(
            isinstance(executive, dict) and executive.get("summary_text")
        ),
        "show_roadmap": bool(isinstance(roadmap, list) and roadmap),
        "unavailable": status == "unavailable",
    }


def _config_snippets_markdown(snippets: dict[str, str]) -> list[str]:
    lines: list[str] = []
    lines.append("**Copy-paste config fix:**")
    lines.append("")
    for label, key in (("Nginx", "nginx"), ("Apache", "apache"), ("Node/Express", "express")):
        body = snippets.get(key)
        if not body:
            continue
        lang = "nginx" if key == "nginx" else ("apache" if key == "apache" else "javascript")
        lines.append(f"*{label}:*")
        lines.append(f"```{lang}")
        lines.append(body)
        lines.append("```")
        lines.append("")
    return lines


def _md_escape(value: Any) -> str:
    """Escape attacker-controlled text before embedding in Markdown reports."""
    text = str(value)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("`", "\\`")
    text = text.replace("[", "\\[").replace("]", "\\]")
    return text


def _build_markdown_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    branding = report.get("_branding")
    if not isinstance(branding, ReportBranding):
        branding = resolve_report_branding(report.get("org_id"))
    lines.append(f"# {_md_escape(branding.brand_name)} Report - {_md_escape(report['scan_id'])}")
    lines.append("")

    ai = _ai_synthesis_block(report)
    if ai["show_ai_summary"]:
        exec_ai = ai["executive_summary"]
        lines.append("## AI Executive Summary")
        lines.append("")
        lines.append("> *AI-Generated*")
        lines.append("")
        lines.append(_md_escape(exec_ai.get("summary_text", "")))
        lines.append("")
        if exec_ai.get("business_impact_one_liner"):
            lines.append(f"**Business impact:** {_md_escape(exec_ai['business_impact_one_liner'])}")
            lines.append("")
        if exec_ai.get("top_risk_finding_id"):
            lines.append(f"**Top risk finding:** `{exec_ai['top_risk_finding_id']}`")
            lines.append("")
    elif ai["unavailable"]:
        lines.append("## AI Executive Summary")
        lines.append("")
        lines.append("_AI summary unavailable._")
        lines.append("")

    if ai["show_roadmap"]:
        lines.append("## Recommended Fix Order")
        lines.append("")
        for idx, item in enumerate(ai["remediation_roadmap"], start=1):
            ids = ", ".join(f"`{fid}`" for fid in item.get("finding_ids") or [])
            effort = item.get("estimated_effort", "moderate")
            lines.append(f"{idx}. **{_md_escape(effort)}** — {_md_escape(item.get('rationale', ''))}")
            if ids:
                lines.append(f"   - Findings: {ids}")
        lines.append("")

    exec_summary = _executive_summary(report)
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"**Overall risk: {exec_summary['risk_label']} "
        f"({exec_summary['overall_risk_score']} / 10).** {exec_summary['risk_sentence']}"
    )
    lines.append("")
    lines.append(exec_summary["headline"])
    lines.append("")
    if exec_summary["priorities"]:
        lines.append("**What to tackle first:**")
        lines.append("")
        for item in exec_summary["priorities"]:
            lines.append(f"1. _{item['severity'].upper()}_ — **{_md_escape(item['title'])}**")
            if item["action"]:
                lines.append(f"   - Fix: {_md_escape(item['action'])}")
        lines.append("")
    if exec_summary["notes"]:
        lines.append("> **Good to know:**")
        lines.append(">")
        for note in exec_summary["notes"]:
            lines.append(f"> - {_md_escape(note)}")
        lines.append("")

    # Truncation notice
    if report.get("truncation"):
        trunc = report["truncation"]
        lines.append(f"> **Note:** Showing {trunc['rendered_findings']} of {trunc['total_findings']} ")
        lines.append("> findings. Lower-severity entries truncated. See JSON report for full data.")
        lines.append("")

    lines.append("## Scan Details")
    lines.append("")
    lines.append(f"- **Target:** `{_md_escape(report['target'])}`")
    lines.append(f"- **Scan ID:** `{_md_escape(report['scan_id'])}`")
    lines.append(f"- **Status:** `{_md_escape(report['status'])}`")
    lines.append(f"- **Generated At:** `{_md_escape(report['generated_at'])}`")
    lines.append(f"- **Total Findings:** `{report['findings_count']}`")
    lines.append(f"- **Overall Risk Score (0-10):** `{report['severity_scores'].get('overall_risk_score', 0.0)}`")
    likely_fp = report["severity_scores"].get("likely_false_positives")
    if likely_fp:
        lines.append(f"- **Likely False Positives (deprioritized):** `{likely_fp}`")
    coverage = report["severity_scores"].get("scan_coverage") or {}
    if coverage.get("ai_synthesis_status"):
        lines.append(f"- **AI Security Copilot:** `{coverage.get('ai_synthesis_status')}`")
        if coverage.get("ai_synthesis_provider"):
            lines.append(
                f"- **AI provider:** `{coverage.get('ai_synthesis_provider')}` "
                f"({coverage.get('ai_synthesis_provider_role', 'none')})"
            )
    if report.get("summary"):
        lines.append(f"- **Summary:** {_md_escape(report['summary'])}")
    if report.get("outcome"):
        lines.append(f"- **Outcome:** `{_md_escape(report['outcome'])}`")
    lines.append("")

    lines.extend(_coverage_markdown(report))

    counts = report["severity_scores"].get("severity_counts", {})
    lines.append("## Severity Summary")
    lines.append("")
    lines.append("| Severity | Count | Description |")
    lines.append("|----------|-------|-------------|")
    for severity in _SEVERITY_ORDER:
        lines.append(
            f"| **{severity.title()}** | {counts.get(severity, 0)} | {_SEVERITY_PLAIN[severity]} |"
        )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    # Use deduplicated findings
    findings_by_severity = (
        report.get("findings_by_severity_deduplicated") or report["findings_by_severity"]
    )
    for severity in _SEVERITY_ORDER:
        severity_findings = findings_by_severity.get(severity, [])
        lines.append(f"### {severity.title()} ({len(severity_findings)})")
        lines.append("")
        if not severity_findings:
            lines.append("✓ _No findings in this severity tier._")
            lines.append("")
            continue

        for finding in severity_findings:
            plain = _plain_language(finding)
            fp_note = " _(likely false positive)_" if finding.get("likely_false_positive") else ""
            instance_note = ""
            if finding.get("is_collapsed") and finding.get("instance_count", 1) > 1:
                instance_note = f" [{finding['instance_count']} instances]"
            lines.append(f"#### {_md_escape(plain['title'])}{fp_note}{instance_note}")
            lines.append("")
            lines.append(
                f"- **In plain English:** {_md_escape(plain['what'])} {_md_escape(plain['why'])}"
            )

            # Handle single vs collapsed URLs
            if finding.get("is_collapsed") and finding.get("affected_urls"):
                urls = finding["affected_urls"]
                url_count = len(urls)
                lines.append(f"- **Found on {url_count} pages:**")
                for url in urls[:8]:
                    lines.append(f"  - `{_md_escape(url)}`")
                if url_count > 8:
                    lines.append(f"  - ...and {url_count - 8} more URLs")
                if finding.get("url_evidence"):
                    lines.append("  - *(Evidence varies per URL - see JSON report)*")
            else:
                lines.append(f"- **Where:** `{_md_escape(finding.get('url', 'n/a'))}`")

            lines.append(f"- **How to fix it:** {_md_escape(finding['remediation'])}")
            lines.append(f"- **Confidence:** {_verification_plain(finding)}")
            snippets = finding.get("config_snippets")
            if isinstance(snippets, dict) and snippets:
                lines.append("")
                lines.extend(_config_snippets_markdown(snippets))
            lines.append("")
            lines.append("<details><summary>Technical details</summary>")
            lines.append("")
            lines.append(
                f"  - Type: `{finding.get('type', 'unknown')}` | "
                f"Tool: `{finding.get('tool', 'unknown')}` | "
                f"Score: `{finding.get('cvss_score', 'n/a')}` | "
                f"Confidence: `{finding.get('confidence', 1.0)}`"
            )
            if finding.get("cwe_id") not in (None, "", -1):
                lines.append(f"  - CWE: `{finding.get('cwe_id')}`")
            lines.append(f"  - Description: {_md_escape(finding.get('description', 'No description provided'))}")
            # Only show evidence if not varying per URL
            if finding.get("evidence") and not finding.get("url_evidence"):
                lines.append(f"  - Evidence: {_md_escape(finding['evidence'])}")
            verification = finding.get("verification") or {}
            v_status = verification.get("status")
            if v_status:
                lines.append(
                    f"  - Verification: {v_status} (confidence: {finding.get('confidence', 1.0)})"
                )
                if verification.get("reason"):
                    lines.append(f"  - Verification note: {_md_escape(verification['reason'])}")
                if verification.get("evidence"):
                    lines.append(f"  - Verified evidence: {_md_escape(verification['evidence'])}")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    return "\n".join(lines).strip() + "\n"


def _build_html_report(report: dict[str, Any]) -> str:
    counts = report["severity_scores"].get("severity_counts", {})
    branding = report.get("_branding")
    if not isinstance(branding, ReportBranding):
        branding = resolve_report_branding(report.get("org_id"))
    logo_uri = _logo_data_uri(branding.logo_path)
    logo_markup = (
        f'<img src="{logo_uri}" alt="{html.escape(branding.brand_name)}" class="logo" />'
        if logo_uri
        else ""
    )
    exec_summary = _executive_summary(report)

    # Use deduplicated findings for display
    findings_by_severity = (
        report.get("findings_by_severity_deduplicated") or report["findings_by_severity"]
    )

    def esc(value: Any) -> str:
        return html.escape(str(value))

    def technical_details(finding: dict[str, Any]) -> str:
        verification = finding.get("verification") or {}
        rows = [
            ("Finding type", finding.get("type", "unknown")),
            ("Detected by", finding.get("tool", "unknown")),
            ("Risk score (0-10)", finding.get("cvss_score", "n/a")),
            ("Confidence", finding.get("confidence", 1.0)),
        ]
        if finding.get("cwe_id") not in (None, "", -1):
            rows.append(("CWE", finding.get("cwe_id")))
        if verification.get("status"):
            rows.append(("Verification status", verification.get("status")))
        # Only show evidence if it doesn't vary per URL
        if finding.get("evidence") and not finding.get("url_evidence"):
            rows.append(("Evidence", finding.get("evidence")))
        if verification.get("reason"):
            rows.append(("Verification note", verification.get("reason")))
        if finding.get("description"):
            rows.append(("Scanner description", finding.get("description")))
        body = "".join(
            f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>" for label, value in rows
        )
        return (
            "<details class='tech'>"
            "<summary>Technical details</summary>"
            f"<table class='tech-table'><tbody>{body}</tbody></table>"
            "</details>"
        )

    def url_list_html(finding: dict[str, Any]) -> str:
        """Render the affected URLs section for a finding."""
        if finding.get("is_collapsed") and finding.get("affected_urls"):
            urls = finding["affected_urls"]
            count = len(urls)
            # Show limited URLs with expand option
            display_urls = urls[:10]
            url_items = "".join(f"<li><code>{esc(u)}</code></li>" for u in display_urls)
            more = ""
            if count > 10:
                more = f"<li class='muted'>...and {count - 10} more URLs</li>"

            # Per-URL evidence notice
            evidence_note = ""
            if finding.get("url_evidence"):
                evidence_note = (
                    "<p class='evidence-varies'><em>Evidence varies per URL. "
                    "See JSON report for per-URL details.</em></p>"
                )

            return f"""
            <div class="affected-urls">
              <p class="location"><strong>Found on {count} pages:</strong></p>
              <ul class="url-list">{url_items}{more}</ul>
              {evidence_note}
            </div>
            """
        else:
            # Single URL
            return f"<p class='location'>Where: <code>{esc(finding.get('url', 'n/a'))}</code></p>"

    def finding_card(finding: dict[str, Any]) -> str:
        severity = _normalize_severity(finding.get("severity"))
        plain = _plain_language(finding)
        fp_badge = (
            "<span class='badge badge-fp'>likely false positive</span>"
            if finding.get("likely_false_positive")
            else ""
        )
        instance_badge = ""
        if finding.get("is_collapsed") and finding.get("instance_count", 1) > 1:
            instance_badge = (
                f"<span class='badge badge-instance'>{finding['instance_count']} instances</span>"
            )

        snippets = finding.get("config_snippets") or {}
        snippet_html = ""
        if isinstance(snippets, dict) and any(snippets.get(k) for k in ("nginx", "apache", "express")):
            parts = []
            for label, key in (("Nginx", "nginx"), ("Apache", "apache"), ("Node/Express", "express")):
                body = snippets.get(key)
                if body:
                    parts.append(
                        f"<div class='snippet'><strong>{esc(label)}</strong>"
                        f"<pre><code>{esc(body)}</code></pre></div>"
                    )
            snippet_html = (
                "<div class='config-fix'><strong>Copy-paste config fix</strong>"
                + "".join(parts)
                + "</div>"
            )

        # Confidence badge with distinct styling
        verification = finding.get("verification") or {}
        v_status = verification.get("status", "").lower()
        confidence_class = "badge-confirmed" if v_status == "confirmed" else "badge-unconfirmed"
        confidence_label = "Confirmed" if v_status == "confirmed" else (
            "Likely FP" if finding.get("likely_false_positive") else "Unverified"
        )

        return f"""
        <article class="finding sev-border-{severity}">
          <div class="finding-head">
            <span class="badge badge-{severity}">{severity.upper()}</span>
            <h3>{esc(plain['title'])}</h3>
            <span class="badge {confidence_class}">{confidence_label}</span>
            <span class="score">Risk {esc(finding.get('cvss_score', 'n/a'))}/10</span>
            {fp_badge}
            {instance_badge}
          </div>
          {url_list_html(finding)}
          <p class="plain"><strong>In plain English:</strong> {esc(plain['what'])} {esc(plain['why'])}</p>
          <p class="fix"><strong>How to fix it:</strong> {esc(finding.get('remediation', ''))}</p>
          <p class="verify"><strong>Confidence:</strong> {esc(_verification_plain(finding))}</p>
          {snippet_html}
          {technical_details(finding)}
        </article>
        """

    sections: list[str] = []
    for severity in _SEVERITY_ORDER:
        findings = findings_by_severity.get(severity, [])
        if not findings:
            body = """
            <div class="empty-state">
              <span class="checkmark">&#10003;</span>
              <span>No findings in this severity tier</span>
            </div>
            """
        else:
            body = "".join(finding_card(f) for f in findings)
        sections.append(
            f"""
            <section id="sev-{severity}">
              <h2 class="sev-{severity}">{severity.title()} ({len(findings)})
                <span class="sev-hint">{esc(_SEVERITY_PLAIN[severity])}</span>
              </h2>
              {body}
            </section>
            """
        )

    # Table of contents / navigation
    toc_items = "".join(
        f"<a href='#sev-{sev}' class='toc-item toc-{sev}'>"
        f"<span class='toc-label'>{sev.title()}</span>"
        f"<span class='toc-count'>{counts.get(sev, 0)}</span></a>"
        for sev in _SEVERITY_ORDER
    )
    toc_block = f"<nav class='toc'>{toc_items}</nav>"

    if exec_summary["priorities"]:
        priority_items = "".join(
            f"<li><span class='badge badge-{p['severity']}'>{p['severity'].upper()}</span> "
            f"<strong>{esc(p['title'])}</strong><br /><span class='muted'>{esc(p['action'])}</span></li>"
            for p in exec_summary["priorities"]
        )
        priorities_block = f"<h3>What to tackle first</h3><ol class='priorities'>{priority_items}</ol>"
    else:
        priorities_block = ""

    notes_block = ""
    if exec_summary["notes"]:
        note_items = "".join(f"<li>{esc(n)}</li>" for n in exec_summary["notes"])
        notes_block = f"""
        <div class="callout callout-info">
          <div class="callout-icon">&#9432;</div>
          <div class="callout-content">
            <h4>Good to know</h4>
            <ul class='notes'>{note_items}</ul>
          </div>
        </div>
        """

    ai = _ai_synthesis_block(report)
    ai_block = ""
    if ai["show_ai_summary"]:
        exec_ai = ai["executive_summary"]
        top = ""
        if exec_ai.get("top_risk_finding_id"):
            top = f"<p class='muted'>Top risk finding: <code>{esc(exec_ai['top_risk_finding_id'])}</code></p>"
        ai_block = f"""
  <div class="exec ai-exec">
    <div class="ai-label"><span class="ai-icon">&#9733;</span> AI-Generated</div>
    <h2>AI Executive Summary</h2>
    <p class="headline">{esc(exec_ai.get('summary_text', ''))}</p>
    <p><strong>Business impact:</strong> {esc(exec_ai.get('business_impact_one_liner', ''))}</p>
    {top}
  </div>
"""
    elif ai["unavailable"]:
        ai_block = """
  <div class="exec ai-exec ai-unavailable">
    <h2>AI Executive Summary</h2>
    <p class="muted"><em>AI summary unavailable for this scan.</em></p>
  </div>
"""

    roadmap_block = ""
    if ai["show_roadmap"]:
        items = "".join(
            f"<li><span class='badge badge-effort'>{esc(item.get('estimated_effort', 'moderate'))}</span> "
            f"{esc(item.get('rationale', ''))}"
            f"<br /><span class='muted'>Findings: "
            f"{esc(', '.join(str(x) for x in (item.get('finding_ids') or [])))}</span></li>"
            for item in ai["remediation_roadmap"]
        )
        roadmap_block = f"""
  <div class="exec">
    <h2>Recommended Fix Order</h2>
    <ol class="priorities">{items}</ol>
  </div>
"""

    # Truncation notice
    truncation_block = ""
    if report.get("truncation"):
        trunc = report["truncation"]
        truncation_block = f"""
        <div class="callout callout-warning">
          <div class="callout-icon">&#9888;</div>
          <div class="callout-content">
            <p><strong>Findings truncated:</strong> Showing {trunc['rendered_findings']} of
            {trunc['total_findings']} findings. Lower-severity entries were truncated.
            See the full JSON report for complete data.</p>
          </div>
        </div>
        """

    risk_pct = max(0.0, min(100.0, float(exec_summary["overall_risk_score"]) * 10.0))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{html.escape(branding.brand_name)} Report - {html.escape(report["scan_id"][:12])}</title>
  <style>
    :root {{
      --bg-dark: #0a0d0b;
      --panel: #0e1310;
      --header-bg: #0f172a;
      --fg-light: #f8fafc;
      --fg-muted: #94a3b8;
      --fg-dim: #6e8478;
      --accent: #3ddc84;
      --critical: #b91c1c;
      --high: #b45309;
      --medium: #854d0e;
      --low: #1d4ed8;
      --info: #4b5563;
      --success: #22c55e;
      --card-bg: #ffffff;
      --border: #e5e7eb;
    }}
    @page {{ margin: 1.5cm; }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0; padding: 24px;
      color: #1f2937; background: #f9fafb; line-height: 1.6;
    }}
    h1, h2, h3 {{ margin-bottom: 8px; }}
    code {{
      background: #f1f5f9; padding: 2px 6px; border-radius: 4px;
      font-size: 12px; word-break: break-all;
      font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
    }}

    /* Brand header */
    .brand {{
      display: flex; align-items: center; gap: 16px;
      margin-bottom: 24px; padding: 20px 24px; border-radius: 12px;
      background: var(--header-bg); color: var(--fg-light);
    }}
    .logo {{ height: 56px; width: auto; }}
    .brand h1 {{ margin: 0; color: var(--fg-light); font-size: 1.5rem; font-weight: 700; }}
    .brand .tagline {{ margin: 4px 0 0; color: var(--fg-muted); font-size: 0.85rem; }}

    /* Table of contents */
    .toc {{
      display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;
      padding: 12px 16px; background: var(--card-bg); border-radius: 8px;
      border: 1px solid var(--border);
    }}
    .toc-item {{
      display: flex; align-items: center; gap: 6px;
      padding: 6px 12px; border-radius: 999px;
      text-decoration: none; font-size: 13px; font-weight: 600;
      transition: transform 0.1s;
    }}
    .toc-item:hover {{ transform: scale(1.05); }}
    .toc-critical {{ background: #fee2e2; color: var(--critical); }}
    .toc-high {{ background: #fef3c7; color: var(--high); }}
    .toc-medium {{ background: #fef9c3; color: var(--medium); }}
    .toc-low {{ background: #dbeafe; color: var(--low); }}
    .toc-info {{ background: #f3f4f6; color: var(--info); }}
    .toc-count {{ font-weight: 700; }}

    /* Executive sections */
    .exec {{
      margin-bottom: 20px; padding: 20px 24px; border-radius: 12px;
      background: var(--card-bg); border: 1px solid var(--border);
    }}
    .ai-exec {{ border-color: #93c5fd; background: #f8fbff; position: relative; }}
    .ai-unavailable {{ opacity: 0.7; }}
    .ai-label {{
      position: absolute; top: 12px; right: 16px;
      display: flex; align-items: center; gap: 4px;
      padding: 4px 10px; border-radius: 999px;
      background: #dbeafe; color: #1d4ed8;
      font-size: 11px; font-weight: 600;
    }}
    .ai-icon {{ font-size: 12px; }}
    .exec h2 {{ margin-top: 0; }}

    /* Risk display */
    .risk-label {{ font-size: 1.5rem; font-weight: 700; }}
    .risk-bar {{
      height: 14px; border-radius: 999px; background: #e5e7eb;
      overflow: hidden; margin: 12px 0;
    }}
    .risk-bar > span {{
      display: block; height: 100%;
      background: linear-gradient(90deg, var(--success), #eab308, #ef4444);
    }}
    .headline {{ font-size: 1rem; color: #374151; }}
    .priorities li {{ margin-bottom: 12px; }}
    .muted {{ color: #6b7280; font-size: 13px; }}

    /* Meta info */
    .meta {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 8px 16px; margin-bottom: 20px; padding: 16px;
      border-radius: 10px; background: var(--card-bg);
      border: 1px solid var(--border); font-size: 13px;
    }}
    .meta div {{ display: flex; gap: 8px; }}
    .meta strong {{ color: #6b7280; min-width: 100px; }}

    /* Callouts */
    .callout {{
      display: flex; gap: 12px; padding: 14px 16px;
      border-radius: 8px; margin-bottom: 16px;
    }}
    .callout-info {{ background: #f0fdf4; border-left: 4px solid var(--success); }}
    .callout-warning {{ background: #fef9c3; border-left: 4px solid #eab308; }}
    .callout-icon {{ font-size: 20px; }}
    .callout-content h4 {{ margin: 0 0 8px; font-size: 14px; }}
    .callout-content ul {{ margin: 0; padding-left: 20px; }}

    /* Sections */
    section {{ margin-bottom: 28px; scroll-margin-top: 20px; }}
    section h2 {{
      padding: 12px 16px; border-radius: 8px;
      color: white; margin-bottom: 16px;
    }}
    .sev-hint {{
      display: block; font-size: 12px; font-weight: 400;
      opacity: 0.85; margin-top: 4px;
    }}
    .sev-critical {{ background: var(--critical); }}
    .sev-high {{ background: var(--high); }}
    .sev-medium {{ background: var(--medium); }}
    .sev-low {{ background: var(--low); }}
    .sev-info {{ background: var(--info); }}

    /* Empty state */
    .empty-state {{
      display: flex; align-items: center; gap: 10px;
      padding: 16px 20px; border-radius: 8px;
      background: #f0fdf4; color: #166534;
      border-left: 4px solid var(--success);
    }}
    .checkmark {{ font-size: 20px; color: var(--success); }}

    /* Finding cards */
    .finding {{
      background: var(--card-bg); border: 1px solid var(--border);
      border-left-width: 5px; border-radius: 10px;
      padding: 16px 20px; margin-bottom: 16px;
    }}
    .finding-head {{
      display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
      margin-bottom: 12px;
    }}
    .finding-head h3 {{ margin: 0; flex: 1 1 auto; font-size: 1.1rem; }}
    .finding p {{ margin: 8px 0; }}
    .location {{ font-size: 13px; color: #4b5563; }}

    /* URL list for collapsed findings */
    .affected-urls {{ margin: 12px 0; }}
    .url-list {{
      list-style: none; padding: 0; margin: 8px 0;
      display: flex; flex-direction: column; gap: 4px;
    }}
    .url-list li {{ font-size: 12px; }}
    .url-list code {{ background: #f8fafc; }}
    .evidence-varies {{ font-size: 12px; color: #6b7280; margin-top: 8px; }}

    .plain {{
      background: #f8fafc; border-radius: 8px; padding: 12px 14px;
      border-left: 3px solid #cbd5e1;
    }}
    .fix {{ color: #065f46; background: #ecfdf5; padding: 10px 14px; border-radius: 6px; }}
    .verify {{ font-size: 13px; color: #4b5563; }}
    .config-fix {{
      margin-top: 12px; padding: 14px; border-radius: 8px;
      background: #f0fdf4; border: 1px solid #bbf7d0;
    }}
    .snippet {{ margin-top: 10px; }}
    .snippet pre {{
      margin: 6px 0 0; padding: 12px; background: var(--header-bg);
      color: #e2e8f0; border-radius: 6px; overflow-x: auto; font-size: 12px;
    }}
    .score {{ font-size: 12px; color: #6b7280; white-space: nowrap; }}

    /* Badges */
    .badge {{
      font-size: 11px; font-weight: 700; padding: 4px 10px;
      border-radius: 999px; color: #fff; text-transform: uppercase;
      letter-spacing: .03em; white-space: nowrap;
    }}
    .badge-critical {{ background: var(--critical); }}
    .badge-high {{ background: var(--high); }}
    .badge-medium {{ background: var(--medium); }}
    .badge-low {{ background: var(--low); }}
    .badge-info {{ background: var(--info); }}
    .badge-fp {{ background: #9ca3af; }}
    .badge-instance {{ background: #6366f1; }}
    .badge-confirmed {{ background: var(--success); }}
    .badge-unconfirmed {{ background: #9ca3af; }}
    .badge-effort {{ background: #7c3aed; }}

    /* Severity borders */
    .sev-border-critical {{ border-left-color: var(--critical); }}
    .sev-border-high {{ border-left-color: var(--high); }}
    .sev-border-medium {{ border-left-color: var(--medium); }}
    .sev-border-low {{ border-left-color: var(--low); }}
    .sev-border-info {{ border-left-color: #9ca3af; }}

    /* Technical details */
    details.tech {{ margin-top: 12px; }}
    details.tech summary {{
      cursor: pointer; font-size: 13px; color: #2563eb;
      font-weight: 500;
    }}
    .tech-table {{
      width: 100%; border-collapse: collapse; margin-top: 10px;
      font-size: 12px;
    }}
    .tech-table th, .tech-table td {{
      border: 1px solid var(--border); padding: 8px 10px;
      text-align: left; vertical-align: top;
    }}
    .tech-table th {{
      background: #f8fafc; width: 160px; white-space: nowrap;
      font-weight: 600; color: #64748b;
    }}
    .tech-table td {{ word-break: break-word; }}
  </style>
</head>
<body>
  <header class="brand">
    {logo_markup}
    <div>
      <h1>{esc(branding.brand_name)} Report</h1>
      <p class="tagline">{esc(branding.tagline)}</p>
    </div>
  </header>

  {toc_block}
  {ai_block}
  {roadmap_block}

  <div class="exec">
    <h2>Executive Summary</h2>
    <p class="risk-label sev-{_risk_severity(exec_summary['overall_risk_score'])}">
      {esc(exec_summary['risk_label'])} &mdash; {esc(exec_summary['overall_risk_score'])} / 10
    </p>
    <div class="risk-bar"><span style="width: {risk_pct:.0f}%;"></span></div>
    <p class="headline">{esc(exec_summary['headline'])}</p>
    <p class="muted">{esc(exec_summary['risk_sentence'])}</p>
    {priorities_block}
  </div>

  {notes_block}
  {truncation_block}

  <div class="meta">
    <div><strong>Scan ID:</strong> <code>{html.escape(report["scan_id"])}</code></div>
    <div><strong>Target:</strong> <code>{html.escape(report["target"])}</code></div>
    <div><strong>Status:</strong> {html.escape(report["status"])}</div>
    <div><strong>Generated:</strong> {html.escape(report["generated_at"])}</div>
    <div><strong>Total Findings:</strong> {report["findings_count"]}</div>
    <div><strong>Risk Score:</strong> {report["severity_scores"].get("overall_risk_score", 0.0)}/10</div>
    <div><strong>False Positives:</strong> {report["severity_scores"].get("likely_false_positives", 0)}</div>
    <div><strong>AI Copilot:</strong> {esc(ai["status"])}</div>
  </div>

  {_coverage_html(report)}

  {"".join(sections)}
</body>
</html>
"""


def run_reporting(state: ScanState) -> dict[str, Any]:
    """Assemble final reports and write JSON/MD/HTML artifacts to disk."""
    settings = get_settings()
    all_findings = [dict(f) for f in state.get("findings", [])]
    # Deduplicate first so truncation cannot hide unique finding types behind
    # many repeats of the same (type, tool) pair.
    deduplicated_groups = _deduplicate_findings(all_findings)
    rendered_groups, group_truncation = _truncate_deduplicated_groups(
        deduplicated_groups,
        settings.report_max_findings,
    )
    # Expand rendered groups back into per-URL rows for the non-collapsed view,
    # then apply the same severity-first cap.
    expanded_from_groups: list[dict[str, Any]] = []
    for group in rendered_groups:
        urls = group.get("affected_urls") or [group.get("url") or ""]
        evidence_by_url = group.get("url_evidence") or {}
        for url in urls:
            row = {
                k: v
                for k, v in group.items()
                if k
                not in {
                    "affected_urls",
                    "url_evidence",
                    "instance_count",
                    "is_collapsed",
                    "urls_truncated",
                }
            }
            row["url"] = url
            if url in evidence_by_url:
                row["evidence"] = evidence_by_url[url]
            expanded_from_groups.append(row)
    rendered_findings, instance_truncation = _truncate_findings(
        expanded_from_groups,
        settings.report_max_findings,
    )
    # Group findings by severity (original - one entry per finding)
    findings_by_severity = _group_findings_by_severity(rendered_findings)
    # Group findings with deduplication (collapsed by type+tool)
    findings_by_severity_deduplicated = _group_findings_by_severity_from_groups(
        rendered_groups
    )
    generated_at = datetime.now(timezone.utc).isoformat()
    summary = _user_summary(state, len(all_findings))
    ai_synthesis = state.get("ai_synthesis") or {}
    branding = resolve_report_branding(state.get("org_id"))

    report = {
        "scan_id": state["scan_id"],
        "target": state["target"],
        "org_id": state.get("org_id"),
        "status": state.get("status", "unknown"),
        "human_approved": state.get("human_approved", False),
        "findings_count": len(all_findings),
        "unique_finding_groups": len(deduplicated_groups),
        "severity_scores": state.get("severity_scores", {}),
        "findings_by_severity": findings_by_severity,
        "findings_by_severity_deduplicated": findings_by_severity_deduplicated,
        "generated_at": generated_at,
        "summary": summary,
        "ai_synthesis": ai_synthesis,
        "branding": {
            "brand_name": branding.brand_name,
            "tagline": branding.tagline,
            "white_label": branding.white_label,
        },
        "_branding": branding,
    }
    report["coverage"] = build_coverage_section(report)

    if state.get("error"):
        report["error"] = state["error"]

    truncation: dict[str, Any] = {}
    if group_truncation:
        truncation["groups"] = group_truncation
    if instance_truncation:
        truncation["instances"] = instance_truncation
    if truncation:
        truncation["truncated"] = True
        truncation["total_findings"] = len(all_findings)
        truncation["rendered_findings"] = sum(
            len(items) for items in findings_by_severity.values()
        )
        truncation["message"] = (
            (group_truncation or instance_truncation or {}).get("message")
            or "Report findings were truncated for readability."
        )
        report["truncation"] = truncation

    outcome = state.get("status")
    rejected = (
        outcome == "rejected"
        or (
            state.get("human_approval_needed")
            and state.get("human_approved") is False
            and outcome not in ("failed",)
        )
    )
    if rejected:
        report["outcome"] = "rejected"
    elif outcome == "failed":
        report["outcome"] = "failed"
    elif len(all_findings) == 0:
        report["outcome"] = "clean"
    else:
        report["outcome"] = "completed"

    scan_report_dir = _REPORTS_ROOT / state["scan_id"]
    scan_report_dir.mkdir(parents=True, exist_ok=True)

    json_path = scan_report_dir / "report.json"
    md_path = scan_report_dir / "report.md"
    html_path = scan_report_dir / "report.html"
    pdf_path = scan_report_dir / "report.pdf"

    markdown_report = _build_markdown_report(report)
    html_report = _build_html_report(report)

    # Internal branding object is not JSON-serializable; strip before write.
    serializable = {k: v for k, v in report.items() if k != "_branding"}

    json_path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
    md_path.write_text(markdown_report, encoding="utf-8")
    html_path.write_text(html_report, encoding="utf-8")
    _write_pdf_report(report, pdf_path)

    report["artifacts"] = {
        "json": str(json_path),
        "md": str(md_path),
        "html": str(html_path),
        "pdf": str(pdf_path),
    }
    report.pop("_branding", None)

    final_status = "completed" if outcome != "failed" else "failed"
    return {"report": report, "status": final_status}
