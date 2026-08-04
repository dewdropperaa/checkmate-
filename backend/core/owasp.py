"""OWASP Top 10 (2021) mapping for scan findings and coverage honesty.

This is not a fake "OWASP checker" — it labels what real tools already test
(nuclei DAST, ZAP ascan, sqlmap, headers, testssl, retire.js) so reports
show which Top 10 categories were exercised.
"""

from __future__ import annotations

from typing import Any

# Categories we can reasonably exercise with current modules.
OWASP_TOP_10_2021: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}

# What each tool is expected to contribute when it runs successfully.
TOOL_OWASP_COVERAGE: dict[str, list[str]] = {
    "nuclei": ["A01:2021", "A03:2021", "A05:2021", "A06:2021", "A10:2021"],
    "testssl": ["A02:2021"],
    "header-checks": ["A01:2021", "A02:2021", "A03:2021", "A05:2021"],
    "retirejs": ["A06:2021", "A08:2021"],
    "zap": ["A01:2021", "A03:2021", "A05:2021", "A07:2021", "A10:2021"],
    "sqlmap": ["A03:2021"],
}

# Finding type / nuclei tag → OWASP id (first match wins).
_TYPE_TO_OWASP: list[tuple[tuple[str, ...], str]] = [
    (("sqli", "sql-injection", "sql_injection", "nosqli"), "A03:2021"),
    (("xss", "cross-site-scripting", "reflected-xss", "stored-xss"), "A03:2021"),
    (("ssti", "rce", "command-injection", "code-injection", "lfi", "rfi", "xxe"), "A03:2021"),
    (("ssrf",), "A10:2021"),
    (("csrf", "idor", "path-traversal", "directory-traversal", "open-redirect", "redirect"), "A01:2021"),
    (("tls", "ssl", "heartbleed", "poodle", "weak-cipher", "certificate", "hsts", "missing-hsts", "weak-hsts"), "A02:2021"),
    (
        (
            "missing-csp",
            "weak-csp",
            "csp-unsafe-inline",
            "csp-unsafe-eval",
            "csp-overly-permissive",
            "missing-xfo",
            "x-frame-options",
            "cors",
            "misconfig",
            "exposed",
            "default-login",
        ),
        "A05:2021",
    ),
    (("retire", "cve-", "outdated", "vulnerable-js"), "A06:2021"),
    (("auth", "session", "jwt", "password", "login"), "A07:2021"),
]

# Categories that automated scanners cannot meaningfully cover alone.
OWASP_NOT_AUTOMATABLE = ("A04:2021", "A09:2021")


def classify_finding_owasp(
    *,
    finding_type: str,
    tool: str,
    tags: list[str] | None = None,
    cwe_id: int | None = None,
) -> str | None:
    """Return an OWASP Top 10 2021 id for a finding, if classifiable."""
    haystack = " ".join(
        [
            (finding_type or "").lower(),
            " ".join(t.lower() for t in (tags or [])),
            tool.lower(),
        ]
    )
    for needles, owasp_id in _TYPE_TO_OWASP:
        if any(n in haystack for n in needles):
            return owasp_id

    # CWE fallbacks for common injection / SSRF families.
    if cwe_id in {79, 89, 74, 78, 94, 95, 91, 643, 917}:
        return "A03:2021"
    if cwe_id == 918:
        return "A10:2021"
    if cwe_id in {22, 352, 601, 639}:
        return "A01:2021"
    if cwe_id in {295, 310, 319, 326, 327}:
        return "A02:2021"

    # Tool-level fallback when type is opaque (e.g. nuclei template ids).
    tool_cats = TOOL_OWASP_COVERAGE.get(tool.replace(".js", "").replace("retire.js", "retirejs"))
    if tool == "retire.js" or tool == "retirejs":
        return "A06:2021"
    if tool == "sqlmap":
        return "A03:2021"
    if tool == "testssl":
        return "A02:2021"
    if tool_cats and len(tool_cats) == 1:
        return tool_cats[0]
    return None


def coverage_for_modules(modules_run: list[str]) -> dict[str, Any]:
    """Summarize which OWASP categories were exercised by successful modules."""
    covered: set[str] = set()
    for module in modules_run:
        key = module.replace("retire.js", "retirejs")
        covered.update(TOOL_OWASP_COVERAGE.get(key, []))
    return {
        "standard": "OWASP Top 10:2021",
        "categories_covered": sorted(covered),
        "categories_not_covered": sorted(
            set(OWASP_TOP_10_2021) - covered
        ),
        "not_automatable": list(OWASP_NOT_AUTOMATABLE),
        "labels": {k: OWASP_TOP_10_2021[k] for k in sorted(covered)},
        "note": (
            "Injection (XSS/SQLi) deep testing requires approved ZAP and/or sqlmap. "
            "Nuclei DAST adds template-based XSS/SQLi/SSRF checks on the passive path. "
            "A04 (Insecure Design) and A09 (Logging) are not fully automatable."
        ),
    }
