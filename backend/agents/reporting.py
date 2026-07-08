"""Report generation agent."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.state import ScanState

_REPORTS_ROOT = Path(__file__).resolve().parent.parent / "reports"
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

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
        grouped[severity].append(enriched)
    return grouped


def _build_markdown_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Sentinel Scan Report - {report['scan_id']}")
    lines.append("")
    lines.append(f"- **Target:** `{report['target']}`")
    lines.append(f"- **Status:** `{report['status']}`")
    lines.append(f"- **Generated At:** `{report['generated_at']}`")
    lines.append(f"- **Total Findings:** `{report['findings_count']}`")
    lines.append(f"- **Overall Risk Score (0-10):** `{report['severity_scores'].get('overall_risk_score', 0.0)}`")
    likely_fp = report["severity_scores"].get("likely_false_positives")
    if likely_fp:
        lines.append(f"- **Likely False Positives (deprioritized):** `{likely_fp}`")
    lines.append("")

    counts = report["severity_scores"].get("severity_counts", {})
    lines.append("## Severity Summary")
    lines.append("")
    for severity in _SEVERITY_ORDER:
        lines.append(f"- **{severity.title()}**: {counts.get(severity, 0)}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    findings_by_severity = report["findings_by_severity"]
    for severity in _SEVERITY_ORDER:
        severity_findings = findings_by_severity.get(severity, [])
        lines.append(f"### {severity.title()} ({len(severity_findings)})")
        lines.append("")
        if not severity_findings:
            lines.append("_No findings in this severity._")
            lines.append("")
            continue

        for finding in severity_findings:
            lines.append(
                f"- **{finding.get('type', 'unknown')}** on `{finding.get('url', 'n/a')}` "
                f"(tool: `{finding.get('tool', 'unknown')}`, score: `{finding.get('cvss_score', 'n/a')}`)"
            )
            lines.append(f"  - Description: {finding.get('description', 'No description provided')}")
            if finding.get("evidence"):
                lines.append(f"  - Evidence: {finding['evidence']}")
            verification = finding.get("verification") or {}
            v_status = verification.get("status")
            if v_status in ("confirmed", "unconfirmed", "unverified"):
                note = f"  - Verification: {v_status} (confidence: {finding.get('confidence', 1.0)})"
                if finding.get("likely_false_positive"):
                    note += " — likely false positive"
                lines.append(note)
            lines.append(f"  - Remediation: {finding['remediation']}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def _build_html_report(report: dict[str, Any]) -> str:
    counts = report["severity_scores"].get("severity_counts", {})

    def verification_label(finding: dict[str, Any]) -> str:
        verification = finding.get("verification") or {}
        status = verification.get("status") or "n/a"
        confidence = finding.get("confidence", 1.0)
        label = f"{status} ({confidence})"
        if finding.get("likely_false_positive"):
            label += " likely FP"
        return label

    def finding_row(finding: dict[str, Any]) -> str:
        return (
            "<tr>"
            f"<td>{html.escape(str(finding.get('type', 'unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('url', 'n/a')))}</td>"
            f"<td>{html.escape(str(finding.get('tool', 'unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('cvss_score', 'n/a')))}</td>"
            f"<td>{html.escape(verification_label(finding))}</td>"
            f"<td>{html.escape(str(finding.get('description', 'No description provided')))}</td>"
            f"<td>{html.escape(str(finding.get('remediation', '')))}</td>"
            "</tr>"
        )

    sections: list[str] = []
    for severity in _SEVERITY_ORDER:
        findings = report["findings_by_severity"].get(severity, [])
        rows = "".join(finding_row(f) for f in findings)
        if not rows:
            rows = (
                "<tr><td colspan='7' class='empty'>No findings in this severity.</td></tr>"
            )
        sections.append(
            f"""
            <section>
              <h2 class="sev-{severity}">{severity.title()} ({len(findings)})</h2>
              <table>
                <thead>
                  <tr>
                    <th>Type</th><th>URL</th><th>Tool</th><th>Score</th><th>Verification</th><th>Description</th><th>Remediation</th>
                  </tr>
                </thead>
                <tbody>{rows}</tbody>
              </table>
            </section>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sentinel Scan Report {html.escape(report["scan_id"])}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2937; background: #f9fafb; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .meta {{ margin-bottom: 20px; padding: 12px; border-radius: 8px; background: #ffffff; border: 1px solid #e5e7eb; }}
    .summary {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 10px 0 20px; }}
    .chip {{ padding: 6px 10px; border-radius: 999px; background: #eef2ff; font-size: 12px; border: 1px solid #c7d2fe; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 18px; background: #fff; border: 1px solid #e5e7eb; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: #f3f4f6; }}
    .sev-critical {{ color: #b91c1c; }}
    .sev-high {{ color: #b45309; }}
    .sev-medium {{ color: #854d0e; }}
    .sev-low {{ color: #1d4ed8; }}
    .sev-info {{ color: #374151; }}
    .empty {{ color: #6b7280; font-style: italic; }}
  </style>
</head>
<body>
  <h1>Sentinel Scan Report</h1>
  <div class="meta">
    <div><strong>Scan ID:</strong> {html.escape(report["scan_id"])}</div>
    <div><strong>Target:</strong> {html.escape(report["target"])}</div>
    <div><strong>Status:</strong> {html.escape(report["status"])}</div>
    <div><strong>Generated At:</strong> {html.escape(report["generated_at"])}</div>
    <div><strong>Total Findings:</strong> {report["findings_count"]}</div>
    <div><strong>Overall Risk Score (0-10):</strong> {report["severity_scores"].get("overall_risk_score", 0.0)}</div>
    <div><strong>Likely False Positives (deprioritized):</strong> {report["severity_scores"].get("likely_false_positives", 0)}</div>
  </div>
  <div class="summary">
    <span class="chip">Critical: {counts.get("critical", 0)}</span>
    <span class="chip">High: {counts.get("high", 0)}</span>
    <span class="chip">Medium: {counts.get("medium", 0)}</span>
    <span class="chip">Low: {counts.get("low", 0)}</span>
    <span class="chip">Info: {counts.get("info", 0)}</span>
  </div>
  {"".join(sections)}
</body>
</html>
"""


def run_reporting(state: ScanState) -> dict[str, Any]:
    """Assemble final reports and write JSON/MD/HTML artifacts to disk."""
    findings = [dict(f) for f in state.get("findings", [])]
    findings_by_severity = _group_findings_by_severity(findings)
    generated_at = datetime.now(timezone.utc).isoformat()

    report = {
        "scan_id": state["scan_id"],
        "target": state["target"],
        "status": state.get("status", "unknown"),
        "human_approved": state.get("human_approved", False),
        "findings_count": len(findings),
        "severity_scores": state.get("severity_scores", {}),
        "findings_by_severity": findings_by_severity,
        "generated_at": generated_at,
    }

    outcome = state.get("status")
    if outcome in ("rejected", "failed"):
        report["outcome"] = outcome

    scan_report_dir = _REPORTS_ROOT / state["scan_id"]
    scan_report_dir.mkdir(parents=True, exist_ok=True)

    json_path = scan_report_dir / "report.json"
    md_path = scan_report_dir / "report.md"
    html_path = scan_report_dir / "report.html"

    markdown_report = _build_markdown_report(report)
    html_report = _build_html_report(report)

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(markdown_report, encoding="utf-8")
    html_path.write_text(html_report, encoding="utf-8")

    report["artifacts"] = {
        "json": str(json_path),
        "md": str(md_path),
        "html": str(html_path),
    }

    return {"report": report, "status": "completed"}
