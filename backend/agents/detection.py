"""Vulnerability detection agent - LangGraph node for running detection tools.

This agent orchestrates passive and active security scanning tools:

Passive tools (run automatically after recon):
- nuclei: Template-based scanner with -dast (XSS/SQLi/SSRF + CVE/misconfig)
- testssl.sh: TLS/SSL configuration checker
- retire.js: JavaScript dependency CVE scanner
- header-checks: HTTP security header analyzer

Active tools (require per-tool human approval — needed for deep injection):
- zap: OWASP ZAP active scanner (XSS, SQLi, and more; AJAX spider enabled)
- sqlmap: SQL injection scanner (level/risk 2 when approved)

Each active tool only runs if it's individually present in
ScanState.approved_tools; a reviewer may approve sqlmap while rejecting zap
(or vice versa). See `_resolve_active_tool_selection` for the resolution
logic and its legacy `human_approved` fallback.

All findings are normalized to a common schema and deduplicated
before being written to ScanState.findings.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from agents.state import ScanState
from core.logging import log_scan_event
from core.toolchain import run_tool_safely
from tools.base import ToolResult
from tools.header_checks import HeaderChecker
from tools.nuclei_tool import NucleiTool
from tools.retirejs_tool import RetireJSTool
from tools.schemas import Finding, Severity, deduplicate_findings
from tools.sqlmap_tool import SQLMapTool, find_injectable_urls
from tools.testssl_tool import TestSSLTool
from tools.zap_tool import (
    EVENT_ZAP_SKIPPED_UNAVAILABLE,
    ZAP_UNAVAILABLE_COVERAGE_NOTE,
    ZAPTool,
    is_zap_unavailable_error,
)

logger = logging.getLogger(__name__)

# Fallback set of active tools for states that predate per-tool planning
# (e.g. hand-built ScanState dicts in tests/older callers that never set
# `planned_active_tests`).
_DEFAULT_ACTIVE_TOOLS = ("zap", "sqlmap")


def _resolve_active_tool_selection(state: ScanState) -> tuple[list[str], list[str]]:
    """Determine which planned active tools a human reviewer approved.

    Returns `(approved_tools, rejected_tools)`, both ordered the same as
    `planned_active_tests`. When a state predates per-tool gating (no
    `approved_tools` key at all), this falls back to the legacy all-or-nothing
    `human_approved` flag so older callers keep working unchanged.
    """
    planned = list(state.get("planned_active_tests") or _DEFAULT_ACTIVE_TOOLS)
    approved_tools = state.get("approved_tools")
    if approved_tools is None:
        approved_tools = planned if state.get("human_approved", False) else []
    approved_set = set(approved_tools)
    approved = [tool for tool in planned if tool in approved_set]
    rejected = [tool for tool in planned if tool not in approved_set]
    return approved, rejected


def _extract_findings_from_result(result: ToolResult) -> list[Finding]:
    """Extract Finding objects from a ToolResult.

    Findings are kept even when ``success`` is False so a partial tool run
    (nonzero exit after emitting some alerts) still contributes evidence while
    the failure is recorded separately for honest coverage scoring.
    """
    findings: list[Finding] = []

    if not result.data:
        return findings

    findings_data = result.data.get("findings", [])
    for fd in findings_data:
        try:
            if isinstance(fd, Finding):
                findings.append(fd)
            elif isinstance(fd, dict):
                findings.append(Finding(**fd))
        except Exception as e:
            logger.warning(f"Failed to parse finding: {e}")
            continue

    return findings


async def run_passive_tools(state: ScanState) -> tuple[list[Finding], dict[str, str]]:
    """
    Run all passive detection tools.

    Passive tools are safe to run automatically without human approval.
    They include:
    - nuclei: against recon-discovered hosts/URLs
    - testssl.sh: against HTTPS hosts
    - retire.js: against discovered JS files
    - header-checks: against discovered URLs

    Args:
        state: Current scan state with recon_results

    Returns:
        Tuple of (list of findings, dict of errors by tool name)
    """
    target = state["target"]
    recon_results = state.get("recon_results", {})

    hosts = recon_results.get("hosts", [target])
    urls = recon_results.get("urls", [])
    js_files = recon_results.get("js_files", [])

    if not hosts:
        hosts = [target]

    def ensure_https_url(url_or_host: str) -> str:
        """Ensure a URL has https:// scheme, handling already-prefixed URLs."""
        if url_or_host.startswith(("http://", "https://")):
            return url_or_host
        return f"https://{url_or_host}"

    scan_urls = urls if urls else [ensure_https_url(target)]

    https_hosts = []
    for host in hosts:
        if isinstance(host, dict):
            host_url = host.get("url", host.get("host", ""))
        else:
            host_url = str(host)

        if not host_url:
            continue

        parsed = urlparse(host_url)
        if parsed.scheme == "https":
            https_hosts.append(host_url)
        elif not parsed.scheme:
            https_hosts.append(f"https://{host_url}")

    if not https_hosts:
        https_hosts = [ensure_https_url(target)]

    nuclei = NucleiTool()
    testssl = TestSSLTool()
    retirejs = RetireJSTool()
    header_checker = HeaderChecker()

    tasks = []

    # DAST enables XSS/SQLi/SSRF fuzzing templates (OWASP A03/A10). Full
    # community set stays on unless NUCLEI_TEMPLATE_TAGS narrows it.
    nuclei_scope: dict[str, Any] = {"dast": True}
    tasks.append(run_tool_safely(
        "nuclei",
        lambda: nuclei.run_batch(scan_urls[:50], nuclei_scope),
    ))

    if https_hosts:
        tasks.append(run_tool_safely(
            "testssl",
            lambda: testssl.run(https_hosts[0], {}),
        ))

    if js_files:
        tasks.append(run_tool_safely(
            "retirejs",
            lambda: retirejs.run_batch(js_files[:20], {}),
        ))
    else:
        logger.info("retirejs: not applicable (no JavaScript files discovered)")

    check_urls = scan_urls[:10] if scan_urls else [ensure_https_url(target)]
    tasks.append(run_tool_safely(
        "header-checks",
        lambda: header_checker.run_batch(check_urls, {}),
    ))

    logger.info(f"Running {len(tasks)} passive detection tools")

    results = await asyncio.gather(*tasks, return_exceptions=False)

    await header_checker.close()

    all_findings: list[Finding] = []
    errors: dict[str, str] = {}

    for tool_name, result, error in results:
        if error:
            errors[tool_name] = error
            logger.warning(f"Passive tool {tool_name} failed: {error}")
            continue

        if result is None:
            errors[tool_name] = "No result returned"
            continue

        if not result.success:
            errors[tool_name] = (
                result.error
                or f"{tool_name} failed (exit_code={result.exit_code})"
            )
            logger.warning(f"Passive tool {tool_name} failed: {errors[tool_name]}")

        findings = _extract_findings_from_result(result)
        all_findings.extend(findings)
        logger.info(f"{tool_name}: found {len(findings)} findings")

    return all_findings, errors


async def run_active_tools(
    state: ScanState,
) -> tuple[list[Finding], dict[str, str], dict[str, Any], list[str]]:
    """
    Run active detection tools that the human reviewer approved.

    Active tools perform intrusive testing and only run per-tool once a
    human reviewer approves them individually (e.g. approve sqlmap while
    rejecting zap). See `_resolve_active_tool_selection`.

    Returns:
        Tuple of (findings, errors_by_tool, auth_scan_meta, coverage_notes)
    """
    from core.auth_scan import load_runtime_auth
    from core.destructive_actions import (
        filter_excluded_urls,
        is_destructive_form,
        path_matches_exclusion,
    )

    target = state["target"]
    recon_results = state.get("recon_results", {})
    approved_tools, rejected_tools = _resolve_active_tool_selection(state)
    approved = set(approved_tools)

    if rejected_tools:
        logger.info(f"Active tools rejected by reviewer, skipping: {rejected_tools}")

    excluded = list(
        (state.get("auth_scan") or {}).get("excluded_paths")
        or recon_results.get("excluded_paths")
        or (state.get("scope") or {}).get("excluded_paths")
        or []
    )

    # Decrypt credentials only here — never put them on ScanState.
    runtime = load_runtime_auth(
        org_id=state.get("org_id"),
        site_id=state.get("site_id"),
        target=target,
        extra_excluded=excluded,
    )
    excluded = list(runtime.meta.excluded_paths or excluded)
    auth_scan_meta = runtime.meta.to_state_dict()

    zap = ZAPTool()
    sqlmap = SQLMapTool()

    tasks = []
    coverage_notes: list[str] = []

    target_url = f"https://{target}" if not target.startswith("http") else target
    if "zap" in approved:
        # Probe once before enqueueing — fail this scan's active stage gracefully
        # during rolling deploys instead of hanging the whole pipeline.
        zap_ready, zap_ready_err = await zap.probe_ready()
        if not zap_ready:
            msg = zap_ready_err or "ZAP unreachable"
            logger.warning("ZAP unavailable before active scan: %s", msg)
            log_scan_event(
                str(state.get("scan_id") or "unknown"),
                EVENT_ZAP_SKIPPED_UNAVAILABLE,
                error=msg,
                target=target,
            )
            coverage_notes.append(ZAP_UNAVAILABLE_COVERAGE_NOTE)
            # Record as a tool error so scoring marks zap failed without crashing.
            # sqlmap (if approved) can still run below.
            errors_pre: dict[str, str] = {"zap": msg}
        else:
            errors_pre = {}
            zap_scope: dict[str, Any] = {
                "excluded_paths": excluded,
                "scan_id": state.get("scan_id"),
                # AJAX spider improves SPA coverage before active XSS/SQLi tests.
                "ajax_spider": True,
            }
            if runtime.meta.enabled and runtime.credentials is not None:
                # Ephemeral auth dict for this tool call only — not persisted.
                zap_scope["auth"] = {
                    "login_url": runtime.meta.login_url,
                    "username": runtime.credentials.username,
                    "password": runtime.credentials.password,
                    "username_field": runtime.username_field,
                    "password_field": runtime.password_field,
                    "context_name": "checkmate-auth",
                    "excluded_paths": excluded,
                }

            async def _run_zap() -> ToolResult:
                result = await zap.run(target_url, zap_scope)
                zap_scope.pop("auth", None)
                return result

            tasks.append(run_tool_safely("zap", _run_zap))
    else:
        errors_pre = {}

    if "sqlmap" in approved:
        injectable_urls = find_injectable_urls(recon_results)
        injectable_urls = filter_excluded_urls(injectable_urls, excluded)
        injectable_urls = [
            u
            for u in injectable_urls
            if not is_destructive_form(action=u)
            and not path_matches_exclusion(u, excluded)
        ]
        if injectable_urls:
            logger.info(f"Found {len(injectable_urls)} URLs for SQLMap testing")
            tasks.append(run_tool_safely(
                "sqlmap",
                # Cap is MAX_LEVEL/MAX_RISK=2 — use full allowed depth for SQLi.
                lambda: sqlmap.run_batch(injectable_urls[:10], {"level": 2, "risk": 2}),
            ))
        else:
            logger.info("sqlmap: not applicable (no parameterized URLs discovered)")
            coverage_notes.append(
                "sqlmap: not applicable (no parameterized URLs discovered)"
            )

    logger.info(f"Running {len(tasks)} active detection tools (approved: {sorted(approved)})")

    results = await asyncio.gather(*tasks, return_exceptions=False) if tasks else []

    await zap.close()
    runtime.credentials = None

    all_findings: list[Finding] = []
    errors: dict[str, str] = dict(errors_pre)

    for tool_name, result, error in results:
        if error:
            errors[tool_name] = error
            logger.warning(f"Active tool {tool_name} failed: {error}")
            if tool_name == "zap" and is_zap_unavailable_error(error):
                if ZAP_UNAVAILABLE_COVERAGE_NOTE not in coverage_notes:
                    coverage_notes.append(ZAP_UNAVAILABLE_COVERAGE_NOTE)
            continue

        if result is None:
            errors[tool_name] = "No result returned"
            continue

        if tool_name == "zap" and result.data and isinstance(result.data, dict):
            note = result.data.get("coverage_note")
            if note and note not in coverage_notes:
                coverage_notes.append(str(note))
            if isinstance(result.data.get("auth"), dict):
                login_ok = result.data["auth"].get("login_succeeded")
                auth_scan_meta["login_succeeded"] = login_ok
                if runtime.meta.enabled and login_ok is False:
                    warnings = list(auth_scan_meta.get("warnings") or [])
                    warnings.append(
                        "Login failed; scan proceeded as an unauthenticated visitor."
                    )
                    auth_scan_meta["warnings"] = warnings
                    auth_scan_meta["fallback_reason"] = "login_failed"

        if not result.success:
            err = result.error or f"{tool_name} failed (exit_code={result.exit_code})"
            errors[tool_name] = err
            if tool_name == "zap" and is_zap_unavailable_error(err):
                if ZAP_UNAVAILABLE_COVERAGE_NOTE not in coverage_notes:
                    coverage_notes.append(ZAP_UNAVAILABLE_COVERAGE_NOTE)
            logger.warning(f"Active tool {tool_name} failed: {err}")

        findings = _extract_findings_from_result(result)
        findings = [
            f
            for f in findings
            if not path_matches_exclusion(f.url or "", excluded)
        ]
        all_findings.extend(findings)
        logger.info(f"{tool_name}: found {len(findings)} findings")

    return all_findings, errors, auth_scan_meta, coverage_notes


async def run_passive_detection_async(state: ScanState) -> dict[str, Any]:
    """Run passive detection tools and merge findings into scan state."""
    target = state["target"]
    logger.info(f"Starting passive detection for target: {target}")

    passive_findings, passive_errors = await run_passive_tools(state)
    deduplicated = deduplicate_findings(passive_findings)

    modules_na: list[str] = []
    recon_results = state.get("recon_results", {})
    if not recon_results.get("js_files"):
        modules_na.append("retirejs")

    existing_findings = state.get("findings", [])
    existing_keys = {
        (ef.get("url", ""), ef.get("type", "")) for ef in existing_findings
    }
    new_findings = [
        finding.model_dump_for_state()
        for finding in deduplicated
        if finding.dedup_key() not in existing_keys
    ]

    prior_meta = dict(state.get("detection_metadata") or {})
    prior_errors = dict(prior_meta.get("errors") or {})
    prior_errors.update(passive_errors)

    return {
        "findings": existing_findings + new_findings,
        "status": "detecting",
        "detection_metadata": {
            **prior_meta,
            "passive_count": len(passive_findings),
            "passive_deduplicated_count": len(deduplicated),
            "passive_new_findings_count": len(new_findings),
            "errors": prior_errors or None,
            "passive_tools_run": True,
            "modules_not_applicable": modules_na or None,
        },
    }


async def run_active_detection_async(state: ScanState) -> dict[str, Any]:
    """Run whichever active detection tools the human reviewer approved."""
    approved_tools, rejected_tools = _resolve_active_tool_selection(state)
    if not approved_tools:
        logger.info("Active tools skipped - no tools approved by reviewer")
        prior_meta = dict(state.get("detection_metadata") or {})
        return {
            "status": "detecting",
            "detection_metadata": {
                **prior_meta,
                "active_count": 0,
                "active_tools_run": False,
                "approved_tools": [],
                "rejected_tools": rejected_tools,
            },
        }

    target = state["target"]
    logger.info(
        f"Starting active detection for target: {target} "
        f"(approved tools: {approved_tools}, rejected: {rejected_tools})"
    )

    active_findings, active_errors, auth_scan_meta, coverage_notes = await run_active_tools(
        state
    )
    all_findings = list(state.get("findings", [])) + [
        f.model_dump_for_state() for f in active_findings
    ]
    deduplicated = deduplicate_findings([
        Finding(**f) if isinstance(f, dict) else f for f in all_findings
    ])

    existing_keys: set[tuple[str, str]] = set()
    merged: list[dict[str, Any]] = []
    for finding in deduplicated:
        key = finding.dedup_key()
        if key not in existing_keys:
            existing_keys.add(key)
            merged.append(finding.model_dump_for_state())

    prior_meta = dict(state.get("detection_metadata") or {})
    prior_errors = dict(prior_meta.get("errors") or {})
    prior_errors.update({f"active_{k}": v for k, v in active_errors.items()})
    prior_notes = list(prior_meta.get("coverage_notes") or [])
    for note in coverage_notes:
        if note not in prior_notes:
            prior_notes.append(note)

    modules_na = list(prior_meta.get("modules_not_applicable") or [])
    if (
        "sqlmap" in approved_tools
        and "sqlmap" not in active_errors
        and any("not applicable" in n.lower() and "sqlmap" in n.lower() for n in prior_notes)
    ):
        if "sqlmap" not in modules_na:
            modules_na.append("sqlmap")

    tools_executed = [
        tool
        for tool in approved_tools
        if tool not in active_errors and tool not in modules_na
    ]

    return {
        "findings": merged,
        "status": "detecting",
        "auth_scan": auth_scan_meta,
        "detection_metadata": {
            **prior_meta,
            "active_count": len(active_findings),
            "deduplicated_count": len(deduplicated),
            "errors": prior_errors or None,
            "coverage_notes": prior_notes or None,
            "active_tools_run": bool(tools_executed),
            "active_tools_executed": tools_executed,
            "approved_tools": approved_tools,
            "rejected_tools": rejected_tools,
            "modules_not_applicable": modules_na or None,
        },
    }


async def run_detection_async(state: ScanState) -> dict[str, Any]:
    """
    Execute detection tools and collect findings.

    This is the async implementation that:
    1. Always runs passive tools
    2. Runs active tools only if human_approved is True
    3. Deduplicates findings from all tools
    4. Returns findings to merge into ScanState

    Args:
        state: Current scan state

    Returns:
        Dict with findings and status to merge into ScanState
    """
    target = state["target"]
    approved_tools, rejected_tools = _resolve_active_tool_selection(state)

    logger.info(f"Starting detection for target: {target}")
    logger.info(f"Approved tools: {approved_tools}, rejected tools: {rejected_tools}")

    all_findings: list[Finding] = []
    all_errors: dict[str, str] = {}

    passive_findings, passive_errors = await run_passive_tools(state)
    all_findings.extend(passive_findings)
    all_errors.update(passive_errors)

    logger.info(f"Passive tools completed: {len(passive_findings)} findings")

    if approved_tools:
        logger.info(f"Running approved active tools: {approved_tools}")
        active_findings, active_errors, auth_scan_meta, coverage_notes = (
            await run_active_tools(state)
        )
        all_findings.extend(active_findings)
        all_errors.update({f"active_{k}": v for k, v in active_errors.items()})

        logger.info(f"Active tools completed: {len(active_findings)} findings")
    else:
        logger.info("Active tools skipped - no tools approved by reviewer")
        auth_scan_meta = dict(state.get("auth_scan") or {})
        coverage_notes = []

    deduplicated = deduplicate_findings(all_findings)
    logger.info(
        f"Detection complete: {len(all_findings)} total findings, "
        f"{len(deduplicated)} after deduplication"
    )

    existing_findings = state.get("findings", [])
    existing_keys = set()
    for ef in existing_findings:
        key = (ef.get("url", ""), ef.get("type", ""))
        existing_keys.add(key)

    new_findings = []
    for finding in deduplicated:
        if finding.dedup_key() not in existing_keys:
            new_findings.append(finding.model_dump_for_state())

    merged_findings = existing_findings + new_findings

    return {
        "findings": merged_findings,
        "status": "detecting",
        "auth_scan": auth_scan_meta,
        "detection_metadata": {
            "passive_count": len(passive_findings),
            "active_count": len(all_findings) - len(passive_findings) if approved_tools else 0,
            "deduplicated_count": len(deduplicated),
            "new_findings_count": len(new_findings),
            "errors": all_errors if all_errors else None,
            "coverage_notes": coverage_notes or None,
            "active_tools_run": bool(approved_tools),
            "approved_tools": approved_tools,
            "rejected_tools": rejected_tools,
        },
    }


def run_detection(state: ScanState) -> dict[str, Any]:
    """
    LangGraph node function for vulnerability detection.

    This is the synchronous entry point that LangGraph calls.
    It runs the async implementation using asyncio.

    Args:
        state: Current scan state

    Returns:
        Dict with findings to merge into ScanState
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        import nest_asyncio
        nest_asyncio.apply()
        return loop.run_until_complete(run_detection_async(state))
    else:
        return asyncio.run(run_detection_async(state))
