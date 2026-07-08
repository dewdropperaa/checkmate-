"""Vulnerability detection agent - LangGraph node for running detection tools.

This agent orchestrates passive and active security scanning tools:

Passive tools (run automatically after recon):
- nuclei: Template-based vulnerability scanner
- testssl.sh: TLS/SSL configuration checker
- retire.js: JavaScript dependency CVE scanner
- header-checks: HTTP security header analyzer

Active tools (require human_approved=True):
- zap: OWASP ZAP active scanner
- sqlmap: SQL injection scanner

All findings are normalized to a common schema and deduplicated
before being written to ScanState.findings.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from agents.state import ScanState
from tools.base import (
    BinaryValidationError,
    ScopeViolationError,
    ToolExecutionError,
    ToolResult,
)
from tools.header_checks import HeaderChecker
from tools.nuclei_tool import NucleiTool
from tools.retirejs_tool import RetireJSTool
from tools.schemas import Finding, Severity, deduplicate_findings
from tools.sqlmap_tool import SQLMapTool, find_injectable_urls
from tools.testssl_tool import TestSSLTool
from tools.zap_tool import ZAPTool

logger = logging.getLogger(__name__)


async def _run_tool_safely(
    tool_name: str,
    coro: Any,
) -> tuple[str, ToolResult | None, str | None]:
    """
    Run a tool coroutine with comprehensive error handling.

    Returns:
        Tuple of (tool_name, result_or_none, error_message_or_none)
    """
    try:
        result = await coro
        return (tool_name, result, None)
    except ScopeViolationError as e:
        logger.error(f"{tool_name}: Scope violation - {e}")
        return (tool_name, None, f"Scope violation: {e}")
    except BinaryValidationError as e:
        logger.error(f"{tool_name}: Binary validation failed - {e}")
        return (tool_name, None, f"Binary validation failed: {e}")
    except ToolExecutionError as e:
        logger.error(f"{tool_name}: Execution error - {e}")
        return (tool_name, None, f"Execution error: {e}")
    except asyncio.CancelledError:
        logger.warning(f"{tool_name}: Cancelled")
        return (tool_name, None, "Cancelled")
    except Exception as e:
        logger.exception(f"{tool_name}: Unexpected error - {e}")
        return (tool_name, None, f"Unexpected error: {type(e).__name__}: {e}")


def _extract_findings_from_result(result: ToolResult) -> list[Finding]:
    """Extract Finding objects from a ToolResult."""
    findings: list[Finding] = []

    if not result.success or not result.data:
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

    tasks.append(_run_tool_safely(
        "nuclei",
        nuclei.run_batch(scan_urls[:50], {}),
    ))

    if https_hosts:
        tasks.append(_run_tool_safely(
            "testssl",
            testssl.run(https_hosts[0], {}),
        ))

    if js_files:
        tasks.append(_run_tool_safely(
            "retirejs",
            retirejs.run_batch(js_files[:20], {}),
        ))

    check_urls = scan_urls[:10] if scan_urls else [ensure_https_url(target)]
    tasks.append(_run_tool_safely(
        "header-checks",
        header_checker.run_batch(check_urls, {}),
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

        findings = _extract_findings_from_result(result)
        all_findings.extend(findings)
        logger.info(f"{tool_name}: found {len(findings)} findings")

    return all_findings, errors


async def run_active_tools(state: ScanState) -> tuple[list[Finding], dict[str, str]]:
    """
    Run active detection tools (requires human approval).

    Active tools perform intrusive testing and should only run
    when state.human_approved is True.

    They include:
    - zap: OWASP ZAP active scanner
    - sqlmap: SQL injection scanner (only against parameterized URLs)

    Args:
        state: Current scan state with recon_results

    Returns:
        Tuple of (list of findings, dict of errors by tool name)
    """
    target = state["target"]
    recon_results = state.get("recon_results", {})

    zap = ZAPTool()
    sqlmap = SQLMapTool()

    tasks = []

    target_url = f"https://{target}" if not target.startswith("http") else target
    tasks.append(_run_tool_safely(
        "zap",
        zap.run(target_url, {}),
    ))

    injectable_urls = find_injectable_urls(recon_results)
    if injectable_urls:
        logger.info(f"Found {len(injectable_urls)} URLs for SQLMap testing")
        tasks.append(_run_tool_safely(
            "sqlmap",
            sqlmap.run_batch(injectable_urls[:10], {"level": 1, "risk": 1}),
        ))
    else:
        logger.info("No parameterized URLs found for SQLMap testing")

    logger.info(f"Running {len(tasks)} active detection tools")

    results = await asyncio.gather(*tasks, return_exceptions=False)

    await zap.close()

    all_findings: list[Finding] = []
    errors: dict[str, str] = {}

    for tool_name, result, error in results:
        if error:
            errors[tool_name] = error
            logger.warning(f"Active tool {tool_name} failed: {error}")
            continue

        if result is None:
            errors[tool_name] = "No result returned"
            continue

        findings = _extract_findings_from_result(result)
        all_findings.extend(findings)
        logger.info(f"{tool_name}: found {len(findings)} findings")

    return all_findings, errors


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
    human_approved = state.get("human_approved", False)

    logger.info(f"Starting detection for target: {target}")
    logger.info(f"Human approval status: {human_approved}")

    all_findings: list[Finding] = []
    all_errors: dict[str, str] = {}

    passive_findings, passive_errors = await run_passive_tools(state)
    all_findings.extend(passive_findings)
    all_errors.update(passive_errors)

    logger.info(f"Passive tools completed: {len(passive_findings)} findings")

    if human_approved:
        logger.info("Human approved - running active tools")
        active_findings, active_errors = await run_active_tools(state)
        all_findings.extend(active_findings)
        all_errors.update({f"active_{k}": v for k, v in active_errors.items()})

        logger.info(f"Active tools completed: {len(active_findings)} findings")
    else:
        logger.info("Active tools skipped - no human approval")

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
        "_detection_metadata": {
            "passive_count": len(passive_findings),
            "active_count": len(all_findings) - len(passive_findings) if human_approved else 0,
            "deduplicated_count": len(deduplicated),
            "new_findings_count": len(new_findings),
            "errors": all_errors if all_errors else None,
            "active_tools_run": human_approved,
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
