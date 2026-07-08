"""Reconnaissance agent - LangGraph node for parallel recon tool execution."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from agents.state import ScanState
from tools.base import (
    BinaryValidationError,
    ScopeViolationError,
    ToolExecutionError,
    ToolResult,
)
from tools.firecrawl_tool import FirecrawlTool
from tools.httpx_tool import HttpxTool
from tools.katana_tool import KatanaTool
from tools.subfinder_tool import SubfinderTool

logger = logging.getLogger(__name__)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    """Deduplicate a list of strings while preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _dedupe_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate endpoint dicts by URL, preserving first-seen order.

    Katana-discovered endpoints (with real status codes/methods) take priority
    over Firecrawl placeholders because Firecrawl is appended after Katana.
    """
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for endpoint in endpoints:
        url = endpoint.get("url", "")
        if url and url not in seen:
            seen.add(url)
            result.append(endpoint)
    return result


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


async def run_recon_async(state: ScanState) -> dict[str, Any]:
    """
    Execute reconnaissance tools in parallel and merge results.

    This is the async implementation that runs subfinder, httpx, katana, and
    Firecrawl concurrently using asyncio.gather. Individual tool failures are
    logged and handled gracefully - one tool failing won't crash the entire
    recon step. Firecrawl augments Katana's live crawl with sitemap/SERP-based
    URL discovery so recon captures endpoints a crawl alone would miss.

    Args:
        state: Current scan state containing target and scope

    Returns:
        Dict with recon_results to merge into ScanState
    """
    target = state["target"]
    scope = state.get("scope", {})

    logger.info(f"Starting reconnaissance for target: {target}")

    subfinder = SubfinderTool()
    httpx = HttpxTool()
    katana = KatanaTool()
    firecrawl = FirecrawlTool()

    tasks = [
        _run_tool_safely("subfinder", subfinder.run(target, scope)),
        _run_tool_safely("httpx", httpx.run(target, {"targets": [target]})),
        _run_tool_safely("katana", katana.run(target, scope)),
        _run_tool_safely("firecrawl", firecrawl.run(target, scope)),
    ]
    total_tools = len(tasks)

    results = await asyncio.gather(*tasks, return_exceptions=False)

    recon_results: dict[str, Any] = {
        "target": target,
        "subdomains": [],
        "hosts": [],
        "technologies": [],
        "endpoints": [],
        "urls": [],
        "js_files": [],
        "pages": [],
        "tool_results": {},
        "errors": {},
        "partial_failure": False,
    }

    for tool_name, result, error in results:
        if error:
            recon_results["errors"][tool_name] = error
            recon_results["partial_failure"] = True
            logger.warning(f"Tool {tool_name} failed: {error}")
            continue

        if result is None:
            recon_results["errors"][tool_name] = "No result returned"
            recon_results["partial_failure"] = True
            continue

        recon_results["tool_results"][tool_name] = {
            "success": result.success,
            "timed_out": result.timed_out,
            "exit_code": result.exit_code,
            "error": result.error,
        }

        if not result.success:
            recon_results["errors"][tool_name] = result.error or "Tool reported failure"
            recon_results["partial_failure"] = True

        if tool_name == "subfinder" and result.data:
            subdomains = result.data.get("subdomains", [])
            recon_results["subdomains"].extend(subdomains)
            logger.info(f"Subfinder found {len(subdomains)} subdomains")

        elif tool_name == "httpx" and result.data:
            hosts = result.data.get("hosts", [])
            technologies = result.data.get("technologies", [])
            recon_results["hosts"].extend(hosts)
            for tech in technologies:
                if tech not in recon_results["technologies"]:
                    recon_results["technologies"].append(tech)
            logger.info(
                f"HTTPx found {len(hosts)} live hosts, "
                f"{len(technologies)} technologies"
            )

        elif tool_name == "katana" and result.data:
            endpoints = result.data.get("endpoints", [])
            urls = result.data.get("urls", [])
            js_files = result.data.get("js_files", [])
            recon_results["endpoints"].extend(endpoints)
            recon_results["urls"].extend(urls)
            recon_results["js_files"].extend(js_files)
            logger.info(
                f"Katana found {len(urls)} URLs, "
                f"{len(endpoints)} endpoints, "
                f"{len(js_files)} JS files"
            )

        elif tool_name == "firecrawl" and result.data:
            fc_urls = result.data.get("urls", [])
            fc_endpoints = result.data.get("endpoints", [])
            fc_js_files = result.data.get("js_files", [])
            fc_subdomains = result.data.get("subdomains", [])
            fc_pages = result.data.get("pages", [])
            recon_results["urls"].extend(fc_urls)
            recon_results["endpoints"].extend(fc_endpoints)
            recon_results["js_files"].extend(fc_js_files)
            recon_results["subdomains"].extend(fc_subdomains)
            recon_results["pages"].extend(fc_pages)
            if result.data.get("skipped"):
                logger.info(
                    "Firecrawl skipped: %s",
                    result.data.get("skip_reason", "unknown"),
                )
            else:
                logger.info(
                    f"Firecrawl found {len(fc_urls)} URLs, "
                    f"{len(fc_js_files)} JS files, "
                    f"{len(fc_subdomains)} subdomains"
                )

    recon_results["subdomains"] = list(set(recon_results["subdomains"]))
    recon_results["technologies"] = list(set(recon_results["technologies"]))
    recon_results["urls"] = _dedupe_preserve_order(recon_results["urls"])
    recon_results["js_files"] = _dedupe_preserve_order(recon_results["js_files"])
    recon_results["endpoints"] = _dedupe_endpoints(recon_results["endpoints"])

    successful_tools = len(recon_results["tool_results"]) - len(recon_results["errors"])

    logger.info(
        f"Reconnaissance complete: {successful_tools}/{total_tools} tools succeeded, "
        f"{len(recon_results['subdomains'])} subdomains, "
        f"{len(recon_results['hosts'])} hosts, "
        f"{len(recon_results['technologies'])} technologies, "
        f"{len(recon_results['urls'])} URLs"
    )

    return {"recon_results": recon_results}


def run_recon(state: ScanState) -> dict[str, Any]:
    """
    LangGraph node function for reconnaissance.

    This is the synchronous entry point that LangGraph calls.
    It runs the async implementation using asyncio.

    Args:
        state: Current scan state

    Returns:
        Dict with recon_results to merge into ScanState
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        import nest_asyncio
        nest_asyncio.apply()
        return loop.run_until_complete(run_recon_async(state))
    else:
        return asyncio.run(run_recon_async(state))
