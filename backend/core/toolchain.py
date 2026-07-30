"""Security tool chain validation, health probes, and safe tool execution."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from core.config import Settings, get_settings
from core.retries import is_retryable_error, run_with_retries
from tools.base import (
    BinaryValidationError,
    ScopeViolationError,
    ToolExecutionError,
    ToolResult,
    resolve_binary_path,
)

logger = logging.getLogger(__name__)

REQUIRED_BINARIES: dict[str, list[str]] = {
    "subfinder": ["subfinder"],
    "httpx": ["httpx"],
    "katana": ["katana"],
    "nuclei": ["nuclei"],
    "testssl": ["testssl.sh", "testssl"],
    "retirejs": ["retire"],
    "sqlmap": ["sqlmap"],
}


@dataclass
class BinaryStatus:
    name: str
    path: str | None
    ok: bool
    error: str | None = None


@dataclass
class ToolchainReport:
    binaries: dict[str, BinaryStatus] = field(default_factory=dict)
    zap_ready: bool = False
    zap_error: str | None = None
    nuclei_templates_ok: bool = True
    ready: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "binaries": {
                name: {
                    "ok": status.ok,
                    "path": status.path,
                    "error": status.error,
                }
                for name, status in self.binaries.items()
            },
            "zap_ready": self.zap_ready,
            "zap_error": self.zap_error,
            "nuclei_templates_ok": self.nuclei_templates_ok,
        }


_toolchain_report: ToolchainReport | None = None


def _resolve_binary(candidates: list[str]) -> Path:
    last_error: BinaryValidationError | None = None
    for candidate in candidates:
        try:
            return resolve_binary_path(candidate)
        except BinaryValidationError as exc:
            last_error = exc
    raise last_error or BinaryValidationError(f"No binary found for {candidates}")


def inspect_toolchain(settings: Settings | None = None) -> ToolchainReport:
    """Check all required binaries and ZAP availability."""
    settings = settings or get_settings()
    report = ToolchainReport()

    for logical_name, candidates in REQUIRED_BINARIES.items():
        try:
            path = _resolve_binary(candidates)
            report.binaries[logical_name] = BinaryStatus(
                name=logical_name,
                path=str(path),
                ok=True,
            )
        except BinaryValidationError as exc:
            report.binaries[logical_name] = BinaryStatus(
                name=logical_name,
                path=None,
                ok=False,
                error=str(exc),
            )

    report.zap_ready, report.zap_error = _probe_zap(settings)
    report.nuclei_templates_ok = _nuclei_templates_present()
    report.ready = (
        all(b.ok for b in report.binaries.values())
        and report.zap_ready
        and report.nuclei_templates_ok
    )
    return report


def _nuclei_templates_present() -> bool:
    home = Path.home()
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        home / "nuclei-templates",
        Path("/root/nuclei-templates"),
        Path("/opt/nuclei-templates"),
    ]
    if appdata:
        candidates.append(Path(appdata) / "nuclei" / "templates")
        candidates.append(Path(appdata) / "nuclei-templates")
    if localappdata:
        candidates.append(Path(localappdata) / "nuclei" / "templates")
        candidates.append(Path(localappdata) / "nuclei-templates")
    for path in candidates:
        if path.is_dir() and any(path.iterdir()):
            return True
    # Binary present is enough to proceed; templates sync at startup/scan time.
    if shutil.which("nuclei") is not None:
        return True
    try:
        _resolve_binary(["nuclei"])
        return True
    except BinaryValidationError:
        return False


def _probe_zap(settings: Settings) -> tuple[bool, str | None]:
    if not settings.zap_api_url:
        return False, "ZAP_API_URL is not configured"
    url = f"{settings.zap_api_url.rstrip('/')}/JSON/core/view/version/"
    params = {"apikey": settings.zap_api_key} if settings.zap_api_key else {}
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(url, params=params)
            if response.status_code == 200:
                return True, None
            return False, f"ZAP returned HTTP {response.status_code}"
    except httpx.RequestError as exc:
        return False, f"ZAP unreachable: {exc}"


def validate_toolchain_at_startup(settings: Settings | None = None) -> ToolchainReport:
    """Fail fast when the scanner cannot run all modules reliably."""
    global _toolchain_report
    settings = settings or get_settings()
    report = inspect_toolchain(settings)
    _toolchain_report = report

    if not settings.require_toolchain_at_startup:
        if not report.ready:
            logger.warning(
                "Toolchain incomplete but REQUIRE_TOOLCHAIN_AT_STARTUP=false; %s",
                report.as_dict(),
            )
        return report

    problems: list[str] = []
    missing = [name for name, b in report.binaries.items() if not b.ok]
    if missing:
        problems.append(f"missing binaries: {', '.join(missing)}")
    if not report.zap_ready:
        problems.append(f"ZAP not ready: {report.zap_error}")
    if not report.nuclei_templates_ok:
        problems.append("nuclei templates not found (run nuclei -update-templates)")

    if problems:
        raise ValueError(
            "Security tool chain is not ready. The API will not accept scans until "
            "all tools are available. "
            + "; ".join(problems)
        )

    logger.info("Security tool chain validated successfully")
    return report


def get_toolchain_report() -> ToolchainReport:
    global _toolchain_report
    if _toolchain_report is None:
        _toolchain_report = inspect_toolchain()
    return _toolchain_report


def ensure_toolchain_ready() -> None:
    """Gate scan creation — raises ValueError when tools are not ready."""
    settings = get_settings()
    if settings.cloud_scan_profile == "firecrawl":
        if not settings.firecrawl_enabled or not settings.firecrawl_api_key:
            raise ValueError(
                "Cloud scans (firecrawl profile) require FIRECRAWL_ENABLED=true "
                "and FIRECRAWL_API_KEY."
            )
        return

    report = get_toolchain_report()
    if report.ready:
        return
    report = inspect_toolchain()
    global _toolchain_report
    _toolchain_report = report
    if not report.ready:
        missing = [n for n, b in report.binaries.items() if not b.ok]
        detail: list[str] = []
        if missing:
            detail.append(f"missing binaries: {', '.join(missing)}")
        if not report.zap_ready:
            detail.append(report.zap_error or "ZAP not ready")
        raise ValueError(
            "Scanner toolchain is not ready. Rebuild/restart the backend container. "
            + "; ".join(detail)
        )


async def run_tool_safely(
    tool_name: str,
    make_coro: Callable[[], Awaitable[Any]],
) -> tuple[str, Any | None, str | None]:
    """Execute a tool with retries; returns (tool_name, result, error_message)."""

    async def _attempt() -> Any:
        result = await make_coro()
        if isinstance(result, ToolResult) and not result.success:
            message = result.error or "Tool reported failure"
            # Do not retry full ZAP active-scan timeouts / unavailability —
            # each attempt can take many minutes and would hang the pipeline.
            if tool_name == "zap" and (
                result.timed_out or not is_retryable_error(message)
            ):
                return result
            if is_retryable_error(message) or result.timed_out:
                raise ToolExecutionError(message)
        return result

    try:
        result = await run_with_retries(tool_name, _attempt)
        return (tool_name, result, None)
    except ScopeViolationError as exc:
        logger.error("%s: Scope violation - %s", tool_name, exc)
        return (tool_name, None, f"Scope violation: {exc}")
    except BinaryValidationError as exc:
        logger.error("%s: Binary validation failed - %s", tool_name, exc)
        return (tool_name, None, f"Binary validation failed: {exc}")
    except ToolExecutionError as exc:
        logger.error("%s: Execution error - %s", tool_name, exc)
        return (tool_name, None, f"Execution error: {exc}")
    except asyncio.CancelledError:
        logger.warning("%s: Cancelled", tool_name)
        return (tool_name, None, "Cancelled")
    except Exception as exc:
        logger.exception("%s: Unexpected error - %s", tool_name, exc)
        return (tool_name, None, f"Unexpected error: {type(exc).__name__}: {exc}")


async def warm_nuclei_templates() -> None:
    """Best-effort nuclei template sync at startup."""
    try:
        binary = _resolve_binary(["nuclei"])
    except BinaryValidationError:
        return

    cmd = [str(binary), "-update-templates", "-silent"]

    def _run_sync() -> None:
        import subprocess

        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=180,
            check=False,
        )

    try:
        # Prefer asyncio subprocess when the loop supports it (Unix / Proactor).
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=180.0)
        except asyncio.TimeoutError:
            proc.kill()
            logger.warning("nuclei template update timed out at startup")
    except NotImplementedError:
        # Windows SelectorEventLoop cannot spawn subprocesses; fall back to a thread.
        logger.debug("asyncio subprocess unsupported; warming nuclei templates in a thread")
        try:
            await asyncio.to_thread(_run_sync)
        except Exception as exc:
            logger.warning("nuclei template update failed at startup: %s", exc)
    except Exception as exc:
        logger.warning("nuclei template update failed at startup: %s", exc)
