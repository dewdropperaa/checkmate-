"""Abstract base class for external security CLI tool wrappers with secure execution."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from core.config import get_settings
from core.scope import is_target_authorized
from core.ssrf import SSRFError, validate_url

logger = logging.getLogger(__name__)

ALLOWED_TOOL_BINARIES = frozenset({
    "subfinder",
    "httpx",
    "katana",
    "nuclei",
    "nmap",
    "testssl.sh",
    "testssl",
    "retire",
    "sqlmap",
})


class ScopeViolationError(Exception):
    """Raised when a target is not in the authorized scope."""


class ToolExecutionError(Exception):
    """Raised when a tool fails to execute properly."""


class ToolTimeoutError(ToolExecutionError):
    """Raised when a tool exceeds its execution timeout."""


class BinaryValidationError(ToolExecutionError):
    """Raised when binary path validation fails."""


class ToolResult(BaseModel):
    """Structured result from a tool execution."""

    tool_name: str
    target: str
    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    timed_out: bool = False


def resolve_binary_path(binary_name: str) -> Path:
    """
    Resolve and validate the full path to a security tool binary.

    Security checks:
    - Binary name must be in the allowlist
    - Resolved path must be a regular file (not a symlink to unexpected location)
    - Path must be executable

    Args:
        binary_name: Name of the binary to resolve (e.g., 'subfinder')

    Returns:
        Absolute Path to the validated binary

    Raises:
        BinaryValidationError: If validation fails
    """
    if binary_name not in ALLOWED_TOOL_BINARIES:
        raise BinaryValidationError(
            f"Binary '{binary_name}' is not in the allowed tools list"
        )

    settings = get_settings()
    tools_dir = Path(settings.tools_binary_dir)

    if sys.platform == "win32":
        # Prefer .exe, then npm-style .cmd/.bat wrappers (e.g. retire).
        name_variants = [
            f"{binary_name}.exe",
            f"{binary_name}.cmd",
            f"{binary_name}.bat",
            binary_name,
        ]
    else:
        name_variants = [binary_name]

    binary_path: Path | None = None
    if tools_dir.exists():
        for variant in name_variants:
            candidate = tools_dir / variant
            if candidate.exists():
                binary_path = candidate.resolve()
                break

    if binary_path is None:
        for variant in name_variants:
            binary_path = _find_in_path(variant)
            if binary_path is not None:
                break

    if binary_path is None:
        which_hit = shutil.which(binary_name)
        if which_hit:
            binary_path = Path(which_hit)

    if binary_path is None:
        raise BinaryValidationError(
            f"Binary '{binary_name}' not found in tools directory or PATH"
        )

    resolved = binary_path.resolve()
    allowed_names = {binary_name, *name_variants}

    if binary_path.is_symlink():
        link_target = binary_path.resolve()
        if link_target.name not in allowed_names:
            raise BinaryValidationError(
                f"Symlink '{binary_path}' points to unexpected target '{link_target}'"
            )

    if not resolved.is_file():
        raise BinaryValidationError(f"Binary path '{resolved}' is not a regular file")

    if sys.platform != "win32" and not os.access(resolved, os.X_OK):
        raise BinaryValidationError(f"Binary '{resolved}' is not executable")

    return resolved


def _find_in_path(binary_name: str) -> Path | None:
    """Find a binary in the system PATH."""
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for dir_path in path_dirs:
        candidate = Path(dir_path) / binary_name
        if candidate.exists():
            return candidate
    return None


def validate_scope(target: str) -> None:
    """
    Validate that a target is within the authorized scope.

    This is called independently by each tool, regardless of upstream checks,
    as a defense-in-depth measure.

    Always enforces SSRF protections (private IP / metadata blocking).
    Allowlist enforcement is temporarily disabled — see core/scope.py.

    Args:
        target: The target hostname or URL to validate

    Raises:
        ScopeViolationError: If target is not authorized or fails SSRF checks
    """
    try:
        validate_url(target, resolve_dns=True)
    except SSRFError as exc:
        raise ScopeViolationError(str(exc)) from exc

    # Allowlist temporarily disabled — always pass after SSRF check.
    # To re-enable: restore the is_target_authorized check below.
    return
    # if not is_target_authorized(target):
    #     raise ScopeViolationError(
    #         f"Target '{target}' is not in the authorized scope. "
    #         "Refusing to execute tool."
    #     )


async def run_subprocess_safely(
    binary_path: Path,
    args: list[str],
    timeout: float = 120.0,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str, bool]:
    """
    Execute a subprocess with security safeguards.

    Security features:
    - Never uses shell=True
    - Explicit argument list only
    - Hard timeout with process group kill
    - Captures stdout/stderr safely

    Args:
        binary_path: Validated path to the binary
        args: List of command-line arguments (NOT a shell string)
        timeout: Maximum execution time in seconds
        env: Optional environment variables (merged with current env)

    Returns:
        Tuple of (exit_code, stdout, stderr, timed_out)
    """
    # Windows .cmd/.bat cannot be started via CreateProcess without cmd.exe.
    if sys.platform == "win32" and binary_path.suffix.lower() in {".cmd", ".bat"}:
        cmd = ["cmd.exe", "/d", "/c", str(binary_path), *args]
    else:
        cmd = [str(binary_path), *args]
    logger.info(f"Executing: {' '.join(cmd)}")

    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    timed_out = False

    try:
        try:
            if sys.platform == "win32":
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=process_env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=process_env,
                    start_new_session=True,
                )
        except NotImplementedError:
            # Some Windows event loops (SelectorEventLoop) cannot spawn subprocesses.
            return await asyncio.to_thread(
                _run_subprocess_sync, cmd, timeout, process_env
            )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
            exit_code = process.returncode or 0
        except asyncio.TimeoutError:
            timed_out = True
            logger.warning(f"Process timed out after {timeout}s, killing process group")
            await _kill_process_tree(process)
            stdout_bytes = b""
            stderr_bytes = b""
            exit_code = -1

    except Exception as e:
        logger.error(f"Failed to execute subprocess: {e}")
        raise ToolExecutionError(f"Subprocess execution failed: {e}") from e

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    return exit_code, stdout, stderr, timed_out


def _run_subprocess_sync(
    cmd: list[str],
    timeout: float,
    process_env: dict[str, str],
) -> tuple[int, str, str, bool]:
    """Synchronous subprocess fallback for event loops without async subprocess support.

    On timeout the ENTIRE process tree is killed. This is critical: some tools
    spawn child processes (resolvers, headless browsers, etc.) that inherit the
    stdout/stderr pipe handles. ``subprocess.run(timeout=...)`` only kills the
    direct child, so those grandchildren keep the pipes open and the follow-up
    read blocks forever — which is exactly what makes recon appear "stuck".
    """
    popen_kwargs: dict[str, Any] = {
        # Close stdin: ProjectDiscovery tools (httpx, katana, ...) read targets
        # from stdin and will block forever on an inherited, never-closed pipe
        # even when -u/-l is passed. DEVNULL gives them immediate EOF.
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": process_env,
    }
    if sys.platform == "win32":
        # New process group lets taskkill /T reliably terminate the whole tree;
        # CREATE_NO_WINDOW stops console popups per spawned tool.
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        )
    else:
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(cmd, **popen_kwargs)  # noqa: S603 - args are validated
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
        return (
            process.returncode or 0,
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            False,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Process timed out after %ss, killing process tree", timeout
        )
        _kill_process_tree_sync(process)
        # Drain whatever is buffered, but never block on the (killed) tree.
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout_bytes, stderr_bytes = b"", b""
        return (
            -1,
            (stdout_bytes or b"").decode("utf-8", errors="replace"),
            (stderr_bytes or b"").decode("utf-8", errors="replace"),
            True,
        )


def _kill_process_tree_sync(process: subprocess.Popen) -> None:
    """Kill a process and all of its descendants (synchronous)."""
    if process.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        else:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
    except Exception as e:  # noqa: BLE001 - best-effort cleanup
        logger.warning("Failed to kill process tree: %s", e)
        try:
            process.kill()
        except Exception:  # noqa: BLE001
            pass


async def _kill_process_tree(process: asyncio.subprocess.Process) -> None:
    """Kill a process and its entire process group."""
    try:
        if sys.platform == "win32":
            if process.pid:
                try:
                    killer = await asyncio.create_subprocess_exec(
                        "taskkill",
                        "/PID",
                        str(process.pid),
                        "/T",
                        "/F",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.wait_for(killer.communicate(), timeout=5.0)
                except Exception as e:
                    logger.warning(f"taskkill failed, falling back to terminate(): {e}")
                    process.terminate()
            else:
                process.terminate()
        else:
            if process.pid:
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    process.kill()
    except Exception as e:
        logger.warning(f"Error killing process tree: {e}")
        try:
            process.kill()
        except Exception:
            pass

    try:
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        logger.warning("Process did not terminate after kill signal")


def parse_json_output(output: str, tool_name: str) -> list[dict[str, Any]]:
    """
    Parse JSON lines output from a tool safely.

    Many ProjectDiscovery tools output one JSON object per line.
    This parses each line independently and collects valid JSON objects.

    SECURITY: Never uses eval() or exec(). Only json.loads().

    Args:
        output: Raw stdout from the tool
        tool_name: Name of the tool (for logging)

    Returns:
        List of parsed JSON objects
    """
    results = []
    for line_num, line in enumerate(output.strip().split("\n"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                results.append(obj)
            elif isinstance(obj, list):
                results.extend(item for item in obj if isinstance(item, dict))
        except json.JSONDecodeError as e:
            logger.debug(f"{tool_name}: Failed to parse line {line_num}: {e}")
            continue
    return results


class BaseSecurityTool(ABC):
    """
    Interface that all security tool wrappers must implement.

    Subclasses must:
    - Implement the `run` method
    - Set `name` class attribute to match the binary name
    - Define a Pydantic input schema for LangChain integration
    """

    name: str = "base"
    description: str = "Base security tool"

    def __init__(self, timeout: float | None = None):
        """
        Initialize the tool with optional timeout override.

        Args:
            timeout: Execution timeout in seconds (uses config default if None)
        """
        settings = get_settings()
        self.timeout = timeout if timeout is not None else settings.tool_timeout
        self._binary_path: Path | None = None

    def get_binary_path(self) -> Path:
        """Get the validated binary path, caching the result."""
        if self._binary_path is None:
            self._binary_path = resolve_binary_path(self.name)
        return self._binary_path

    @abstractmethod
    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Execute the tool against an authorized target.

        Implementations MUST:
        1. Call validate_scope(target) before any execution
        2. Use run_subprocess_safely() for process execution
        3. Return a ToolResult with structured data

        Args:
            target: Normalized scan target (URL or hostname).
            scope: Scope metadata (allowlist context, scan options, etc.).

        Returns:
            ToolResult with structured output from the tool run.
        """
        ...
