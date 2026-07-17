"""Subfinder CLI wrapper - subdomain enumeration tool."""

from __future__ import annotations

import logging
from typing import Any, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field, field_validator

from core.config import get_settings
from core.scope import is_target_authorized
from tools.base import (
    BaseSecurityTool,
    ScopeViolationError,
    ToolResult,
    parse_json_output,
    run_subprocess_safely,
    validate_scope,
)

logger = logging.getLogger(__name__)


class SubfinderInput(BaseModel):
    """Input schema for Subfinder tool with scope validation."""

    target: str = Field(
        description="Target domain to enumerate subdomains for (e.g., 'example.com')"
    )

    @field_validator("target")
    @classmethod
    def validate_target_in_scope(cls, v: str) -> str:
        """Validate that the target is in the authorized scope."""
        target = v.strip().lower()
        if not target:
            raise ValueError("Target domain cannot be empty")
        if "/" in target or ":" in target:
            raise ValueError(
                "Target should be a domain name only, not a URL. "
                "Example: 'example.com' not 'https://example.com'"
            )
        if not is_target_authorized(target):
            raise ValueError(
                f"Target '{target}' is not in the authorized scope. "
                "Only explicitly authorized targets may be scanned."
            )
        return target


class SubfinderTool(BaseSecurityTool):
    """
    Subfinder CLI wrapper for subdomain enumeration.

    Subfinder is a passive subdomain discovery tool that uses various
    sources (APIs, search engines, etc.) to find subdomains.
    """

    name = "subfinder"
    description = (
        "Enumerate subdomains for a target domain using passive reconnaissance. "
        "Returns a list of discovered subdomains."
    )

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Execute subfinder against an authorized target.

        Args:
            target: Domain to enumerate subdomains for
            scope: Scope metadata (unused but required by interface)

        Returns:
            ToolResult containing discovered subdomains
        """
        validate_scope(target)

        binary_path = self.get_binary_path()
        settings = get_settings()

        timeout = settings.subfinder_timeout or self.timeout

        # Bound subfinder's own runtime well under the subprocess timeout so it
        # exits cleanly instead of being force-killed (which would be treated as
        # a retryable timeout and rerun several times, stalling recon). We drop
        # "-all": it enables dozens of slow/keyless sources that routinely hang
        # and add little for a single target.
        source_budget = max(int(timeout) - 15, 20)
        args = [
            "-d", target,
            "-json",
            "-silent",
            "-timeout", "20",
            "-max-time", str(max(source_budget // 60, 1)),
        ]

        exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
            binary_path=binary_path,
            args=args,
            timeout=timeout,
        )

        if timed_out:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"Subfinder timed out after {timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        raw_results = parse_json_output(stdout, self.name)

        subdomains = []
        for item in raw_results:
            if "host" in item:
                subdomain = item["host"].lower().strip()
                if subdomain and subdomain not in subdomains:
                    subdomains.append(subdomain)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=exit_code == 0 or len(subdomains) > 0,
            data={
                "subdomains": subdomains,
                "count": len(subdomains),
                "raw_results": raw_results[:50],
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )


class SubfinderLangChainTool(BaseTool):
    """LangChain-compatible wrapper for Subfinder."""

    name: str = "subfinder"
    description: str = (
        "Enumerate subdomains for a target domain using passive reconnaissance. "
        "Input should be a domain name like 'example.com'. "
        "Returns a list of discovered subdomains."
    )
    args_schema: Type[BaseModel] = SubfinderInput

    _tool: SubfinderTool | None = None

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self._tool = SubfinderTool()

    def _run(self, target: str) -> str:
        """Synchronous execution not supported - use async."""
        raise NotImplementedError(
            "SubfinderLangChainTool only supports async execution. Use _arun instead."
        )

    async def _arun(self, target: str) -> str:
        """Execute subfinder asynchronously."""
        if self._tool is None:
            self._tool = SubfinderTool()

        try:
            result = await self._tool.run(target, {})
            if result.success:
                return (
                    f"Found {result.data['count']} subdomains for {target}:\n"
                    + "\n".join(result.data["subdomains"][:20])
                    + (
                        f"\n... and {result.data['count'] - 20} more"
                        if result.data["count"] > 20
                        else ""
                    )
                )
            else:
                return f"Subfinder failed: {result.error}"
        except ScopeViolationError as e:
            return f"Scope violation: {e}"
        except Exception as e:
            return f"Error running subfinder: {e}"
