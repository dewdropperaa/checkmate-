"""HTTPx CLI wrapper - live host probing and technology fingerprinting."""

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


class HttpxInput(BaseModel):
    """Input schema for HTTPx tool with scope validation."""

    targets: list[str] = Field(
        description="List of hosts/URLs to probe (e.g., ['example.com', 'sub.example.com'])"
    )

    @field_validator("targets")
    @classmethod
    def validate_targets_in_scope(cls, v: list[str]) -> list[str]:
        """Validate that all targets are in the authorized scope."""
        if not v:
            raise ValueError("At least one target is required")

        validated = []
        for target in v:
            target = target.strip().lower()
            if not target:
                continue

            base_domain = target
            if "://" in target:
                from urllib.parse import urlparse
                parsed = urlparse(target)
                base_domain = parsed.hostname or target

            if not is_target_authorized(base_domain):
                raise ValueError(
                    f"Target '{target}' is not in the authorized scope. "
                    "Only explicitly authorized targets may be scanned."
                )
            validated.append(target)

        if not validated:
            raise ValueError("No valid targets provided")
        return validated


class HttpxTool(BaseSecurityTool):
    """
    HTTPx CLI wrapper for live host probing and tech fingerprinting.

    HTTPx is a fast HTTP toolkit that probes for live hosts,
    captures response information, and fingerprints web technologies.
    """

    name = "httpx"
    description = (
        "Probe hosts for live HTTP services and fingerprint web technologies. "
        "Returns live hosts with status codes, titles, and detected technologies."
    )

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Execute httpx against authorized targets.

        Args:
            target: Single target or newline-separated list of targets
            scope: Scope metadata containing optional 'targets' list

        Returns:
            ToolResult containing live hosts and technology fingerprints
        """
        targets = scope.get("targets", [target]) if isinstance(target, str) else [target]
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split("\n") if t.strip()]

        for t in targets:
            validate_scope(t)

        binary_path = self.get_binary_path()
        settings = get_settings()

        args = [
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-content-length",
            "-follow-redirects",
            "-rate-limit", str(settings.httpx_rate_limit),
        ]

        for t in targets:
            args.extend(["-u", t])

        timeout = settings.httpx_timeout or self.timeout

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
                error=f"HTTPx timed out after {timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        raw_results = parse_json_output(stdout, self.name)

        hosts = []
        technologies = set()

        for item in raw_results:
            host_info = {
                "url": item.get("url", ""),
                "host": item.get("host", ""),
                "port": item.get("port", 0),
                "status_code": item.get("status_code", 0),
                "title": item.get("title", ""),
                "web_server": item.get("webserver", ""),
                "content_length": item.get("content_length", 0),
                "technologies": item.get("tech", []),
                "scheme": item.get("scheme", "https"),
            }

            if host_info["url"] or host_info["host"]:
                hosts.append(host_info)
                for tech in host_info["technologies"]:
                    technologies.add(tech)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=exit_code == 0 or len(hosts) > 0,
            data={
                "hosts": hosts,
                "host_count": len(hosts),
                "technologies": sorted(technologies),
                "technology_count": len(technologies),
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )


class HttpxLangChainTool(BaseTool):
    """LangChain-compatible wrapper for HTTPx."""

    name: str = "httpx"
    description: str = (
        "Probe hosts for live HTTP services and fingerprint web technologies. "
        "Input should be a list of hosts/URLs to probe. "
        "Returns live hosts with status codes, titles, and detected technologies."
    )
    args_schema: Type[BaseModel] = HttpxInput

    _tool: HttpxTool | None = None

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self._tool = HttpxTool()

    def _run(self, targets: list[str]) -> str:
        """Synchronous execution not supported - use async."""
        raise NotImplementedError(
            "HttpxLangChainTool only supports async execution. Use _arun instead."
        )

    async def _arun(self, targets: list[str]) -> str:
        """Execute httpx asynchronously."""
        if self._tool is None:
            self._tool = HttpxTool()

        try:
            result = await self._tool.run(
                targets[0] if targets else "",
                {"targets": targets}
            )
            if result.success:
                lines = [f"Found {result.data['host_count']} live hosts:"]
                for host in result.data["hosts"][:10]:
                    tech_str = ", ".join(host["technologies"][:3]) or "N/A"
                    lines.append(
                        f"  - {host['url']} [{host['status_code']}] "
                        f"Title: {host['title'][:50] if host['title'] else 'N/A'} "
                        f"Tech: {tech_str}"
                    )
                if result.data["host_count"] > 10:
                    lines.append(f"  ... and {result.data['host_count'] - 10} more")

                if result.data["technologies"]:
                    lines.append(f"\nAll technologies detected: {', '.join(result.data['technologies'][:15])}")

                return "\n".join(lines)
            else:
                return f"HTTPx failed: {result.error}"
        except ScopeViolationError as e:
            return f"Scope violation: {e}"
        except Exception as e:
            return f"Error running httpx: {e}"
