"""Katana CLI wrapper - web crawler for endpoint discovery."""

from __future__ import annotations

import logging
from typing import Any, Type
from urllib.parse import urlparse

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


class KatanaInput(BaseModel):
    """Input schema for Katana tool with scope validation and crawl limits."""

    target: str = Field(
        description="Target URL to crawl (e.g., 'https://example.com')"
    )
    max_depth: int | None = Field(
        default=None,
        description="Maximum crawl depth (overrides config default)",
        ge=1,
        le=10,
    )
    max_pages: int | None = Field(
        default=None,
        description="Maximum pages to crawl (overrides config default)",
        ge=1,
        le=1000,
    )

    @field_validator("target")
    @classmethod
    def validate_target_in_scope(cls, v: str) -> str:
        """Validate that the target URL is in the authorized scope."""
        target = v.strip()
        if not target:
            raise ValueError("Target URL cannot be empty")

        if "://" not in target:
            target = f"https://{target}"

        try:
            parsed = urlparse(target)
            if not parsed.hostname:
                raise ValueError(f"Could not parse hostname from target: {v}")
            base_domain = parsed.hostname
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

        if not is_target_authorized(base_domain):
            raise ValueError(
                f"Target '{base_domain}' is not in the authorized scope. "
                "Only explicitly authorized targets may be scanned."
            )
        return target


class KatanaTool(BaseSecurityTool):
    """
    Katana CLI wrapper for web crawling and endpoint discovery.

    Katana is a fast crawler designed to crawl websites and discover
    endpoints, JavaScript files, and other resources.

    SECURITY: Crawl depth and page count are capped via configuration
    to prevent unbounded crawling.
    """

    name = "katana"
    description = (
        "Crawl a website to discover endpoints, URLs, and resources. "
        "Depth and page limits are enforced to prevent unbounded crawling."
    )

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Execute katana against an authorized target.

        Args:
            target: URL to crawl
            scope: Scope metadata (may contain 'max_depth', 'max_pages')

        Returns:
            ToolResult containing discovered endpoints and URLs
        """
        if "://" not in target:
            target = f"https://{target}"

        parsed = urlparse(target)
        if parsed.hostname:
            validate_scope(parsed.hostname)

        binary_path = self.get_binary_path()
        settings = get_settings()

        max_depth = min(
            scope.get("max_depth", settings.katana_max_depth),
            settings.katana_max_depth,
        )
        max_pages = min(
            scope.get("max_pages", settings.katana_max_pages),
            settings.katana_max_pages,
        )
        rate_limit = settings.katana_rate_limit

        args = [
            "-u", target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-depth", str(max_depth),
            "-crawl-duration", "60",
            "-rate-limit", str(rate_limit),
        ]

        if max_pages > 0:
            args.extend(["-max-domain-pages", str(max_pages)])

        exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
            binary_path=binary_path,
            args=args,
            timeout=self.timeout,
        )

        if timed_out:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"Katana timed out after {self.timeout}s",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                timed_out=True,
            )

        raw_results = parse_json_output(stdout, self.name)

        urls = []
        endpoints = []
        js_files = []
        seen_urls = set()

        for item in raw_results:
            request = item.get("request") if isinstance(item.get("request"), dict) else {}
            response = item.get("response") if isinstance(item.get("response"), dict) else {}
            url = request.get("endpoint", "") or item.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            endpoint_info = {
                "url": url,
                "path": urlparse(url).path or item.get("path", ""),
                "method": request.get("method", item.get("method", "GET")),
                "status_code": response.get("status_code", item.get("status_code", 0)),
            }

            urls.append(url)
            endpoints.append(endpoint_info)

            if url.endswith(".js") or ".js?" in url:
                js_files.append(url)

            if len(urls) >= max_pages:
                logger.info(f"Katana reached max pages limit ({max_pages})")
                break

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=exit_code == 0 or len(urls) > 0,
            data={
                "urls": urls[:max_pages],
                "url_count": len(urls),
                "endpoints": endpoints[:max_pages],
                "endpoint_count": len(endpoints),
                "js_files": js_files,
                "js_file_count": len(js_files),
                "max_depth_used": max_depth,
                "max_pages_used": max_pages,
            },
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=False,
        )


class KatanaLangChainTool(BaseTool):
    """LangChain-compatible wrapper for Katana."""

    name: str = "katana"
    description: str = (
        "Crawl a website to discover endpoints, URLs, and JavaScript files. "
        "Input should be a URL like 'https://example.com'. "
        "Crawl depth and page count are limited to prevent unbounded crawling."
    )
    args_schema: Type[BaseModel] = KatanaInput

    _tool: KatanaTool | None = None

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self._tool = KatanaTool()

    def _run(self, target: str, max_depth: int | None = None, max_pages: int | None = None) -> str:
        """Synchronous execution not supported - use async."""
        raise NotImplementedError(
            "KatanaLangChainTool only supports async execution. Use _arun instead."
        )

    async def _arun(
        self,
        target: str,
        max_depth: int | None = None,
        max_pages: int | None = None,
    ) -> str:
        """Execute katana asynchronously."""
        if self._tool is None:
            self._tool = KatanaTool()

        scope = {}
        if max_depth is not None:
            scope["max_depth"] = max_depth
        if max_pages is not None:
            scope["max_pages"] = max_pages

        try:
            result = await self._tool.run(target, scope)
            if result.success:
                lines = [
                    f"Crawled {target} (depth={result.data['max_depth_used']}, "
                    f"max_pages={result.data['max_pages_used']}):",
                    f"  - Found {result.data['url_count']} URLs",
                    f"  - Found {result.data['endpoint_count']} endpoints",
                    f"  - Found {result.data['js_file_count']} JavaScript files",
                    "",
                    "Sample URLs:",
                ]
                for url in result.data["urls"][:10]:
                    lines.append(f"  - {url}")
                if result.data["url_count"] > 10:
                    lines.append(f"  ... and {result.data['url_count'] - 10} more")

                if result.data["js_files"]:
                    lines.append("\nJavaScript files:")
                    for js in result.data["js_files"][:5]:
                        lines.append(f"  - {js}")

                return "\n".join(lines)
            else:
                return f"Katana failed: {result.error}"
        except ScopeViolationError as e:
            return f"Scope violation: {e}"
        except Exception as e:
            return f"Error running katana: {e}"
