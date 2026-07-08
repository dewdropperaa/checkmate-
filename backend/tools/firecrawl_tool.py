"""Firecrawl API wrapper - managed web crawling for thorough URL discovery.

Unlike the other recon tools, Firecrawl is a hosted API (not a local CLI
binary), so this wrapper talks to the Firecrawl SDK instead of spawning a
subprocess. It is used during reconnaissance to complement Katana:

- ``map``    -> discovers URLs from the site's sitemap, search-engine results,
                and previously crawled pages, catching endpoints a live crawl
                alone would miss ("don't miss a thing").
- ``scrape`` -> fetches the root page as clean markdown plus its extracted
                links, giving downstream detection verified, live content so
                findings can be corroborated instead of guessed (fewer false
                positives).

Design notes:
- The tool degrades gracefully. If the SDK is not installed, no API key is
  configured, or Firecrawl is disabled, it returns a *successful* empty result
  with a note rather than raising, so recon never breaks because of it.
- The Firecrawl SDK signature has drifted across major versions, so calls are
  made defensively: unsupported keyword arguments are dropped and retried.
- Network work is bounded by ``firecrawl_timeout`` and, when only the sync SDK
  is available, executed in a worker thread so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any
from urllib.parse import urlparse

from core.config import get_settings
from tools.base import BaseSecurityTool, ToolResult, validate_scope

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import guard exercised via tests with monkeypatch
    from firecrawl import AsyncFirecrawl as _AsyncFirecrawl  # type: ignore
except Exception:  # noqa: BLE001 - any import failure means "not available"
    _AsyncFirecrawl = None

try:  # pragma: no cover - import guard
    from firecrawl import Firecrawl as _Firecrawl  # type: ignore
except Exception:  # noqa: BLE001
    _Firecrawl = None


def _looks_like_js(url: str) -> bool:
    """Return True if a URL points at a JavaScript resource."""
    lowered = url.split("#", 1)[0].lower()
    return lowered.endswith(".js") or ".js?" in lowered or ".mjs" in lowered


def _same_registrable_host(candidate_host: str, base_host: str) -> bool:
    """Return True if candidate host equals or is a subdomain of base host."""
    candidate_host = candidate_host.lower().lstrip(".")
    base_host = base_host.lower().lstrip(".")
    if not candidate_host or not base_host:
        return False
    return candidate_host == base_host or candidate_host.endswith("." + base_host)


def _coerce_url(item: Any) -> str | None:
    """Extract a URL string from the many shapes Firecrawl SDKs return."""
    if item is None:
        return None
    if isinstance(item, str):
        return item.strip() or None
    if isinstance(item, dict):
        for key in ("url", "link", "href"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None
    for attr in ("url", "link", "href"):
        value = getattr(item, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_link_list(payload: Any) -> list[str]:
    """Pull a list of URL strings out of a map/scrape response payload."""
    if payload is None:
        return []

    container: Any = payload
    # Responses may be the list directly, or wrap it under `links`/`data`/etc.
    for attr in ("links", "urls", "data"):
        if isinstance(container, dict) and attr in container:
            container = container[attr]
            break
        nested = getattr(container, attr, None)
        if nested is not None:
            container = nested
            break

    if isinstance(container, dict):
        container = container.get("links") or container.get("urls") or []

    if not isinstance(container, (list, tuple, set)):
        return []

    urls: list[str] = []
    for item in container:
        url = _coerce_url(item)
        if url:
            urls.append(url)
    return urls


class FirecrawlTool(BaseSecurityTool):
    """Firecrawl-powered URL discovery for reconnaissance.

    This tool does not resolve or execute a local binary; it calls the hosted
    Firecrawl API. ``get_binary_path`` is intentionally not used.
    """

    name = "firecrawl"
    description = (
        "Discover URLs for a target using Firecrawl's managed map + scrape API. "
        "Augments the local crawler so recon captures sitemap, SERP, and "
        "previously-crawled endpoints, and provides clean page content."
    )

    def __init__(self, timeout: float | None = None):
        settings = get_settings()
        resolved_timeout = (
            timeout if timeout is not None else settings.firecrawl_timeout
        )
        super().__init__(timeout=resolved_timeout)

    def _skipped_result(self, target: str, reason: str) -> ToolResult:
        """Return a non-fatal empty result when Firecrawl cannot run."""
        logger.info(f"Firecrawl skipped for {target}: {reason}")
        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            data={
                "urls": [],
                "url_count": 0,
                "endpoints": [],
                "endpoint_count": 0,
                "js_files": [],
                "js_file_count": 0,
                "subdomains": [],
                "pages": [],
                "skipped": True,
                "skip_reason": reason,
            },
        )

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """Discover URLs for ``target`` using Firecrawl.

        Args:
            target: URL or hostname to map.
            scope: Scope metadata (may contain ``firecrawl_limit`` override).

        Returns:
            ToolResult with discovered urls/endpoints/js_files/subdomains and
            optional scraped page content. Never raises for configuration
            problems; those produce a skipped (but successful) result.
        """
        url = target if "://" in target else f"https://{target}"
        parsed = urlparse(url)
        base_host = parsed.hostname or target
        validate_scope(base_host)

        settings = get_settings()

        if not settings.firecrawl_enabled:
            return self._skipped_result(target, "Firecrawl disabled via config")
        if not settings.firecrawl_api_key:
            return self._skipped_result(target, "FIRECRAWL_API_KEY not configured")
        if _AsyncFirecrawl is None and _Firecrawl is None:
            return self._skipped_result(target, "firecrawl-py package not installed")

        limit = int(scope.get("firecrawl_limit", settings.firecrawl_map_limit))

        try:
            discovered = await asyncio.wait_for(
                self._discover(url, base_host, limit, settings),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"Firecrawl timed out after {self.timeout}s for {target}")
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"Firecrawl timed out after {self.timeout}s",
                timed_out=True,
            )
        except Exception as e:  # noqa: BLE001 - report, never crash recon
            logger.exception(f"Firecrawl failed for {target}: {e}")
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"Firecrawl error: {type(e).__name__}: {e}",
            )

        urls = discovered["urls"]
        js_files = discovered["js_files"]
        subdomains = discovered["subdomains"]
        pages = discovered["pages"]

        endpoints = [
            {"url": u, "path": urlparse(u).path or "/", "method": "GET", "status_code": 0}
            for u in urls
        ]

        logger.info(
            f"Firecrawl discovered {len(urls)} URLs, {len(js_files)} JS files, "
            f"{len(subdomains)} subdomains for {target}"
        )

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            data={
                "urls": urls,
                "url_count": len(urls),
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
                "js_files": js_files,
                "js_file_count": len(js_files),
                "subdomains": subdomains,
                "pages": pages,
                "skipped": False,
            },
        )

    async def scrape_content(self, url: str, timeout: float | None = None) -> str | None:
        """Scrape a single URL and return combined searchable text.

        Returns markdown + HTML + link text concatenated (lowercased-safe for
        the caller), or None when Firecrawl is unavailable/disabled or the
        scrape fails. Never raises. Used by finding verification to corroborate
        content-based findings against the actual page body.
        """
        settings = get_settings()
        if not settings.firecrawl_enabled or not settings.firecrawl_api_key:
            return None
        if _AsyncFirecrawl is None and _Firecrawl is None:
            return None

        normalized = url if "://" in url else f"https://{url}"
        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            client, is_async = self._build_client()
            payload = await asyncio.wait_for(
                self._invoke(
                    client,
                    is_async,
                    "scrape",
                    normalized,
                    {"formats": ["markdown", "html", "links"]},
                ),
                timeout=effective_timeout,
            )
        except Exception as e:  # noqa: BLE001 - verification is best-effort
            logger.warning(f"Firecrawl verification scrape of {url} failed: {e}")
            return None

        return self._extract_searchable_text(payload)

    @staticmethod
    def _extract_searchable_text(payload: Any) -> str | None:
        """Concatenate markdown, HTML, and link URLs from a scrape payload."""
        parts: list[str] = []

        def _get(obj: Any, key: str) -> Any:
            if isinstance(obj, dict):
                return obj.get(key)
            return getattr(obj, key, None)

        for key in ("markdown", "html", "rawHtml", "raw_html", "content"):
            value = _get(payload, key)
            if isinstance(value, str) and value.strip():
                parts.append(value)

        links = _extract_link_list(payload)
        if links:
            parts.append("\n".join(links))

        # Also inspect a nested `data` container (some SDK shapes wrap content).
        data = _get(payload, "data")
        if isinstance(data, dict):
            for key in ("markdown", "html", "rawHtml", "content"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value)

        if not parts:
            return None
        return "\n".join(parts)

    async def _discover(
        self,
        url: str,
        base_host: str,
        limit: int,
        settings: Any,
    ) -> dict[str, Any]:
        """Run map (+ optional root scrape) and normalize the results."""
        # Build the SDK client once and reuse it for every call in this run.
        client, is_async = self._build_client()

        raw_urls: list[str] = []

        map_payload = await self._call_map(client, is_async, url, limit, settings)
        raw_urls.extend(_extract_link_list(map_payload))

        pages: list[dict[str, str]] = []
        if settings.firecrawl_scrape_root:
            try:
                scrape_payload = await self._call_scrape(client, is_async, url)
            except Exception as e:  # noqa: BLE001 - scrape is best-effort
                logger.warning(f"Firecrawl scrape of {url} failed: {e}")
                scrape_payload = None

            if scrape_payload is not None:
                raw_urls.extend(_extract_link_list(scrape_payload))
                markdown = self._extract_markdown(scrape_payload)
                if markdown:
                    pages.append({"url": url, "markdown": markdown[:20000]})

        # Always keep the target itself as an endpoint.
        raw_urls.append(url)

        seen: set[str] = set()
        urls: list[str] = []
        js_files: list[str] = []
        subdomains: set[str] = set()

        for candidate in raw_urls:
            candidate = candidate.strip()
            if not candidate or candidate in seen:
                continue

            candidate_host = urlparse(
                candidate if "://" in candidate else f"https://{candidate}"
            ).hostname
            if not candidate_host or not _same_registrable_host(candidate_host, base_host):
                continue

            seen.add(candidate)
            urls.append(candidate)

            if candidate_host != base_host:
                subdomains.add(candidate_host)
            if _looks_like_js(candidate):
                js_files.append(candidate)

            if len(urls) >= max(limit, 1):
                break

        return {
            "urls": urls,
            "js_files": js_files,
            "subdomains": sorted(subdomains),
            "pages": pages,
        }

    def _build_client(self) -> tuple[Any, bool]:
        """Construct a Firecrawl client, preferring the async variant."""
        settings = get_settings()
        kwargs: dict[str, Any] = {"api_key": settings.firecrawl_api_key}
        if settings.firecrawl_api_url:
            kwargs["api_url"] = settings.firecrawl_api_url

        if _AsyncFirecrawl is not None:
            return self._instantiate(_AsyncFirecrawl, kwargs), True
        return self._instantiate(_Firecrawl, kwargs), False

    @staticmethod
    def _instantiate(client_cls: Any, kwargs: dict[str, Any]) -> Any:
        """Instantiate a client, dropping kwargs the constructor rejects."""
        try:
            return client_cls(**kwargs)
        except TypeError:
            return client_cls(api_key=kwargs.get("api_key"))

    async def _call_map(
        self, client: Any, is_async: bool, url: str, limit: int, settings: Any
    ) -> Any:
        """Call the SDK ``map`` method with version-tolerant kwargs."""
        kwargs: dict[str, Any] = {
            "limit": limit,
            "sitemap": settings.firecrawl_sitemap,
            "include_subdomains": settings.firecrawl_include_subdomains,
        }
        return await self._invoke(client, is_async, "map", url, kwargs)

    async def _call_scrape(self, client: Any, is_async: bool, url: str) -> Any:
        """Call the SDK ``scrape`` method with version-tolerant kwargs."""
        return await self._invoke(
            client, is_async, "scrape", url, {"formats": ["markdown", "links"]}
        )

    async def _invoke(
        self,
        client: Any,
        is_async: bool,
        method_name: str,
        url: str,
        kwargs: dict[str, Any],
    ) -> Any:
        """Invoke a Firecrawl SDK method, tolerating async/sync + kwarg drift."""
        method = getattr(client, method_name, None)
        if method is None:
            raise RuntimeError(f"Firecrawl client has no '{method_name}' method")

        attempt_kwargs = dict(kwargs)
        # Progressively drop unsupported kwargs (older SDKs) until the call
        # signature is satisfied, always keeping the positional URL.
        drop_order = ["include_subdomains", "sitemap", "formats", "limit"]

        while True:
            try:
                if is_async or inspect.iscoroutinefunction(method):
                    return await method(url, **attempt_kwargs)
                return await asyncio.to_thread(method, url, **attempt_kwargs)
            except TypeError as e:
                removed = False
                for key in drop_order:
                    if key in attempt_kwargs:
                        logger.debug(
                            f"Firecrawl {method_name}: dropping unsupported "
                            f"kwarg '{key}' ({e})"
                        )
                        attempt_kwargs.pop(key)
                        removed = True
                        break
                if not removed:
                    raise

    @staticmethod
    def _extract_markdown(payload: Any) -> str | None:
        """Extract markdown content from a scrape response payload."""
        if isinstance(payload, dict):
            for key in ("markdown", "content"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value
            data = payload.get("data")
            if isinstance(data, dict):
                value = data.get("markdown")
                if isinstance(value, str) and value.strip():
                    return value
            return None
        for attr in ("markdown", "content"):
            value = getattr(payload, attr, None)
            if isinstance(value, str) and value.strip():
                return value
        return None
