"""Tests for the Firecrawl recon tool and its integration into the recon agent.

The real Firecrawl SDK / network is never used. We inject a fake client and a
fake settings object so behavior (URL normalization, scope filtering, JS
detection, subdomain extraction, kwarg-drift tolerance, graceful degradation,
and timeout handling) is verified deterministically.
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from typing import Any

import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")

from tools import firecrawl_tool
from tools.firecrawl_tool import FirecrawlTool


def make_settings(**overrides: Any) -> SimpleNamespace:
    """Build a settings stand-in with sane Firecrawl defaults."""
    defaults = dict(
        firecrawl_timeout=30.0,
        firecrawl_enabled=True,
        firecrawl_api_key="fc-test-key",
        firecrawl_api_url=None,
        firecrawl_map_limit=500,
        firecrawl_include_subdomains=True,
        firecrawl_sitemap="include",
        firecrawl_scrape_root=True,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def patch_settings(monkeypatch: pytest.MonkeyPatch, settings: SimpleNamespace) -> None:
    monkeypatch.setattr(firecrawl_tool, "get_settings", lambda: settings)


class FakeAsyncClient:
    """Minimal async Firecrawl client returning canned payloads."""

    def __init__(self, map_payload: Any, scrape_payload: Any) -> None:
        self._map_payload = map_payload
        self._scrape_payload = scrape_payload
        self.map_calls: list[dict[str, Any]] = []
        self.scrape_calls: list[dict[str, Any]] = []

    async def map(self, url: str, **kwargs: Any) -> Any:
        self.map_calls.append({"url": url, **kwargs})
        return self._map_payload

    async def scrape(self, url: str, **kwargs: Any) -> Any:
        self.scrape_calls.append({"url": url, **kwargs})
        return self._scrape_payload


def install_fake_client(
    monkeypatch: pytest.MonkeyPatch,
    client: Any,
) -> None:
    """Force FirecrawlTool to use the given async client instance."""
    monkeypatch.setattr(firecrawl_tool, "_AsyncFirecrawl", object)
    monkeypatch.setattr(firecrawl_tool, "_Firecrawl", None)
    monkeypatch.setattr(
        FirecrawlTool, "_build_client", lambda self: (client, True)
    )


class TestGracefulDegradation:
    """Firecrawl must never crash recon; misconfiguration -> skipped result."""

    @pytest.mark.asyncio
    async def test_disabled_returns_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_settings(monkeypatch, make_settings(firecrawl_enabled=False))
        result = await FirecrawlTool().run("authorized.example.com", {})
        assert result.success is True
        assert result.data["skipped"] is True
        assert "disabled" in result.data["skip_reason"].lower()
        assert result.data["urls"] == []

    @pytest.mark.asyncio
    async def test_missing_key_returns_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_settings(monkeypatch, make_settings(firecrawl_api_key=None))
        result = await FirecrawlTool().run("authorized.example.com", {})
        assert result.success is True
        assert result.data["skipped"] is True
        assert "api_key" in result.data["skip_reason"].lower() or "key" in result.data["skip_reason"].lower()

    @pytest.mark.asyncio
    async def test_sdk_not_installed_returns_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_settings(monkeypatch, make_settings())
        monkeypatch.setattr(firecrawl_tool, "_AsyncFirecrawl", None)
        monkeypatch.setattr(firecrawl_tool, "_Firecrawl", None)
        result = await FirecrawlTool().run("authorized.example.com", {})
        assert result.success is True
        assert result.data["skipped"] is True
        assert "not installed" in result.data["skip_reason"].lower()


class TestDiscovery:
    """URL discovery, normalization, scope filtering, JS + subdomain handling."""

    @pytest.mark.asyncio
    async def test_map_and_scrape_merge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_settings(monkeypatch, make_settings())

        map_payload = {
            "links": [
                {"url": "https://authorized.example.com/"},
                {"url": "https://authorized.example.com/login"},
                {"url": "https://api.authorized.example.com/v1/users"},
                "https://authorized.example.com/static/app.js",
                {"url": "https://evil.example.org/phishing"},  # out of scope
            ]
        }
        scrape_payload = {
            "markdown": "# Home\nWelcome",
            "links": [
                "https://authorized.example.com/contact",
                "https://authorized.example.com/static/vendor.js",
            ],
        }
        client = FakeAsyncClient(map_payload, scrape_payload)
        install_fake_client(monkeypatch, client)

        result = await FirecrawlTool().run("authorized.example.com", {})

        assert result.success is True
        assert result.data["skipped"] is False

        urls = result.data["urls"]
        assert "https://authorized.example.com/login" in urls
        assert "https://authorized.example.com/contact" in urls
        assert "https://api.authorized.example.com/v1/users" in urls
        # Out-of-scope host is filtered out to avoid false positives downstream.
        assert all("evil.example.org" not in u for u in urls)

        assert "https://authorized.example.com/static/app.js" in result.data["js_files"]
        assert "https://authorized.example.com/static/vendor.js" in result.data["js_files"]

        assert "api.authorized.example.com" in result.data["subdomains"]

        assert len(result.data["pages"]) == 1
        assert result.data["pages"][0]["markdown"].startswith("# Home")

        # Endpoints mirror urls and carry parsed paths.
        endpoint_urls = {e["url"] for e in result.data["endpoints"]}
        assert endpoint_urls == set(urls)

    @pytest.mark.asyncio
    async def test_urls_are_deduplicated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_settings(monkeypatch, make_settings(firecrawl_scrape_root=False))
        map_payload = {
            "links": [
                "https://authorized.example.com/a",
                "https://authorized.example.com/a",
                "https://authorized.example.com/b",
            ]
        }
        client = FakeAsyncClient(map_payload, None)
        install_fake_client(monkeypatch, client)

        result = await FirecrawlTool().run("https://authorized.example.com", {})
        urls = result.data["urls"]
        assert urls.count("https://authorized.example.com/a") == 1
        assert not client.scrape_calls  # scrape_root disabled

    @pytest.mark.asyncio
    async def test_respects_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_settings(monkeypatch, make_settings(firecrawl_scrape_root=False))
        map_payload = {
            "links": [f"https://authorized.example.com/p{i}" for i in range(50)]
        }
        client = FakeAsyncClient(map_payload, None)
        install_fake_client(monkeypatch, client)

        result = await FirecrawlTool().run(
            "authorized.example.com", {"firecrawl_limit": 5}
        )
        assert result.data["url_count"] <= 5


class TestKwargDrift:
    """Older SDKs reject newer kwargs; the tool must retry without them."""

    @pytest.mark.asyncio
    async def test_unsupported_kwargs_are_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_settings(monkeypatch, make_settings(firecrawl_scrape_root=False))

        class PickyClient:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            async def map(self, url: str, **kwargs: Any) -> Any:
                if "include_subdomains" in kwargs:
                    raise TypeError("unexpected keyword 'include_subdomains'")
                if "sitemap" in kwargs:
                    raise TypeError("unexpected keyword 'sitemap'")
                self.calls.append({"url": url, **kwargs})
                return {"links": ["https://authorized.example.com/ok"]}

        client = PickyClient()
        install_fake_client(monkeypatch, client)

        result = await FirecrawlTool().run("authorized.example.com", {})
        assert "https://authorized.example.com/ok" in result.data["urls"]
        # Final successful call retained only supported kwargs (limit).
        assert client.calls and "include_subdomains" not in client.calls[-1]
        assert "sitemap" not in client.calls[-1]


class TestTimeout:
    """A slow Firecrawl call must be bounded and reported, not hang recon."""

    @pytest.mark.asyncio
    async def test_timeout_returns_error_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_settings(monkeypatch, make_settings(firecrawl_timeout=0.05))

        class SlowClient:
            async def map(self, url: str, **kwargs: Any) -> Any:
                await asyncio.sleep(1.0)
                return {"links": []}

            async def scrape(self, url: str, **kwargs: Any) -> Any:
                return None

        install_fake_client(monkeypatch, SlowClient())

        result = await FirecrawlTool().run("authorized.example.com", {})
        assert result.success is False
        assert result.timed_out is True
        assert "timed out" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_map_exception_reported_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_settings(monkeypatch, make_settings())

        class BrokenClient:
            async def map(self, url: str, **kwargs: Any) -> Any:
                raise RuntimeError("boom")

            async def scrape(self, url: str, **kwargs: Any) -> Any:
                return None

        install_fake_client(monkeypatch, BrokenClient())

        result = await FirecrawlTool().run("authorized.example.com", {})
        assert result.success is False
        assert "boom" in (result.error or "")


class TestReconIntegration:
    """Firecrawl results must merge into recon_results alongside other tools."""

    @pytest.mark.asyncio
    async def test_firecrawl_merges_into_recon(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agents import recon as recon_module
        from agents.recon import run_recon_async
        from agents.state import ScanState
        from tools.base import ToolResult

        async def fake_run(self: Any, target: str, scope: dict[str, Any]) -> ToolResult:
            return ToolResult(
                tool_name="firecrawl",
                target=target,
                success=True,
                data={
                    "urls": ["https://authorized.example.com/fc-only"],
                    "endpoints": [
                        {
                            "url": "https://authorized.example.com/fc-only",
                            "path": "/fc-only",
                            "method": "GET",
                            "status_code": 0,
                        }
                    ],
                    "js_files": ["https://authorized.example.com/fc.js"],
                    "subdomains": ["cdn.authorized.example.com"],
                    "pages": [{"url": "https://authorized.example.com", "markdown": "hi"}],
                    "skipped": False,
                },
            )

        # Stub the three CLI tools so only Firecrawl contributes URLs.
        async def empty_ok(self: Any, target: str, scope: dict[str, Any]) -> ToolResult:
            return ToolResult(tool_name="stub", target=target, success=True, data={})

        monkeypatch.setattr(recon_module.FirecrawlTool, "run", fake_run)
        monkeypatch.setattr(recon_module.SubfinderTool, "run", empty_ok)
        monkeypatch.setattr(recon_module.HttpxTool, "run", empty_ok)
        monkeypatch.setattr(recon_module.KatanaTool, "run", empty_ok)

        state: ScanState = {
            "scan_id": "t",
            "target": "authorized.example.com",
            "scope": {},
            "authorized": True,
            "recon_results": {},
            "planned_active_tests": [],
            "findings": [],
            "severity_scores": {},
            "report": None,
            "status": "running",
            "human_approval_needed": False,
            "human_approved": False,
        }

        result = await run_recon_async(state)
        recon = result["recon_results"]

        assert "https://authorized.example.com/fc-only" in recon["urls"]
        assert "https://authorized.example.com/fc.js" in recon["js_files"]
        assert "cdn.authorized.example.com" in recon["subdomains"]
        assert recon["pages"] and recon["pages"][0]["markdown"] == "hi"
        assert recon["partial_failure"] is False
