"""Regression tests for production module failures diagnosed from real scan checkpoints.

Real babliy.ai / medilink.ma detection_metadata.errors showed:
- nuclei: 'Nuclei batch exited with code 2'  (flag -json removed in nuclei v3)
- testssl: 'Fatal error: You need to install hexdump...'
- retirejs: '... exit 1' with no stderr surfaced
- header-checks: 'All 1 origin checks failed' with empty per-origin detail
  (SSRF pin used content=request.stream → AssertionError with str() == '')
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from tools.base import ToolResult
from tools.header_checks import HeaderChecker
from tools.nuclei_tool import NucleiTool
from tools.retirejs_tool import RetireJSTool


class TestNucleiJsonlFlag:
    @pytest.mark.asyncio
    async def test_run_batch_uses_jsonl_not_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/opt/tools/nuclei"))
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)

        captured: dict = {}

        async def _fake_subprocess(*, binary_path, args, timeout):
            captured["args"] = list(args)
            return (0, "", "", False)

        monkeypatch.setattr("tools.nuclei_tool.run_subprocess_safely", _fake_subprocess)
        result = await tool.run_batch(["https://authorized.example.com/"], {"dast": False})
        assert result.success is True
        assert "-jsonl" in captured["args"]
        assert "-json" not in captured["args"]

    @pytest.mark.asyncio
    async def test_run_uses_jsonl_not_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/opt/tools/nuclei"))
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)

        captured: dict = {}

        async def _fake_subprocess(*, binary_path, args, timeout):
            captured["args"] = list(args)
            return (0, "", "", False)

        monkeypatch.setattr("tools.nuclei_tool.run_subprocess_safely", _fake_subprocess)
        result = await tool.run("https://authorized.example.com/", {"dast": False})
        assert result.success is True
        assert "-jsonl" in captured["args"]
        assert "-json" not in captured["args"]

    @pytest.mark.asyncio
    async def test_run_batch_enables_dast_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/opt/tools/nuclei"))
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)
        monkeypatch.setattr(tool, "_enable_dast", True)

        captured: dict = {}

        async def _fake_subprocess(*, binary_path, args, timeout):
            captured["args"] = list(args)
            return (0, "", "", False)

        monkeypatch.setattr("tools.nuclei_tool.run_subprocess_safely", _fake_subprocess)
        result = await tool.run_batch(["https://authorized.example.com/"], {})
        assert result.success is True
        assert "-dast" in captured["args"]

    @pytest.mark.asyncio
    async def test_run_batch_honors_tags_and_severity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/opt/tools/nuclei"))
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)

        captured: dict = {}

        async def _fake_subprocess(*, binary_path, args, timeout):
            captured["args"] = list(args)
            return (0, "", "", False)

        monkeypatch.setattr("tools.nuclei_tool.run_subprocess_safely", _fake_subprocess)
        result = await tool.run_batch(
            ["https://authorized.example.com/"],
            {
                "dast": True,
                "template_tags": ["xss", "sqli", "ssrf"],
                "severity_filter": ["medium", "high", "critical"],
            },
        )
        assert result.success is True
        assert "-dast" in captured["args"]
        assert "-tags" in captured["args"]
        assert captured["args"][captured["args"].index("-tags") + 1] == "xss,sqli,ssrf"
        assert "-severity" in captured["args"]

    @pytest.mark.asyncio
    async def test_nonzero_exit_includes_stderr_detail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = NucleiTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/opt/tools/nuclei"))
        monkeypatch.setattr("tools.nuclei_tool.validate_scope", lambda *_a, **_k: None)

        async def _fake_subprocess(*, binary_path, args, timeout):
            return (2, "", "flag provided but not defined: -json", False)

        monkeypatch.setattr("tools.nuclei_tool.run_subprocess_safely", _fake_subprocess)
        result = await tool.run_batch(["https://authorized.example.com/"], {})
        assert result.success is False
        assert "flag provided but not defined: -json" in (result.error or "")


class TestHeaderChecksErrorSurfacing:
    @pytest.mark.asyncio
    async def test_batch_promotes_per_origin_errors_into_aggregate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        checker = HeaderChecker(timeout=1, rate_limit_delay=0)
        monkeypatch.setattr("tools.header_checks.validate_scope", lambda *_a, **_k: None)

        async def _fail_run(origin, scope):
            return ToolResult(
                tool_name="header-checks",
                target=origin,
                success=False,
                error="AssertionError: ",
            )

        monkeypatch.setattr(checker, "run", _fail_run)
        result = await checker.run_batch(["https://authorized.example.com/"], {})
        assert result.success is False
        assert "All 1 origin checks failed" in (result.error or "")
        assert "https://authorized.example.com" in (result.error or "")
        assert "AssertionError" in (result.error or "")
        assert result.data and result.data.get("errors")

    @pytest.mark.asyncio
    async def test_run_formats_empty_str_exceptions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        checker = HeaderChecker(timeout=1, rate_limit_delay=0)
        monkeypatch.setattr("tools.header_checks.validate_scope", lambda *_a, **_k: None)
        monkeypatch.setattr("tools.header_checks.validate_url", lambda *_a, **_k: None)

        class _BoomClient:
            async def head(self, *_a, **_k):
                raise AssertionError()

            async def aclose(self):
                return None

        async def _get_client():
            return _BoomClient()

        monkeypatch.setattr(checker, "_get_client", _get_client)
        monkeypatch.setattr(
            "tools.header_checks.run_with_retries",
            AsyncMock(side_effect=AssertionError()),
        )
        result = await checker.run("https://authorized.example.com/", {})
        assert result.success is False
        assert "AssertionError" in (result.error or "")


class TestRetireJsFailureDetail:
    @pytest.mark.asyncio
    async def test_batch_includes_stderr_in_child_failures(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = RetireJSTool(timeout=5)
        monkeypatch.setattr(tool, "get_binary_path", lambda: Path("/opt/tools/retire"))
        monkeypatch.setattr("tools.retirejs_tool.validate_scope", lambda *_a, **_k: None)
        monkeypatch.setattr(
            tool,
            "_download_js",
            AsyncMock(return_value=b"console.log(1)"),
        )

        async def _fake_subprocess(*, binary_path, args, timeout):
            assert "--path" in args
            assert "--jsuri" not in args
            return (
                1,
                "",
                "/usr/bin/env: 'node': No such file or directory",
                False,
            )

        monkeypatch.setattr("tools.retirejs_tool.run_subprocess_safely", _fake_subprocess)
        result = await tool.run_batch(
            ["https://authorized.example.com/app.js"],
            {},
        )
        assert result.success is False
        assert "No such file or directory" in (result.error or "")
        assert "node" in (result.error or "").lower()
