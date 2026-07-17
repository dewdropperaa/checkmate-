"""Tests for security tool chain validation and retries."""

from __future__ import annotations

import pytest

from core.config import get_settings
from core.toolchain import run_tool_safely
from core.retries import is_retryable_error, run_with_retries
from tools.base import BinaryValidationError, ToolResult


class TestRetryableErrors:
    def test_timeout_is_retryable(self) -> None:
        assert is_retryable_error("Request timed out after 30s") is True

    def test_binary_missing_is_not_retryable(self) -> None:
        assert is_retryable_error("Binary 'nuclei' not found in tools directory") is False


class TestRunWithRetries:
    @pytest.mark.asyncio
    async def test_recovers_after_transient_failure(self) -> None:
        calls = {"n": 0}

        async def flaky() -> str:
            calls["n"] += 1
            if calls["n"] < 3:
                raise ConnectionError("connection reset by peer")
            return "ok"

        result = await run_with_retries("test-tool", flaky, max_attempts=3, backoff_seconds=0)
        assert result == "ok"
        assert calls["n"] == 3

    @pytest.mark.asyncio
    async def test_does_not_retry_permanent_errors(self) -> None:
        calls = {"n": 0}

        async def broken() -> str:
            calls["n"] += 1
            raise ValueError("Binary validation failed")

        with pytest.raises(ValueError):
            await run_with_retries("test-tool", broken, max_attempts=3, backoff_seconds=0)
        assert calls["n"] == 1


_TOOLS = (
    "subfinder",
    "httpx",
    "katana",
    "firecrawl",
    "nuclei",
    "testssl",
    "retirejs",
    "header-checks",
    "zap",
    "sqlmap",
)


class TestWrapperFailureMatrix:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", _TOOLS)
    async def test_missing_binary_degrades_gracefully_per_tool(self, tool_name: str) -> None:
        async def _missing_binary() -> ToolResult:
            raise BinaryValidationError(f"Binary '{tool_name}' not found")

        resolved_name, result, error = await run_tool_safely(tool_name, _missing_binary)
        assert resolved_name == tool_name
        assert result is None
        assert error is not None
        assert "Binary validation failed" in error

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", _TOOLS)
    async def test_timeout_failure_retries_then_returns_error(self, tool_name: str) -> None:
        settings = get_settings()
        old_attempts = settings.tool_retry_attempts
        old_backoff = settings.tool_retry_backoff_seconds
        settings.tool_retry_attempts = 3
        settings.tool_retry_backoff_seconds = 0

        calls = {"n": 0}

        async def _timed_out() -> ToolResult:
            calls["n"] += 1
            return ToolResult(
                tool_name=tool_name,
                target="https://authorized.example.com",
                success=False,
                error=f"{tool_name} timed out after 1s",
                timed_out=True,
            )

        try:
            resolved_name, result, error = await run_tool_safely(tool_name, _timed_out)
        finally:
            settings.tool_retry_attempts = old_attempts
            settings.tool_retry_backoff_seconds = old_backoff

        assert resolved_name == tool_name
        assert result is None
        assert error is not None
        assert "Execution error" in error
        assert "timed out" in error.lower()
        assert calls["n"] == 3

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name", _TOOLS)
    async def test_malformed_output_parser_error_is_captured(self, tool_name: str) -> None:
        async def _malformed_output() -> ToolResult:
            raise ValueError("Malformed output payload")

        resolved_name, result, error = await run_tool_safely(tool_name, _malformed_output)
        assert resolved_name == tool_name
        assert result is None
        assert error is not None
        assert "Unexpected error" in error
        assert "Malformed output payload" in error
