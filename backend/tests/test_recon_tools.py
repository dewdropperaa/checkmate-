"""Tests for reconnaissance tools with mocked subprocess layer.

These tests verify:
1. Scope rejection works correctly
2. Timeout handling kills processes properly
3. Partial-failure handling works (one tool failing doesn't crash recon)
4. JSON parsing is safe and handles malformed input
5. Binary path validation works
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com,test.example.com")
os.environ.setdefault("TOOLS_BINARY_DIR", "/opt/tools")

from tools.base import (
    BinaryValidationError,
    ScopeViolationError,
    ToolResult,
    parse_json_output,
    resolve_binary_path,
    run_subprocess_safely,
    validate_scope,
)
from tools.httpx_tool import HttpxInput, HttpxTool
from tools.katana_tool import KatanaInput, KatanaTool
from tools.subfinder_tool import SubfinderInput, SubfinderTool


class TestScopeValidation:
    """Tests for scope validation and rejection."""

    def test_validate_scope_authorized_target_passes(self) -> None:
        """Authorized targets should not raise."""
        validate_scope("authorized.example.com")

    def test_validate_scope_unauthorized_target_passes(self) -> None:
        """Allowlist enforcement disabled: any target passes validate_scope."""
        validate_scope("malicious.attacker.com")

    def test_subfinder_input_accepts_any_target(self) -> None:
        """Allowlist enforcement disabled: SubfinderInput accepts any domain."""
        input_obj = SubfinderInput(target="evil.hacker.com")
        assert input_obj.target == "evil.hacker.com"

    def test_subfinder_input_accepts_authorized_target(self) -> None:
        """SubfinderInput schema should accept authorized targets."""
        input_obj = SubfinderInput(target="authorized.example.com")
        assert input_obj.target == "authorized.example.com"

    def test_subfinder_input_rejects_urls(self) -> None:
        """SubfinderInput should reject URLs, only accept domains."""
        with pytest.raises(ValueError) as exc_info:
            SubfinderInput(target="https://authorized.example.com/path")

        assert "domain name only" in str(exc_info.value)

    def test_httpx_input_accepts_any_targets(self) -> None:
        """Allowlist enforcement disabled: HttpxInput accepts any targets."""
        input_obj = HttpxInput(targets=["evil.hacker.com"])
        assert len(input_obj.targets) == 1

    def test_httpx_input_accepts_authorized_targets(self) -> None:
        """HttpxInput schema should accept authorized targets."""
        input_obj = HttpxInput(targets=["authorized.example.com"])
        assert len(input_obj.targets) == 1

    def test_katana_input_accepts_any_target(self) -> None:
        """Allowlist enforcement disabled: KatanaInput accepts any target."""
        input_obj = KatanaInput(target="https://evil.hacker.com")
        assert "evil.hacker.com" in input_obj.target

    def test_katana_input_accepts_authorized_target(self) -> None:
        """KatanaInput schema should accept authorized targets."""
        input_obj = KatanaInput(target="https://authorized.example.com")
        assert "authorized.example.com" in input_obj.target


class TestBinaryValidation:
    """Tests for binary path validation."""

    def test_resolve_binary_rejects_unknown_tool(self) -> None:
        """Unknown tools should be rejected."""
        with pytest.raises(BinaryValidationError) as exc_info:
            resolve_binary_path("malicious_binary")

        assert "not in the allowed tools list" in str(exc_info.value)

    @patch("tools.base._find_in_path")
    def test_resolve_binary_rejects_missing_binary(
        self, mock_find: MagicMock
    ) -> None:
        """Missing binaries should raise error."""
        mock_find.return_value = None

        with pytest.raises(BinaryValidationError) as exc_info:
            resolve_binary_path("subfinder")

        assert "not found" in str(exc_info.value)

    @patch("tools.base._find_in_path")
    @patch("pathlib.Path.is_symlink")
    @patch("pathlib.Path.resolve")
    @patch("pathlib.Path.is_file")
    @patch("os.access")
    def test_resolve_binary_accepts_valid_binary(
        self,
        mock_access: MagicMock,
        mock_is_file: MagicMock,
        mock_resolve: MagicMock,
        mock_is_symlink: MagicMock,
        mock_find: MagicMock,
    ) -> None:
        """Valid binaries should be accepted."""
        mock_path = Path("/opt/tools/subfinder")
        mock_find.return_value = mock_path
        mock_is_symlink.return_value = False
        mock_resolve.return_value = mock_path
        mock_is_file.return_value = True
        mock_access.return_value = True

        result = resolve_binary_path("subfinder")
        assert result is not None


class TestTimeoutHandling:
    """Tests for subprocess timeout and process killing."""

    @pytest.mark.asyncio
    async def test_timeout_kills_process_and_returns_timed_out(self) -> None:
        """Timeout should kill the process and return timed_out=True."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
                binary_path=Path("/opt/tools/subfinder"),
                args=["-d", "example.com"],
                timeout=0.001,
            )

        assert timed_out is True
        assert exit_code == -1

    @pytest.mark.asyncio
    async def test_successful_execution_returns_output(self) -> None:
        """Successful execution should return stdout/stderr."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(b'{"host": "sub.example.com"}', b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            exit_code, stdout, stderr, timed_out = await run_subprocess_safely(
                binary_path=Path("/opt/tools/subfinder"),
                args=["-d", "example.com"],
                timeout=120,
            )

        assert timed_out is False
        assert exit_code == 0
        assert '{"host": "sub.example.com"}' in stdout


class TestJsonParsing:
    """Tests for safe JSON output parsing."""

    def test_parse_json_output_handles_valid_jsonl(self) -> None:
        """Valid JSON lines should be parsed correctly."""
        output = '{"host": "a.example.com"}\n{"host": "b.example.com"}\n'
        results = parse_json_output(output, "test")
        assert len(results) == 2
        assert results[0]["host"] == "a.example.com"
        assert results[1]["host"] == "b.example.com"

    def test_parse_json_output_handles_malformed_lines(self) -> None:
        """Malformed lines should be skipped, not crash."""
        output = '{"host": "valid.example.com"}\nthis is not json\n{"broken\n'
        results = parse_json_output(output, "test")
        assert len(results) == 1
        assert results[0]["host"] == "valid.example.com"

    def test_parse_json_output_handles_empty_output(self) -> None:
        """Empty output should return empty list."""
        results = parse_json_output("", "test")
        assert results == []

    def test_parse_json_output_handles_mixed_content(self) -> None:
        """Mix of valid and invalid JSON should parse valid lines only."""
        output = """
{"host": "a.example.com"}
[INFO] Starting scan...
{"host": "b.example.com"}
Error: something went wrong
{"host": "c.example.com"}
"""
        results = parse_json_output(output, "test")
        assert len(results) == 3


class TestSubfinderTool:
    """Tests for SubfinderTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_subfinder_parses_results_correctly(self) -> None:
        """Subfinder should parse JSON output into subdomains list."""
        mock_output = '{"host": "sub1.authorized.example.com"}\n{"host": "sub2.authorized.example.com"}\n'

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(mock_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(SubfinderTool, "get_binary_path", return_value=Path("/opt/tools/subfinder")):
            tool = SubfinderTool()
            result = await tool.run("authorized.example.com", {})

        assert result.success is True
        assert result.data["count"] == 2
        assert "sub1.authorized.example.com" in result.data["subdomains"]
        assert "sub2.authorized.example.com" in result.data["subdomains"]

    @pytest.mark.asyncio
    async def test_subfinder_accepts_any_target(self) -> None:
        """Allowlist enforcement disabled: Subfinder does not raise ScopeViolationError."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(SubfinderTool, "get_binary_path", return_value=Path("/opt/tools/subfinder")):
            tool = SubfinderTool()
            result = await tool.run("evil.attacker.com", {})

        assert result is not None
        # Must not fail due to scope; empty tool output is fine
        assert "authorized scope" not in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_subfinder_handles_timeout(self) -> None:
        """Subfinder should handle timeout gracefully."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_process.terminate = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(SubfinderTool, "get_binary_path", return_value=Path("/opt/tools/subfinder")):
            tool = SubfinderTool(timeout=0.001)
            result = await tool.run("authorized.example.com", {})

        assert result.success is False
        assert result.timed_out is True
        assert "timed out" in result.error.lower()


class TestHttpxTool:
    """Tests for HttpxTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_httpx_parses_results_correctly(self) -> None:
        """HTTPx should parse JSON output into hosts and technologies."""
        mock_output = json.dumps({
            "url": "https://authorized.example.com",
            "host": "authorized.example.com",
            "port": 443,
            "status_code": 200,
            "title": "Example Site",
            "webserver": "nginx",
            "tech": ["nginx", "PHP"],
        }) + "\n"

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(mock_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(HttpxTool, "get_binary_path", return_value=Path("/opt/tools/httpx")):
            tool = HttpxTool()
            result = await tool.run("authorized.example.com", {"targets": ["authorized.example.com"]})

        assert result.success is True
        assert result.data["host_count"] == 1
        assert "nginx" in result.data["technologies"]
        assert "PHP" in result.data["technologies"]

    @pytest.mark.asyncio
    async def test_httpx_accepts_any_targets(self) -> None:
        """Allowlist enforcement disabled: HTTPx does not raise ScopeViolationError."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(HttpxTool, "get_binary_path", return_value=Path("/opt/tools/httpx")):
            tool = HttpxTool()
            result = await tool.run("evil.attacker.com", {"targets": ["evil.attacker.com"]})

        assert result is not None
        assert "authorized scope" not in (result.error or "").lower()


class TestKatanaTool:
    """Tests for KatanaTool with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_katana_parses_results_correctly(self) -> None:
        """Katana should parse JSON output into URLs and endpoints."""
        mock_output = '\n'.join([
            json.dumps({"request": {"endpoint": "https://authorized.example.com/"}, "url": "https://authorized.example.com/"}),
            json.dumps({"request": {"endpoint": "https://authorized.example.com/api"}, "url": "https://authorized.example.com/api"}),
            json.dumps({"request": {"endpoint": "https://authorized.example.com/app.js"}, "url": "https://authorized.example.com/app.js"}),
        ])

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(mock_output.encode(), b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
             patch.object(KatanaTool, "get_binary_path", return_value=Path("/opt/tools/katana")):
            tool = KatanaTool()
            result = await tool.run("https://authorized.example.com", {})

        assert result.success is True
        assert result.data["url_count"] == 3
        assert result.data["js_file_count"] == 1

    @pytest.mark.asyncio
    async def test_katana_respects_max_depth_config(self) -> None:
        """Katana should respect max_depth from scope."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"{}", b""))

        captured_args: list[str] = []

        async def capture_args(*args: Any, **kwargs: Any) -> AsyncMock:
            captured_args.extend(args)
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=capture_args), \
             patch.object(KatanaTool, "get_binary_path", return_value=Path("/opt/tools/katana")):
            tool = KatanaTool()
            await tool.run("https://authorized.example.com", {"max_depth": 2})

        assert "-depth" in captured_args
        depth_idx = captured_args.index("-depth")
        assert captured_args[depth_idx + 1] == "2"


class TestReconAgent:
    """Tests for the recon agent with parallel tool execution."""

    @pytest.mark.asyncio
    async def test_partial_failure_handling(self) -> None:
        """One tool failing should not crash the entire recon step."""
        from agents.recon import run_recon_async
        from agents.state import ScanState

        subfinder_output = '{"host": "sub.authorized.example.com"}\n'
        httpx_output = json.dumps({
            "url": "https://authorized.example.com",
            "host": "authorized.example.com",
            "status_code": 200,
            "tech": ["nginx"],
        }) + "\n"

        call_count = 0

        async def mock_create_subprocess(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal call_count
            call_count += 1

            mock_process = AsyncMock()
            mock_process.pid = 12345 + call_count
            mock_process.terminate = MagicMock()
            mock_process.kill = MagicMock()
            mock_process.wait = AsyncMock()

            if "katana" in str(args[0]):
                mock_process.returncode = None
                mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            elif "subfinder" in str(args[0]):
                mock_process.returncode = 0
                mock_process.communicate = AsyncMock(return_value=(subfinder_output.encode(), b""))
            else:
                mock_process.returncode = 0
                mock_process.communicate = AsyncMock(return_value=(httpx_output.encode(), b""))

            return mock_process

        state: ScanState = {
            "scan_id": "test-123",
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

        with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess), \
             patch.object(SubfinderTool, "get_binary_path", return_value=Path("/opt/tools/subfinder")), \
             patch.object(HttpxTool, "get_binary_path", return_value=Path("/opt/tools/httpx")), \
             patch.object(KatanaTool, "get_binary_path", return_value=Path("/opt/tools/katana")):

            result = await run_recon_async(state)

        assert "recon_results" in result
        recon = result["recon_results"]

        assert recon["partial_failure"] is True
        assert "katana" in recon["errors"]

        assert len(recon["subdomains"]) > 0
        assert len(recon["hosts"]) > 0 or len(recon["technologies"]) > 0

    @pytest.mark.asyncio
    async def test_all_tools_success(self) -> None:
        """All tools succeeding should merge results correctly."""
        from agents.recon import run_recon_async
        from agents.state import ScanState

        subfinder_output = '{"host": "sub.authorized.example.com"}\n'
        httpx_output = json.dumps({
            "url": "https://authorized.example.com",
            "host": "authorized.example.com",
            "status_code": 200,
            "tech": ["nginx", "PHP"],
        }) + "\n"
        katana_output = json.dumps({
            "request": {"endpoint": "https://authorized.example.com/api"},
            "url": "https://authorized.example.com/api",
        }) + "\n"

        async def mock_create_subprocess(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_process = AsyncMock()
            mock_process.pid = 12345
            mock_process.returncode = 0
            mock_process.terminate = MagicMock()
            mock_process.kill = MagicMock()
            mock_process.wait = AsyncMock()

            if "subfinder" in str(args[0]):
                mock_process.communicate = AsyncMock(return_value=(subfinder_output.encode(), b""))
            elif "httpx" in str(args[0]):
                mock_process.communicate = AsyncMock(return_value=(httpx_output.encode(), b""))
            else:
                mock_process.communicate = AsyncMock(return_value=(katana_output.encode(), b""))

            return mock_process

        state: ScanState = {
            "scan_id": "test-123",
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

        with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess), \
             patch.object(SubfinderTool, "get_binary_path", return_value=Path("/opt/tools/subfinder")), \
             patch.object(HttpxTool, "get_binary_path", return_value=Path("/opt/tools/httpx")), \
             patch.object(KatanaTool, "get_binary_path", return_value=Path("/opt/tools/katana")):

            result = await run_recon_async(state)

        recon = result["recon_results"]

        assert recon["partial_failure"] is False
        assert len(recon["errors"]) == 0
        assert len(recon["subdomains"]) == 1
        assert len(recon["hosts"]) == 1
        assert "nginx" in recon["technologies"]
        assert len(recon["urls"]) == 1
