"""ZAP deployment hardening: isolation, observability, graceful unavailability."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from tools.base import ToolResult
from tools.zap_tool import (
    EVENT_ZAP_SCAN_COMPLETED,
    EVENT_ZAP_SCAN_TIMEOUT,
    EVENT_ZAP_UNREACHABLE,
    ZAP_UNAVAILABLE_COVERAGE_NOTE,
    ZAPTool,
    is_zap_unavailable_error,
    reset_zap_semaphore_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_zap_sem():
    reset_zap_semaphore_for_tests()
    yield
    reset_zap_semaphore_for_tests()


def test_compose_pins_zap_image_digest():
    compose = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    assert "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:" in text
    # Full digest pin (64 hex chars) — tag alone is not enough.
    assert (
        "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2"
        in text
    )


def test_is_zap_unavailable_error_distinguishes_timeout():
    assert is_zap_unavailable_error("ZAP unreachable: connection refused")
    assert not is_zap_unavailable_error("ZAP scan timed out after 600s")


@pytest.mark.asyncio
async def test_zap_run_creates_and_tears_down_session():
    tool = ZAPTool(api_url="http://localhost:8080", api_key="test-key")
    calls: list[str] = []

    async def mock_api_call(endpoint: str, params: dict | None = None):
        calls.append(endpoint)
        if "version" in endpoint:
            return {"version": "2.17.0"}
        if "newSession" in endpoint:
            return {"Result": "OK"}
        if "spider/action/scan" in endpoint or "ascan/action/scan" in endpoint:
            return {"scan": "1"}
        if "status" in endpoint:
            return {"status": "100"}
        if "alerts" in endpoint:
            return {"alerts": []}
        return {}

    with patch.object(tool, "_api_call", side_effect=mock_api_call):
        result = await tool.run(
            "https://authorized.example.com",
            {"scan_id": "scan-iso-1"},
        )

    assert result.success is True
    assert any("newSession" in c for c in calls)
    # begin + teardown
    assert sum(1 for c in calls if "newSession" in c) >= 2
    assert result.data.get("zap_event") == EVENT_ZAP_SCAN_COMPLETED


@pytest.mark.asyncio
async def test_zap_unreachable_emits_coverage_note(monkeypatch):
    events: list[str] = []

    def _capture(scan_id, event, **fields):
        events.append(event)

    monkeypatch.setattr("tools.zap_tool.log_scan_event", _capture)
    tool = ZAPTool(api_url="http://localhost:8080", api_key="test-key")

    async def mock_api_call(endpoint: str, params: dict | None = None):
        raise ConnectionError("connection refused")

    with patch.object(tool, "_api_call", side_effect=mock_api_call):
        result = await tool.run("https://authorized.example.com", {"scan_id": "s1"})

    assert result.success is False
    assert result.data["zap_event"] == EVENT_ZAP_UNREACHABLE
    assert result.data["coverage_note"] == ZAP_UNAVAILABLE_COVERAGE_NOTE
    assert EVENT_ZAP_UNREACHABLE in events


@pytest.mark.asyncio
async def test_zap_timeout_event(monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(
        "tools.zap_tool.log_scan_event",
        lambda scan_id, event, **fields: events.append(event),
    )
    tool = ZAPTool(
        api_url="http://localhost:8080",
        api_key="test-key",
        timeout=0.01,
        poll_interval=0.01,
    )

    async def mock_api_call(endpoint: str, params: dict | None = None):
        if "version" in endpoint or "newSession" in endpoint:
            return {"version": "2.17.0"}
        if "spider/action/scan" in endpoint:
            return {"scan": "1"}
        if "spider/view/status" in endpoint:
            return {"status": "50"}  # never completes
        return {}

    with patch.object(tool, "_api_call", side_effect=mock_api_call):
        result = await tool.run("https://authorized.example.com", {"scan_id": "s2"})

    assert result.success is False
    assert result.timed_out is True
    assert result.data["zap_event"] == EVENT_ZAP_SCAN_TIMEOUT
    assert EVENT_ZAP_SCAN_TIMEOUT in events


@pytest.mark.asyncio
async def test_active_tools_skips_zap_when_probe_fails(monkeypatch):
    from agents.detection import run_active_tools
    from agents.state import ScanState
    from tools.zap_tool import ZAPTool
    from tools.sqlmap_tool import SQLMapTool

    monkeypatch.setattr(
        ZAPTool,
        "probe_ready",
        AsyncMock(return_value=(False, "ZAP unreachable: connection refused")),
    )
    monkeypatch.setattr(ZAPTool, "run", AsyncMock())
    monkeypatch.setattr(ZAPTool, "close", AsyncMock())
    monkeypatch.setattr(
        SQLMapTool,
        "run_batch",
        AsyncMock(
            return_value=ToolResult(
                tool_name="sqlmap",
                target="batch",
                success=True,
                data={"findings": []},
            )
        ),
    )
    monkeypatch.setattr(
        "agents.detection.find_injectable_urls",
        lambda recon: ["https://authorized.example.com/item?id=1"],
    )

    state: ScanState = {
        "scan_id": "s-unavail",
        "target": "https://authorized.example.com",
        "planned_active_tests": ["zap", "sqlmap"],
        "approved_tools": ["zap", "sqlmap"],
        "human_approved": True,
        "recon_results": {"urls": ["https://authorized.example.com/item?id=1"]},
    }
    findings, errors, _auth, notes = await run_active_tools(state)
    assert "zap" in errors
    assert ZAP_UNAVAILABLE_COVERAGE_NOTE in notes
    ZAPTool.run.assert_not_called()
