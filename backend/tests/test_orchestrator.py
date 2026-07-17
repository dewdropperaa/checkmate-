"""LangGraph orchestrator integration tests."""

import asyncio
import time
from pathlib import Path

import pytest

from agents.orchestrator import (
    ScanOrchestrator,
    build_scan_graph,
    create_checkpointer,
)
from core.config import get_settings


@pytest.fixture
def orchestrator(fast_scan_nodes: None) -> ScanOrchestrator:
    get_settings.cache_clear()
    return ScanOrchestrator(use_sqlite=False)


@pytest.fixture
def authorized_target() -> str:
    return "https://authorized.example.com"


def test_graph_topology_has_expected_nodes() -> None:
    graph = build_scan_graph()
    compiled = graph.compile(checkpointer=create_checkpointer(use_sqlite=False))
    node_names = set(compiled.get_graph().nodes.keys())
    expected = {
        "check_scope",
        "recon",
        "passive_detection",
        "plan_active_tests",
        "human_approval_gate",
        "active_detection",
        "verification",
        "scoring",
        "ai_synthesis",
        "reporting",
        "__start__",
        "__end__",
    }
    assert expected.issubset(node_names)


@pytest.mark.asyncio
async def test_graph_pauses_at_approval_gate_then_resumes_to_end(
    orchestrator: ScanOrchestrator,
    authorized_target: str,
) -> None:
    scan_id = "test-scan-approval-flow"
    orchestrator.register_scan(scan_id, authorized_target)

    await orchestrator.start_scan(scan_id, authorized_target)

    summary = await orchestrator.get_status_summary(scan_id)
    assert summary is not None
    assert summary["pending_interrupt"] is not None
    assert summary["pending_interrupt"]["node"] == "human_approval_gate"
    assert summary["human_approval_needed"] is True
    assert summary["is_complete"] is False
    assert summary["status"] == "awaiting_approval"
    assert "sqlmap" in summary["pending_interrupt"]["value"]["planned_active_tests"]

    await orchestrator.resume_scan(scan_id, approved=True)

    final = await orchestrator.get_status_summary(scan_id)
    assert final is not None
    assert final["is_complete"] is True
    assert final["status"] == "completed"
    assert final["human_approved"] is True

    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    assert snapshot.values.get("report") is not None


@pytest.mark.asyncio
async def test_graph_rejection_skips_active_detection(
    orchestrator: ScanOrchestrator,
    authorized_target: str,
) -> None:
    """Rejected scans still keep passive findings but skip active tools."""
    scan_id = "test-scan-reject-flow"
    orchestrator.register_scan(scan_id, authorized_target)
    await orchestrator.start_scan(scan_id, authorized_target)

    pre_resume = await orchestrator.get_status_summary(scan_id)
    assert pre_resume is not None
    assert pre_resume["pending_interrupt"] is not None

    await orchestrator.resume_scan(scan_id, approved=False)

    final = await orchestrator.get_status_summary(scan_id)
    assert final is not None
    assert final["is_complete"] is True
    assert final["status"] == "completed"
    assert final["human_approved"] is False
    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    assert snapshot.values.get("report", {}).get("outcome") == "rejected"
    assert snapshot.values.get("detection_metadata", {}).get("passive_tools_run") is True
    assert snapshot.values.get("detection_metadata", {}).get("active_tools_run") is False


@pytest.mark.asyncio
async def test_graph_partial_approval_runs_only_selected_tool(
    orchestrator: ScanOrchestrator,
    authorized_target: str,
) -> None:
    """A reviewer can approve sqlmap while rejecting zap (per-tool gate)."""
    scan_id = "test-scan-partial-approval"
    orchestrator.register_scan(scan_id, authorized_target)

    await orchestrator.start_scan(scan_id, authorized_target)

    summary = await orchestrator.get_status_summary(scan_id)
    assert summary is not None
    planned = summary["pending_interrupt"]["value"]["planned_active_tests"]
    assert set(planned) == {"sqlmap", "zap"}

    await orchestrator.resume_scan(scan_id, approved=True, approved_tools=["sqlmap"])

    final = await orchestrator.get_status_summary(scan_id)
    assert final is not None
    assert final["is_complete"] is True
    assert final["human_approved"] is True
    assert final["approved_tools"] == ["sqlmap"]
    assert final["rejected_tools"] == ["zap"]

    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    detection_metadata = snapshot.values.get("detection_metadata", {})
    assert detection_metadata.get("active_tools_run") is True
    assert detection_metadata.get("approved_tools") == ["sqlmap"]
    assert detection_metadata.get("rejected_tools") == ["zap"]


@pytest.mark.asyncio
async def test_graph_empty_approved_tools_list_behaves_like_rejection(
    orchestrator: ScanOrchestrator,
    authorized_target: str,
) -> None:
    """Explicitly approving zero tools should behave like a full rejection."""
    scan_id = "test-scan-empty-approval"
    orchestrator.register_scan(scan_id, authorized_target)

    await orchestrator.start_scan(scan_id, authorized_target)
    await orchestrator.resume_scan(scan_id, approved=True, approved_tools=[])

    final = await orchestrator.get_status_summary(scan_id)
    assert final is not None
    assert final["is_complete"] is True
    assert final["human_approved"] is False
    assert final["approved_tools"] == []
    assert set(final["rejected_tools"]) == {"sqlmap", "zap"}


@pytest.mark.asyncio
async def test_async_schedule_reaches_interrupt(
    orchestrator: ScanOrchestrator,
    authorized_target: str,
) -> None:
    scan_id = "test-scan-async"
    orchestrator.register_scan(scan_id, authorized_target)
    task = orchestrator.schedule_scan(scan_id, authorized_target)

    deadline = time.monotonic() + 5.0
    summary = None
    while time.monotonic() < deadline:
        summary = await orchestrator.get_status_summary(scan_id)
        if summary and summary.get("pending_interrupt"):
            break
        await asyncio.sleep(0.05)
    else:
        raise TimeoutError("Graph did not reach interrupt")

    assert summary is not None
    assert summary["pending_interrupt"]["node"] == "human_approval_gate"

    await orchestrator.resume_scan(scan_id, approved=True)
    await task

    final = await orchestrator.get_status_summary(scan_id)
    assert final is not None
    assert final["is_complete"] is True


@pytest.mark.asyncio
async def test_paused_scan_survives_restart_with_sqlite_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fast_scan_nodes: None,
) -> None:
    """A paused approval gate remains visible and resumable after restart."""
    checkpoints_db = tmp_path / "checkpoints.db"
    registry_db = tmp_path / "scan_registry.json"
    monkeypatch.setattr("agents.orchestrator._CHECKPOINT_DB", checkpoints_db)
    monkeypatch.setattr("agents.orchestrator._REGISTRY_DB", registry_db)

    scan_id = "restart-durable-scan"
    target = "https://authorized.example.com"
    owner_id = "api_key:tenant-a"

    orchestrator_a = ScanOrchestrator(use_sqlite=True)
    await orchestrator_a.setup()
    orchestrator_a.register_scan(scan_id, target, owner_id=owner_id)
    await orchestrator_a.start_scan(scan_id, target)
    paused_before = await orchestrator_a.get_status_summary(scan_id)
    await orchestrator_a.teardown()

    assert paused_before is not None
    assert paused_before["pending_interrupt"] is not None
    assert paused_before["status"] == "awaiting_approval"
    assert paused_before["is_complete"] is False
    assert registry_db.exists()

    orchestrator_b = ScanOrchestrator(use_sqlite=True)
    await orchestrator_b.setup()
    try:
        paused_after = await orchestrator_b.get_status_summary(scan_id)
        assert paused_after is not None
        assert paused_after["pending_interrupt"] is not None
        assert paused_after["status"] == "awaiting_approval"
        assert orchestrator_b.get_scan_owner(scan_id) == owner_id

        await orchestrator_b.resume_scan(scan_id, approved=True)
        completed = await orchestrator_b.get_status_summary(scan_id)
        assert completed is not None
        assert completed["is_complete"] is True
        assert completed["status"] == "completed"
    finally:
        await orchestrator_b.teardown()
