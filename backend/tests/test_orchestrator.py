"""LangGraph orchestrator integration tests."""

import asyncio
import time

import pytest

from agents.orchestrator import ScanOrchestrator, build_scan_graph, create_checkpointer
from core.config import get_settings


@pytest.fixture
def orchestrator() -> ScanOrchestrator:
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
        "plan_active_tests",
        "human_approval_gate",
        "detection",
        "scoring",
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
async def test_graph_rejection_skips_detection(
    orchestrator: ScanOrchestrator,
    authorized_target: str,
) -> None:
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
    assert final["findings_count"] == 0
    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    assert snapshot.values.get("report", {}).get("outcome") == "rejected"


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
