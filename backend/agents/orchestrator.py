"""LangGraph multi-agent scan orchestrator."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from agents.detection import run_detection_async
from agents.recon import run_recon_async
from agents.reporting import run_reporting
from agents.scoring import run_scoring
from agents.state import ScanState
from agents.verification import run_verification_async
from core.logging import log_node_transition
from core.scope import is_target_authorized

logger = logging.getLogger(__name__)

# Active/intrusive tools that require human approval before execution.
_INTRUSIVE_TOOLS = ("sqlmap", "zap_active_scan")

_CHECKPOINT_DB = Path(__file__).resolve().parent.parent / "data" / "checkpoints.db"


def _build_initial_state(scan_id: str, target: str) -> ScanState:
    return ScanState(
        scan_id=scan_id,
        target=target,
        scope={"target": target},
        authorized=False,
        recon_results={},
        planned_active_tests=[],
        findings=[],
        severity_scores={},
        report=None,
        status="pending",
        human_approval_needed=False,
        human_approved=False,
    )


def _node_check_scope(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "check_scope", target=state["target"])
    authorized = is_target_authorized(state["target"])
    if not authorized:
        logger.warning(
            "Scope check failed in graph",
            extra={"scan_id": state["scan_id"], "target": state["target"]},
        )
        return {"authorized": False, "status": "failed"}
    return {"authorized": True, "status": "running"}


async def _node_recon(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "recon")
    return await run_recon_async(state)


def _node_plan_active_tests(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "plan_active_tests")
    planned = list(_INTRUSIVE_TOOLS)
    return {
        "planned_active_tests": planned,
        "human_approval_needed": True,
        "status": "awaiting_approval",
    }


def _node_human_approval_gate(state: ScanState) -> dict[str, Any]:
    log_node_transition(
        state["scan_id"],
        "human_approval_gate",
        planned_active_tests=state.get("planned_active_tests", []),
    )
    decision = interrupt(
        {
            "scan_id": state["scan_id"],
            "target": state["target"],
            "planned_active_tests": state.get("planned_active_tests", []),
            "message": (
                "Active/intrusive tests require human approval before execution."
            ),
        }
    )
    approved = bool(decision.get("approved", False))
    return {
        "human_approved": approved,
        "status": "running" if approved else "rejected",
    }


async def _node_detection(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "detection")
    return await run_detection_async(state)


async def _node_verification(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "verification")
    return await run_verification_async(state)


def _node_scoring(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "scoring")
    return run_scoring(state)


def _node_reporting(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "reporting")
    return run_reporting(state)


def _route_after_scope(state: ScanState) -> Literal["recon", "__end__"]:
    if state.get("authorized"):
        return "recon"
    return "__end__"


def _route_after_approval(state: ScanState) -> Literal["detection", "reporting"]:
    if state.get("human_approved"):
        return "detection"
    return "reporting"


def build_scan_graph() -> StateGraph:
    """Construct the scan StateGraph (uncompiled)."""
    graph = StateGraph(ScanState)

    graph.add_node("check_scope", _node_check_scope)
    graph.add_node("recon", _node_recon)
    graph.add_node("plan_active_tests", _node_plan_active_tests)
    graph.add_node("human_approval_gate", _node_human_approval_gate)
    graph.add_node("detection", _node_detection)
    graph.add_node("verification", _node_verification)
    graph.add_node("scoring", _node_scoring)
    graph.add_node("reporting", _node_reporting)

    graph.add_edge(START, "check_scope")
    graph.add_conditional_edges(
        "check_scope",
        _route_after_scope,
        {"recon": "recon", "__end__": END},
    )
    graph.add_edge("recon", "plan_active_tests")
    graph.add_edge("plan_active_tests", "human_approval_gate")
    graph.add_conditional_edges(
        "human_approval_gate",
        _route_after_approval,
        {"detection": "detection", "reporting": "reporting"},
    )
    graph.add_edge("detection", "verification")
    graph.add_edge("verification", "scoring")
    graph.add_edge("scoring", "reporting")
    graph.add_edge("reporting", END)

    return graph


def create_checkpointer(*, use_sqlite: bool = True) -> MemorySaver:
    """Create an in-memory checkpointer (used in tests)."""
    if use_sqlite:
        logger.warning(
            "Sync create_checkpointer(use_sqlite=True) is deprecated; "
            "use ScanOrchestrator.setup() for Sqlite persistence."
        )
    return MemorySaver()


class ScanOrchestrator:
    """Runs and inspects LangGraph scan workflows."""

    def __init__(self, *, use_sqlite: bool = True) -> None:
        self._use_sqlite = use_sqlite
        self._checkpointer: Any = None
        self._checkpointer_cm: Any = None
        self._graph = None
        self._registry: dict[str, dict[str, Any]] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

        if not use_sqlite:
            self._checkpointer = MemorySaver()
            self._graph = build_scan_graph().compile(checkpointer=self._checkpointer)

    async def setup(self) -> None:
        """Initialize async sqlite checkpointer for production."""
        if self._graph is not None:
            return
        if self._use_sqlite:
            from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

            _CHECKPOINT_DB.parent.mkdir(parents=True, exist_ok=True)
            self._checkpointer_cm = AsyncSqliteSaver.from_conn_string(str(_CHECKPOINT_DB))
            self._checkpointer = await self._checkpointer_cm.__aenter__()
        else:
            self._checkpointer = MemorySaver()
        self._graph = build_scan_graph().compile(checkpointer=self._checkpointer)

    async def teardown(self) -> None:
        if self._checkpointer_cm is not None:
            await self._checkpointer_cm.__aexit__(None, None, None)
            self._checkpointer_cm = None

    def _ensure_graph(self) -> None:
        if self._graph is None:
            raise RuntimeError("ScanOrchestrator is not initialized; call setup() first")

    @property
    def graph(self):
        self._ensure_graph()
        return self._graph

    def _config(self, scan_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": scan_id}}

    def register_scan(self, scan_id: str, target: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._registry[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "created_at": now,
            "updated_at": now,
        }

    def get_registered_target(self, scan_id: str) -> str | None:
        record = self._registry.get(scan_id)
        return record["target"] if record else None

    def _touch(self, scan_id: str) -> None:
        if scan_id in self._registry:
            self._registry[scan_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    async def start_scan(self, scan_id: str, target: str) -> None:
        """Run the graph asynchronously until completion or human-approval interrupt."""
        self._ensure_graph()
        self.register_scan(scan_id, target)
        config = self._config(scan_id)
        initial = _build_initial_state(scan_id, target)
        log_node_transition(scan_id, "graph_start", target=target)
        try:
            await self._graph.ainvoke(initial, config)
        except Exception as e:
            logger.exception(
                "Scan %s failed with unhandled error: %s", scan_id, e
            )
        finally:
            self._touch(scan_id)

    def schedule_scan(self, scan_id: str, target: str) -> asyncio.Task[None]:
        task = asyncio.create_task(self.start_scan(scan_id, target))
        self._tasks[scan_id] = task
        return task

    async def resume_scan(self, scan_id: str, *, approved: bool) -> None:
        """Resume past the human-approval interrupt."""
        self._ensure_graph()
        config = self._config(scan_id)
        log_node_transition(
            scan_id,
            "human_approval_resume",
            approved=approved,
        )
        await self._graph.ainvoke(
            Command(resume={"approved": approved}),
            config,
        )
        self._touch(scan_id)

    async def get_graph_snapshot(self, scan_id: str) -> Any:
        self._ensure_graph()
        return await self._graph.aget_state(self._config(scan_id))

    async def get_status_summary(self, scan_id: str) -> dict[str, Any] | None:
        record = self._registry.get(scan_id)
        if record is None:
            return None

        try:
            snapshot = await self.get_graph_snapshot(scan_id)
        except Exception as e:
            logger.warning(
                "Failed to get graph snapshot for scan %s: %s",
                scan_id,
                e,
            )
            return {
                "scan_id": scan_id,
                "target": record["target"],
                "status": "pending",
                "authorized": False,
                "current_node": None,
                "next_nodes": [],
                "human_approval_needed": False,
                "human_approved": False,
                "pending_interrupt": None,
                "findings_count": 0,
                "is_complete": False,
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
            }

        if snapshot is None or not hasattr(snapshot, "values"):
            return {
                "scan_id": scan_id,
                "target": record["target"],
                "status": "pending",
                "authorized": False,
                "current_node": None,
                "next_nodes": [],
                "human_approval_needed": False,
                "human_approved": False,
                "pending_interrupt": None,
                "findings_count": 0,
                "is_complete": False,
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
            }

        values = dict(snapshot.values) if snapshot.values else {}
        next_nodes = list(snapshot.next) if snapshot.next else []

        pending_interrupt: dict[str, Any] | None = None
        if snapshot.tasks:
            for task in snapshot.tasks:
                if task.interrupts:
                    pending_interrupt = {
                        "node": task.name,
                        "value": task.interrupts[0].value,
                    }
                    break

        current_node = next_nodes[0] if next_nodes else None
        if pending_interrupt:
            current_node = pending_interrupt["node"]

        is_complete = not next_nodes and pending_interrupt is None
        if not values:
            is_complete = False

        return {
            "scan_id": scan_id,
            "target": record["target"],
            "status": values.get("status", "pending"),
            "authorized": values.get("authorized", False),
            "current_node": current_node,
            "next_nodes": next_nodes,
            "human_approval_needed": values.get("human_approval_needed", False),
            "human_approved": values.get("human_approved", False),
            "pending_interrupt": pending_interrupt,
            "findings_count": len(values.get("findings", [])),
            "is_complete": is_complete,
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }


_orchestrator: ScanOrchestrator | None = None


def get_orchestrator() -> ScanOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator(use_sqlite=True)
    return _orchestrator


def reset_orchestrator(*, use_sqlite: bool = False) -> ScanOrchestrator:
    """Replace the global orchestrator (used in tests)."""
    global _orchestrator
    _orchestrator = ScanOrchestrator(use_sqlite=use_sqlite)
    return _orchestrator
