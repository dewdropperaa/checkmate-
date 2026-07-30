"""LangGraph multi-agent scan orchestrator."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from agents.ai_synthesis import run_ai_synthesis
from agents.detection import (
    run_active_detection_async,
    run_passive_detection_async,
)
from agents.recon import run_recon_async
from agents.reporting import run_reporting
from agents.scoring import run_scoring
from agents.state import ScanState
from agents.verification import run_verification_async
from core.config import get_settings
from core.logging import log_node_transition, log_scan_event
from core.scope import is_target_authorized
from core.ssrf import SSRFError, validate_scan_target

logger = logging.getLogger(__name__)

# Active/intrusive tools that require human approval before execution.
_INTRUSIVE_TOOLS = ("sqlmap", "zap")

_CHECKPOINT_DB = Path(__file__).resolve().parent.parent / "data" / "checkpoints.db"
_REGISTRY_DB = Path(__file__).resolve().parent.parent / "data" / "scan_registry.json"


def _build_initial_state(
    scan_id: str,
    target: str,
    *,
    org_id: str | None = None,
    site_id: str | None = None,
) -> ScanState:
    from core.auth_scan import build_public_auth_meta

    auth_meta = build_public_auth_meta(
        org_id=org_id,
        site_id=site_id,
        target=target,
    )
    return ScanState(
        scan_id=scan_id,
        target=target,
        scope={"target": target, "excluded_paths": list(auth_meta.excluded_paths)},
        authorized=False,
        recon_results={},
        planned_active_tests=[],
        findings=[],
        severity_scores={},
        ai_synthesis={},
        report=None,
        status="pending",
        human_approval_needed=False,
        human_approved=False,
        approved_tools=[],
        rejected_tools=[],
        org_id=org_id or "",
        site_id=site_id or "",
        auth_scan=auth_meta.to_state_dict(),
    )


def resolve_approved_tools(
    planned: list[str],
    *,
    approved: bool = False,
    approved_tools: list[str] | None = None,
) -> list[str]:
    """Resolve which planned active/intrusive tools a reviewer approved.

    Per-tool selection (`approved_tools`) takes precedence when the caller
    provides it explicitly, e.g. approving sqlmap while rejecting zap.
    Unknown tool names are silently dropped and the result preserves the
    order of `planned`. When `approved_tools` is omitted entirely (None),
    this falls back to the legacy bulk `approved` flag, which approves every
    planned tool or none, for backward compatibility with older clients.
    """
    if approved_tools is not None:
        requested = {str(t).strip().lower() for t in approved_tools if str(t).strip()}
        return [tool for tool in planned if tool in requested]
    return list(planned) if approved else []


def _node_check_scope(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "check_scope", target=state["target"])
    try:
        validate_scan_target(state["target"])
    except SSRFError as exc:
        logger.warning(
            "SSRF check failed in graph",
            extra={"scan_id": state["scan_id"], "target": state["target"]},
        )
        return {
            "authorized": False,
            "status": "failed",
            "error": {
                "code": "invalid_scan_target",
                "message": str(exc),
            },
        }
    authorized = is_target_authorized(state["target"])
    if not authorized:
        logger.warning(
            "Scope check failed in graph",
            extra={"scan_id": state["scan_id"], "target": state["target"]},
        )
        return {
            "authorized": False,
            "status": "failed",
            "error": {
                "code": "target_not_authorized",
                "message": (
                    "Scan target is not on the authorized allowlist. "
                    "Only explicitly authorized targets may be scanned."
                ),
            },
        }
    return {"authorized": True, "status": "running"}


async def _node_recon(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "recon")
    return await run_recon_async(state)


def _node_plan_active_tests(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "plan_active_tests")
    settings = get_settings()
    if settings.cloud_scan_profile == "firecrawl":
        return {
            "planned_active_tests": [],
            "human_approval_needed": False,
            "status": "running",
        }
    planned = list(_INTRUSIVE_TOOLS)
    return {
        "planned_active_tests": planned,
        "human_approval_needed": True,
        "status": "awaiting_approval",
    }


def _node_human_approval_gate(state: ScanState) -> dict[str, Any]:
    planned = list(state.get("planned_active_tests", []))
    auth_scan = dict(state.get("auth_scan") or {})
    excluded = list(
        auth_scan.get("excluded_paths")
        or (state.get("recon_results") or {}).get("excluded_paths")
        or []
    )
    log_node_transition(
        state["scan_id"],
        "human_approval_gate",
        planned_active_tests=planned,
    )
    interrupt_payload: dict[str, Any] = {
        "scan_id": state["scan_id"],
        "target": state["target"],
        "planned_active_tests": planned,
        "message": (
            "Active/intrusive tests require human approval before execution. "
            "Approve or reject each tool individually, or approve/reject all."
        ),
    }
    if auth_scan.get("configured") and auth_scan.get("enabled"):
        interrupt_payload["authenticated_scanning"] = {
            "enabled": True,
            "username_hint": auth_scan.get("username_hint"),
            "excluded_paths": excluded,
            "message": (
                f"Authenticated scan will run as: {auth_scan.get('username_hint')}. "
                f"Excluded destructive paths: {', '.join(excluded) or '(none)'}."
            ),
        }
    elif auth_scan.get("configured") and not auth_scan.get("enabled"):
        interrupt_payload["authenticated_scanning"] = {
            "enabled": False,
            "username_hint": auth_scan.get("username_hint"),
            "excluded_paths": excluded,
            "fallback_reason": auth_scan.get("fallback_reason"),
            "warnings": list(auth_scan.get("warnings") or []),
            "message": (
                "Credentials are stored but authenticated scanning is disabled "
                f"({auth_scan.get('fallback_reason') or 'unavailable'}). "
                "Active tests would run as an unauthenticated visitor."
            ),
        }
    decision = interrupt(interrupt_payload)
    decision = decision if isinstance(decision, dict) else {}
    approved_tools = resolve_approved_tools(
        planned,
        approved=bool(decision.get("approved", False)),
        approved_tools=decision.get("approved_tools"),
    )
    rejected_tools = [tool for tool in planned if tool not in approved_tools]
    human_approved = bool(approved_tools)
    log_node_transition(
        state["scan_id"],
        "human_approval_gate",
        approved_tools=approved_tools,
        rejected_tools=rejected_tools,
    )
    return {
        "human_approved": human_approved,
        "approved_tools": approved_tools,
        "rejected_tools": rejected_tools,
        "status": "running" if human_approved else "rejected",
    }


async def _node_passive_detection(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "passive_detection")
    return await run_passive_detection_async(state)


async def _node_active_detection(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "active_detection")
    return await run_active_detection_async(state)


async def _node_verification(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "verification")
    return await run_verification_async(state)


def _node_scoring(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "scoring")
    return run_scoring(state)


def _node_ai_synthesis(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "ai_synthesis")
    try:
        return run_ai_synthesis(state)
    except Exception as exc:  # noqa: BLE001 — never block reporting on AI failure
        logger.exception(
            "ai_synthesis_unhandled",
            extra={"scan_id": state["scan_id"], "event": "ai_synthesis_unhandled"},
        )
        coverage = dict((state.get("severity_scores") or {}).get("scan_coverage") or {})
        coverage.update(
            {
                "ai_synthesis_status": "unavailable",
                "ai_synthesis_provider": "none",
                "ai_synthesis_provider_role": "none",
                "ai_synthesis_fallback_reason": "unhandled_exception",
            }
        )
        scores = dict(state.get("severity_scores") or {})
        scores["scan_coverage"] = coverage
        return {
            "severity_scores": scores,
            "ai_synthesis": {
                "status": "unavailable",
                "provider": "none",
                "provider_role": "none",
                "fallback_reason": "unhandled_exception",
                "error": str(exc),
                "executive_summary": None,
                "remediation_roadmap": None,
                "config_fixes": [],
            },
            "status": state.get("status") or "scored",
        }


def _node_reporting(state: ScanState) -> dict[str, Any]:
    log_node_transition(state["scan_id"], "reporting")
    return run_reporting(state)


def _route_after_scope(state: ScanState) -> Literal["recon", "reporting"]:
    if state.get("authorized"):
        return "recon"
    return "reporting"


def _route_after_approval(state: ScanState) -> Literal["active_detection"]:
    # Always visit active_detection; it no-ops when approval was denied.
    return "active_detection"


def _route_after_plan_active_tests(
    state: ScanState,
) -> Literal["human_approval_gate", "active_detection"]:
    if state.get("planned_active_tests"):
        return "human_approval_gate"
    return "active_detection"


def build_scan_graph() -> StateGraph:
    """Construct the scan StateGraph (uncompiled)."""
    graph = StateGraph(ScanState)

    graph.add_node("check_scope", _node_check_scope)
    graph.add_node("recon", _node_recon)
    graph.add_node("passive_detection", _node_passive_detection)
    graph.add_node("plan_active_tests", _node_plan_active_tests)
    graph.add_node("human_approval_gate", _node_human_approval_gate)
    graph.add_node("active_detection", _node_active_detection)
    graph.add_node("verification", _node_verification)
    graph.add_node("scoring", _node_scoring)
    graph.add_node("ai_synthesis", _node_ai_synthesis)
    graph.add_node("reporting", _node_reporting)

    graph.add_edge(START, "check_scope")
    graph.add_conditional_edges(
        "check_scope",
        _route_after_scope,
        {"recon": "recon", "reporting": "reporting"},
    )
    graph.add_edge("recon", "passive_detection")
    graph.add_edge("passive_detection", "plan_active_tests")
    graph.add_conditional_edges(
        "plan_active_tests",
        _route_after_plan_active_tests,
        {
            "human_approval_gate": "human_approval_gate",
            "active_detection": "active_detection",
        },
    )
    graph.add_conditional_edges(
        "human_approval_gate",
        _route_after_approval,
        {"active_detection": "active_detection"},
    )
    graph.add_edge("active_detection", "verification")
    graph.add_edge("verification", "scoring")
    graph.add_edge("scoring", "ai_synthesis")
    graph.add_edge("ai_synthesis", "reporting")
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
        self._load_registry()

    async def teardown(self) -> None:
        if self._checkpointer_cm is not None:
            await self._checkpointer_cm.__aexit__(None, None, None)
            self._checkpointer_cm = None

    async def recover_stale_scans(self) -> list[str]:
        """Resolve orphaned in-progress scan rows left by a service restart."""
        from core.accounts import list_stale_active_scans, update_scan_record

        settings = get_settings()
        cutoff = (
            datetime.now(timezone.utc)
            - timedelta(seconds=float(settings.scan_timeout_seconds))
        ).isoformat()
        recovered: list[str] = []
        for record in list_stale_active_scans(older_than_iso=cutoff):
            self.register_scan(record.id, record.target, owner_id=f"org:{record.org_id}")
            await self._finalize_failed_scan(
                record.id,
                record.target,
                error_code="service_restart_interrupted",
                message=(
                    "The scan was interrupted by a service restart and could not be "
                    "safely resumed from its last checkpoint."
                ),
            )
            update_scan_record(
                record.id,
                status="failed",
                current_node=record.current_node,
            )
            recovered.append(record.id)
        return recovered

    def _ensure_graph(self) -> None:
        if self._graph is None:
            raise RuntimeError("ScanOrchestrator is not initialized; call setup() first")

    @property
    def graph(self):
        self._ensure_graph()
        return self._graph

    def _config(self, scan_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": scan_id}}

    def register_scan(
        self,
        scan_id: str,
        target: str,
        *,
        owner_id: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        existing = self._registry.get(scan_id)
        self._registry[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "owner_id": owner_id if owner_id is not None else (
                existing.get("owner_id") if existing else None
            ),
            "created_at": existing["created_at"] if existing else now,
            "updated_at": now,
        }
        self._persist_registry()

    def get_scan_owner(self, scan_id: str) -> str | None:
        record = self._registry.get(scan_id)
        if record is None:
            return None
        return record.get("owner_id")

    def get_registered_target(self, scan_id: str) -> str | None:
        record = self._registry.get(scan_id)
        return record["target"] if record else None

    def _touch(self, scan_id: str) -> None:
        if scan_id in self._registry:
            self._registry[scan_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._persist_registry()

    def _load_registry(self) -> None:
        if not _REGISTRY_DB.exists():
            return
        try:
            data = json.loads(_REGISTRY_DB.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("scan_registry.json unreadable; starting with empty registry")
            return
        if not isinstance(data, dict):
            return

        loaded: dict[str, dict[str, Any]] = {}
        for scan_id, entry in data.items():
            if not isinstance(scan_id, str) or not isinstance(entry, dict):
                continue
            target = entry.get("target")
            created_at = entry.get("created_at")
            updated_at = entry.get("updated_at")
            if not isinstance(target, str):
                continue
            loaded[scan_id] = {
                "scan_id": scan_id,
                "target": target,
                "owner_id": (
                    entry.get("owner_id")
                    if isinstance(entry.get("owner_id"), str) or entry.get("owner_id") is None
                    else None
                ),
                "created_at": created_at if isinstance(created_at, str) else datetime.now(timezone.utc).isoformat(),
                "updated_at": updated_at if isinstance(updated_at, str) else datetime.now(timezone.utc).isoformat(),
            }
        self._registry = loaded

    def _persist_registry(self) -> None:
        # Best-effort durability for ownership metadata so paused scans remain
        # addressable after API restarts while checkpoints still exist.
        try:
            _REGISTRY_DB.parent.mkdir(parents=True, exist_ok=True)
            _REGISTRY_DB.write_text(
                json.dumps(self._registry, indent=2),
                encoding="utf-8",
            )
        except OSError:
            logger.warning("Failed to persist scan registry", exc_info=True)

    async def start_scan(
        self,
        scan_id: str,
        target: str,
        *,
        org_id: str | None = None,
        site_id: str | None = None,
    ) -> None:
        """Run the graph asynchronously until completion or human-approval interrupt."""
        self._ensure_graph()
        self.register_scan(scan_id, target)
        config = self._config(scan_id)
        initial = _build_initial_state(
            scan_id, target, org_id=org_id, site_id=site_id
        )
        log_node_transition(scan_id, "graph_start", target=target)
        settings = get_settings()
        try:
            await asyncio.wait_for(
                self._graph.ainvoke(initial, config),
                timeout=settings.scan_timeout_seconds,
            )
        except asyncio.TimeoutError:
            log_scan_event(
                scan_id,
                "scan_timeout",
                level=logging.ERROR,
                target=target,
                timeout_seconds=settings.scan_timeout_seconds,
            )
            await self._finalize_failed_scan(
                scan_id,
                target,
                error_code="scan_timeout",
                message=(
                    "The scan timed out before completing. "
                    "Please try again later."
                ),
            )
        except Exception as e:
            log_scan_event(
                scan_id,
                "scan_unhandled_error",
                level=logging.ERROR,
                target=target,
                error_type=type(e).__name__,
            )
            logger.exception(
                "Scan %s failed with unhandled error: %s", scan_id, e
            )
            await self._finalize_failed_scan(
                scan_id,
                target,
                error_code="scan_error",
                message=(
                    "The scan failed due to an unexpected error. "
                    "Please try again later."
                ),
            )
        finally:
            self._touch(scan_id)

    async def _finalize_failed_scan(
        self,
        scan_id: str,
        target: str,
        *,
        error_code: str,
        message: str,
    ) -> None:
        """Write a failed scan report when the graph cannot complete normally."""
        config = self._config(scan_id)
        try:
            snapshot = await self.get_graph_snapshot(scan_id)
            state: ScanState = (
                dict(snapshot.values)
                if snapshot and snapshot.values
                else _build_initial_state(scan_id, target)
            )
        except Exception:
            state = _build_initial_state(scan_id, target)

        state["status"] = "failed"
        state["error"] = {"code": error_code, "message": message}
        report_result = run_reporting(state)
        merged = {**state, **report_result}
        try:
            await self._graph.aupdate_state(config, merged, as_node="reporting")
        except Exception:
            logger.exception(
                "Failed to persist failed scan state for %s", scan_id
            )

    def schedule_scan(
        self,
        scan_id: str,
        target: str,
        *,
        org_id: str | None = None,
        site_id: str | None = None,
    ) -> asyncio.Task[None]:
        task = asyncio.create_task(
            self.start_scan(scan_id, target, org_id=org_id, site_id=site_id)
        )
        self._tasks[scan_id] = task
        return task

    async def resume_scan(
        self,
        scan_id: str,
        *,
        approved: bool,
        approved_tools: list[str] | None = None,
    ) -> None:
        """Resume past the human-approval interrupt and run to completion.

        `approved_tools`, when provided, selects individual planned tools to
        run (e.g. sqlmap but not zap) and takes precedence over the legacy
        bulk `approved` flag, which is kept for backward compatibility and
        approves/rejects every planned tool at once.

        This awaits the remaining pipeline (active detection, verification,
        scoring, reporting), so it can take a long time. HTTP callers should
        prefer :meth:`schedule_resume` to avoid blocking the request while the
        scan finishes; use this directly only when you need to await the result
        (e.g. in tests).
        """
        self._ensure_graph()
        config = self._config(scan_id)
        target = self.get_registered_target(scan_id) or ""
        log_node_transition(
            scan_id,
            "human_approval_resume",
            approved=approved,
            approved_tools=approved_tools,
        )
        settings = get_settings()
        resume_payload: dict[str, Any] = {"approved": approved}
        if approved_tools is not None:
            resume_payload["approved_tools"] = approved_tools
        try:
            await asyncio.wait_for(
                self._graph.ainvoke(
                    Command(resume=resume_payload),
                    config,
                ),
                timeout=settings.scan_timeout_seconds,
            )
        except asyncio.TimeoutError:
            log_scan_event(
                scan_id,
                "scan_timeout",
                level=logging.ERROR,
                target=target,
                timeout_seconds=settings.scan_timeout_seconds,
            )
            await self._finalize_failed_scan(
                scan_id,
                target,
                error_code="scan_timeout",
                message=(
                    "The scan timed out before completing. "
                    "Please try again later."
                ),
            )
        except Exception as e:
            log_scan_event(
                scan_id,
                "scan_unhandled_error",
                level=logging.ERROR,
                target=target,
                error_type=type(e).__name__,
            )
            logger.exception(
                "Scan %s failed during resume: %s", scan_id, e
            )
            await self._finalize_failed_scan(
                scan_id,
                target,
                error_code="scan_error",
                message=(
                    "The scan failed due to an unexpected error. "
                    "Please try again later."
                ),
            )
        finally:
            self._touch(scan_id)

    def schedule_resume(
        self,
        scan_id: str,
        *,
        approved: bool,
        approved_tools: list[str] | None = None,
    ) -> asyncio.Task[None]:
        """Resume the scan in the background so the caller returns immediately."""
        task = asyncio.create_task(
            self.resume_scan(scan_id, approved=approved, approved_tools=approved_tools)
        )
        self._tasks[scan_id] = task
        return task

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
                "approved_tools": [],
                "rejected_tools": [],
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
                "approved_tools": [],
                "rejected_tools": [],
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
            "approved_tools": values.get("approved_tools", []),
            "rejected_tools": values.get("rejected_tools", []),
            "pending_interrupt": pending_interrupt,
            "findings_count": len(values.get("findings", [])),
            "is_complete": is_complete,
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "error": values.get("error"),
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
