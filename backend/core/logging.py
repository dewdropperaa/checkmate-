"""Structured JSON logging with per-request correlation IDs."""

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from core.config import get_settings

request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get() or None,
        }
        for key in (
            "scan_id",
            "org_id",
            "target",
            "node",
            "event",
            "client_id",
            "error_code",
            "provider",
            "model",
            "reason",
            "error",
            "retryable",
        ):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    settings = get_settings()
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())


def new_request_id() -> str:
    return str(uuid.uuid4())


def bind_request_id(request_id: str | None = None) -> str:
    rid = request_id or new_request_id()
    request_id_var.set(rid)
    return rid


def get_request_id() -> str:
    return request_id_var.get()


def log_node_transition(scan_id: str, node: str, **fields: Any) -> None:
    """Emit structured log for LangGraph node transitions."""
    logger = logging.getLogger("agents.orchestrator")
    extra = {"scan_id": scan_id, "node": node, "event": "node_transition", **fields}
    logger.info("node_transition %s", json.dumps(extra, default=str), extra=extra)


def log_scan_event(
    scan_id: str,
    event: str,
    *,
    level: int = logging.INFO,
    **fields: Any,
) -> None:
    """Emit a structured scan lifecycle event suitable for alerting."""
    logger = logging.getLogger("scan.lifecycle")
    extra = {"scan_id": scan_id, "event": event, **fields}
    logger.log(level, "scan_event %s", json.dumps(extra, default=str), extra=extra)
