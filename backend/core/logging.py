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
    payload = {"scan_id": scan_id, "node": node, "event": "node_transition", **fields}
    logger.info("node_transition %s", json.dumps(payload, default=str))
