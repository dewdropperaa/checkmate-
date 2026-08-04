"""Shared retry helpers for tool execution."""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, TypeVar

from core.config import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T")

_RETRYABLE_MARKERS = (
    "timed out",
    "timeout",
    "connection",
    "temporarily",
    "reset by peer",
    "broken pipe",
    "resource temporarily unavailable",
    "exit code",
    "cancelled",
)

# Long-running / terminal failures that must not burn retry budget.
_NON_RETRYABLE_MARKERS = (
    "zap scan timed out",
    "zap unreachable",
    "zap unavailable",
    "active scanning skipped",
)


def is_retryable_error(message: str | None) -> bool:
    if not message:
        return False
    lower = message.lower()
    if any(marker in lower for marker in _NON_RETRYABLE_MARKERS):
        return False
    return any(marker in lower for marker in _RETRYABLE_MARKERS)


async def run_with_retries(
    tool_name: str,
    factory: Callable[[], Awaitable[T]],
    *,
    max_attempts: int | None = None,
    backoff_seconds: float | None = None,
) -> T:
    """Run an async callable with exponential backoff on transient errors."""
    settings = get_settings()
    attempts = max_attempts if max_attempts is not None else settings.tool_retry_attempts
    backoff = (
        backoff_seconds
        if backoff_seconds is not None
        else settings.tool_retry_backoff_seconds
    )

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return await factory()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_error = exc
            # AssertionError and some stdlib errors stringify to "" — always
            # include the type so logs/coverage stay actionable.
            exc_label = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            retryable = is_retryable_error(str(exc)) or is_retryable_error(exc_label)
            if attempt >= attempts or not retryable:
                logger.error(
                    "%s failed after %s attempt(s): %s",
                    tool_name,
                    attempt,
                    exc_label,
                    exc_info=True,
                )
                raise
            delay = backoff * (2 ** (attempt - 1))
            logger.warning(
                "%s attempt %s/%s failed (%s); retrying in %.1fs",
                tool_name,
                attempt,
                attempts,
                exc_label,
                delay,
            )
            await asyncio.sleep(delay)

    assert last_error is not None
    raise last_error
