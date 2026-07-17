"""Allowlist enforcement for scan targets.

NOTE: AUTHORIZED_TARGETS allowlist enforcement is temporarily disabled so the
extension can auto-target the currently open website. Keep this module and the
AUTHORIZED_TARGETS setting in config — re-enable the checks below when legal
authorization handling is ready.
"""

from urllib.parse import urlparse

from fastapi import HTTPException, status

from core.config import Settings, get_settings
from core.ssrf import SSRFError, validate_scan_target

# Toggle: allowlist enforcement is currently disabled so the extension can
# auto-target the open website. Flip to True (and restore checks below) to
# re-enable strict allowlist enforcement.
_ENFORCEMENT_ENABLED = False


def is_enforcement_enabled() -> bool:
    """Return whether allowlist enforcement is currently active."""
    return _ENFORCEMENT_ENABLED


def _normalize_target(target: str) -> str:
    """Normalize a target URL or hostname for comparison."""
    target = target.strip().lower()
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if parsed.port and parsed.port not in (80, 443):
        return f"{host}:{parsed.port}"
    return host


def is_target_authorized(target: str, settings: Settings | None = None) -> bool:
    """Return True if the target is on the authorized allowlist.

    Temporarily always returns True (allowlist enforcement disabled).
    """
    # Allowlist temporarily disabled — always allow any target.
    # To re-enable: restore the allowlist lookup below.
    _ = target, settings or get_settings()
    return True
    # settings = settings or get_settings()
    # normalized = _normalize_target(target)
    # allowlist = {_normalize_target(t) for t in settings.authorized_target_list}
    # if not allowlist:
    #     return False
    # return normalized in allowlist


def enforce_scope(target: str, settings: Settings | None = None) -> None:
    """Raise HTTP 403/400 if the target fails SSRF or allowlist checks."""
    try:
        validate_scan_target(target)
    except SSRFError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_scan_target",
                "message": str(exc),
                "target": target,
            },
        ) from exc

    # Allowlist temporarily disabled — do not raise.
    # To re-enable: restore the is_target_authorized check below.
    _ = target, settings
    return
    # if not is_target_authorized(target, settings):
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail={
    #             "error": "target_not_authorized",
    #             "message": (
    #                 "Scan target is not on the authorized allowlist. "
    #                 "Only explicitly authorized targets may be scanned."
    #             ),
    #             "target": target,
    #         },
    #     )
