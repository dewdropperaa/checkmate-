"""OWASP ZAP active scanner integration via REST API.

ZAP is an active scanner that performs intrusive security testing.
This wrapper drives ZAP via its REST API (assuming ZAP daemon is running).

ACTIVE TOOL - REQUIRES HUMAN APPROVAL BEFORE EXECUTION

Security considerations:
- Active scanner - performs intrusive tests that may modify application state
- MUST only run with explicit human approval
- Scope re-validated before each scan
- Polls for completion and retrieves alerts
- Shared ZAP daemon: each scan uses an isolated session and tears it down
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

from core.config import get_settings
from core.logging import log_scan_event
from core.scope import is_target_authorized
from tools.base import ScopeViolationError, ToolResult, validate_scope
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

# Distinct observability events (match ai_synthesis / scan.lifecycle style).
EVENT_ZAP_UNREACHABLE = "zap_unreachable"
EVENT_ZAP_SCAN_TIMEOUT = "zap_scan_timeout"
EVENT_ZAP_SCAN_COMPLETED = "zap_scan_completed"
EVENT_ZAP_SCAN_FAILED = "zap_scan_failed"
EVENT_ZAP_SKIPPED_UNAVAILABLE = "zap_skipped_unavailable"

ZAP_UNAVAILABLE_COVERAGE_NOTE = (
    "ZAP unavailable, active scanning skipped"
)

ZAP_RISK_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

ZAP_CWE_MAP = {
    "Cross Site Scripting": 79,
    "SQL Injection": 89,
    "Path Traversal": 22,
    "Remote File Inclusion": 98,
    "Command Injection": 78,
    "LDAP Injection": 90,
    "XML External Entity": 611,
    "CSRF": 352,
    "Clickjacking": 1021,
    "CORS": 942,
    "HSTS": 319,
    "CSP": 693,
    "Cookie": 614,
    "X-Frame-Options": 1021,
    "X-Content-Type-Options": 16,
}

# Process-wide gate: ZAP is a shared stateful daemon — concurrent scans would
# race on session/context/site-tree state and risk cross-tenant leakage.
_zap_semaphore: asyncio.Semaphore | None = None
_zap_semaphore_limit: int | None = None


def _get_zap_semaphore() -> asyncio.Semaphore:
    global _zap_semaphore, _zap_semaphore_limit
    settings = get_settings()
    limit = max(1, int(getattr(settings, "zap_max_concurrent", 1) or 1))
    if _zap_semaphore is None or _zap_semaphore_limit != limit:
        _zap_semaphore = asyncio.Semaphore(limit)
        _zap_semaphore_limit = limit
    return _zap_semaphore


def reset_zap_semaphore_for_tests() -> None:
    """Reset the process-wide ZAP concurrency gate (tests only)."""
    global _zap_semaphore, _zap_semaphore_limit
    _zap_semaphore = None
    _zap_semaphore_limit = None


def _classify_zap_error(exc: BaseException) -> str:
    """Return zap_unreachable | zap_scan_timeout | zap_scan_failed."""
    if isinstance(exc, asyncio.TimeoutError):
        return EVENT_ZAP_SCAN_TIMEOUT
    message = str(exc).lower()
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.NetworkError)):
        return EVENT_ZAP_UNREACHABLE
    if any(
        marker in message
        for marker in (
            "connect",
            "unreachable",
            "name or service not known",
            "nodename nor servname",
            "connection refused",
            "network is unreachable",
        )
    ):
        return EVENT_ZAP_UNREACHABLE
    if "timed out" in message or "timeout" in message:
        return EVENT_ZAP_SCAN_TIMEOUT
    return EVENT_ZAP_SCAN_FAILED


def is_zap_unavailable_error(message: str | None) -> bool:
    """True when active scanning should be reported as ZAP-unavailable coverage."""
    if not message:
        return False
    lower = message.lower()
    return any(
        marker in lower
        for marker in (
            "zap unreachable",
            "zap unavailable",
            "connection refused",
            "connecterror",
            "connect timeout",
            "network is unreachable",
            "name or service not known",
        )
    ) and "timed out after" not in lower


class ZAPInput(BaseModel):
    """Input schema for ZAP tool with validation."""

    target: str = Field(
        ...,
        description="Target URL to scan (must be a full URL)",
    )
    scan_policy: str | None = Field(
        default=None,
        description="Optional scan policy name to use",
    )
    ajax_spider: bool = Field(
        default=False,
        description="Whether to use AJAX spider before active scan",
    )

    @field_validator("target")
    @classmethod
    def validate_target_in_scope(cls, v: str) -> str:
        """Ensure target is within the authorized scope."""
        parsed = urlparse(v)
        host = parsed.hostname or ""
        if not is_target_authorized(host):
            raise ValueError(
                f"Target '{v}' is not in the authorized scope. "
                "Scan aborted for safety."
            )
        return v


class ZAPAuthConfig(BaseModel):
    """Form-based auth parameters matching ZAP's built-in authentication API.

    Field names are HTML form ``name`` attributes (not CSS selectors), as
    required by ZAP ``formBasedAuthentication`` ``loginRequestData``.
    """

    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    context_name: str = "checkmate-auth"
    excluded_paths: list[str] = Field(default_factory=list)


class ZAPTool:
    """
    OWASP ZAP active scanner wrapper.

    Drives ZAP via REST API to perform active vulnerability scanning.

    ACTIVE TOOL - Requires human approval before execution.
    """

    name = "zap"
    description = "OWASP ZAP active vulnerability scanner"
    requires_approval = True

    def __init__(
        self,
        api_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        poll_interval: float | None = None,
    ):
        settings = get_settings()
        self.api_url = api_url or getattr(settings, "zap_api_url", "http://zap:8080")
        self.api_key = api_key if api_key is not None else getattr(settings, "zap_api_key", "")
        self.timeout = (
            timeout
            if timeout is not None
            else float(getattr(settings, "zap_timeout", 600.0))
        )
        self.poll_interval = (
            poll_interval
            if poll_interval is not None
            else float(getattr(settings, "zap_poll_interval", 5.0))
        )
        self._client: httpx.AsyncClient | None = None
        self._session_name: str | None = None
        self._context_names: list[str] = []

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                timeout=60.0,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _api_call(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an API call to ZAP. Attaches the API key on every request.

        Production refuses to call ZAP without a key. Development may omit it
        only when talking to a local daemon started with ``api.disablekey=true``
        (see ``scripts/start_zap.ps1``) — never ship that mode to production.
        """
        settings = get_settings()
        if not self.api_key and settings.app_env == "production":
            raise httpx.HTTPError(
                "ZAP_API_KEY is not configured; refusing to call ZAP without "
                "API key authentication"
            )
        client = await self._get_client()
        params = dict(params or {})
        if self.api_key:
            params["apikey"] = self.api_key

        response = await client.get(endpoint, params=params)
        response.raise_for_status()
        return response.json()

    async def probe_ready(self) -> tuple[bool, str | None]:
        """Lightweight readiness check against ZAP's version endpoint."""
        try:
            await self._api_call("/JSON/core/view/version/")
            return True, None
        except Exception as exc:
            return False, f"ZAP unreachable: {exc}"

    def _emit(self, event: str, *, scan_id: str | None = None, **fields: Any) -> None:
        sid = scan_id or fields.pop("correlation_id", None) or "zap"
        log_scan_event(sid, event, **fields)
        logger.log(
            logging.WARNING if event != EVENT_ZAP_SCAN_COMPLETED else logging.INFO,
            event,
            extra={"scan_id": sid, "event": event, **fields},
        )

    async def _begin_isolated_session(self) -> str:
        """Create a fresh ZAP session so prior tenants' site trees cannot leak in."""
        session_name = f"checkmate-{uuid.uuid4().hex}"
        await self._api_call(
            "/JSON/core/action/newSession/",
            {"name": session_name, "overwrite": "true"},
        )
        self._session_name = session_name
        logger.info("ZAP isolated session started: %s", session_name)
        return session_name

    async def _teardown_session(self) -> None:
        """Drop scan contexts and reset to a blank session to bound disk/state growth."""
        for context_name in list(self._context_names):
            try:
                await self._api_call(
                    "/JSON/context/action/removeContext/",
                    {"contextName": context_name},
                )
            except Exception as exc:
                logger.debug("ZAP removeContext(%s) failed: %s", context_name, exc)
        self._context_names.clear()

        # Disable forced-user mode leftover from authenticated scans.
        try:
            await self._api_call(
                "/JSON/forcedUser/action/setForcedUserModeEnabled/",
                {"boolean": "false"},
            )
        except Exception:
            pass

        # newSession clears the site tree / alerts / spider results for the next tenant.
        try:
            await self._api_call(
                "/JSON/core/action/newSession/",
                {"name": f"checkmate-idle-{uuid.uuid4().hex[:8]}", "overwrite": "true"},
            )
        except Exception as exc:
            logger.warning("ZAP session teardown failed: %s", exc)
        finally:
            self._session_name = None

    async def run(self, target: str, scope: dict[str, Any]) -> ToolResult:
        """
        Run ZAP active scan against a target.

        This method:
        1. Acquires the shared ZAP concurrency slot
        2. Creates an isolated ZAP session
        3. Optionally configures ZAP form-based authentication context
        4. Opens the target URL
        5. Runs spider to discover pages (respecting excluded paths)
        6. Runs active scan
        7. Waits for completion
        8. Retrieves and parses alerts
        9. Tears down the session/context (always)

        Args:
            target: Target URL to scan
            scope: Scope metadata with optional configuration. Auth secrets
                may be passed under ``scope["auth"]`` for this call only —
                they must never be persisted into ScanState.

        Returns:
            ToolResult with vulnerability findings
        """
        parsed = urlparse(target)
        host = parsed.hostname or ""
        validate_scope(host)

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        scan_policy = scope.get("scan_policy")
        ajax_spider = scope.get("ajax_spider", False)
        auth_cfg = scope.get("auth")
        excluded_paths = list(scope.get("excluded_paths") or [])
        if isinstance(auth_cfg, dict):
            excluded_paths = list(
                auth_cfg.get("excluded_paths") or excluded_paths
            )
        scan_id = str(scope.get("scan_id") or scope.get("correlation_id") or "unknown")

        auth_meta: dict[str, Any] = {
            "configured": bool(auth_cfg),
            "login_succeeded": None,
        }

        sem = _get_zap_semaphore()
        await sem.acquire()
        try:
            return await self._run_isolated(
                target=target,
                scan_policy=scan_policy,
                ajax_spider=ajax_spider,
                auth_cfg=auth_cfg,
                excluded_paths=excluded_paths,
                auth_meta=auth_meta,
                scan_id=scan_id,
            )
        finally:
            sem.release()

    async def _run_isolated(
        self,
        *,
        target: str,
        scan_policy: str | None,
        ajax_spider: bool,
        auth_cfg: Any,
        excluded_paths: list[str],
        auth_meta: dict[str, Any],
        scan_id: str,
    ) -> ToolResult:
        try:
            # Fail fast with a clear unavailable signal before starting work.
            ready, ready_err = await self.probe_ready()
            if not ready:
                self._emit(
                    EVENT_ZAP_UNREACHABLE,
                    scan_id=scan_id,
                    target=target,
                    error=ready_err,
                )
                return ToolResult(
                    tool_name=self.name,
                    target=target,
                    success=False,
                    error=ready_err or "ZAP unreachable",
                    data={
                        "auth": auth_meta,
                        "zap_event": EVENT_ZAP_UNREACHABLE,
                        "coverage_note": ZAP_UNAVAILABLE_COVERAGE_NOTE,
                    },
                )

            await self._begin_isolated_session()

            logger.info("Starting ZAP scan against %s", target)

            # Unique context name per scan — never reuse a shared org-agnostic name.
            context_suffix = uuid.uuid4().hex[:12]
            if isinstance(auth_cfg, dict):
                auth_cfg = {
                    **auth_cfg,
                    "context_name": f"checkmate-auth-{context_suffix}",
                }

            if auth_cfg:
                login_ok = await self.configure_form_authentication(
                    target=target,
                    auth_cfg=auth_cfg,
                    excluded_paths=excluded_paths,
                )
                auth_meta["login_succeeded"] = login_ok
                if not login_ok:
                    logger.warning(
                        "ZAP form authentication failed; continuing without "
                        "forced-user mode (scan may be unauthenticated)"
                    )

            # Exclude destructive paths from spider + active scan via ZAP context
            if excluded_paths:
                await self._apply_exclude_paths(
                    context_name=(
                        (auth_cfg or {}).get(
                            "context_name", f"checkmate-scope-{context_suffix}"
                        )
                        if auth_cfg
                        else f"checkmate-scope-{context_suffix}"
                    ),
                    target=target,
                    excluded_paths=excluded_paths,
                    ensure_context=not bool(auth_cfg),
                )

            await self._api_call("/JSON/core/action/accessUrl/", {"url": target})

            logger.info("Running ZAP spider...")
            spider_params: dict[str, Any] = {"url": target, "maxChildren": "100"}
            if auth_cfg:
                spider_params["contextName"] = auth_cfg.get("context_name")
            spider_result = await self._api_call(
                "/JSON/spider/action/scan/",
                spider_params,
            )
            spider_id = spider_result.get("scan", "0")

            await self._wait_for_spider(spider_id)

            if ajax_spider:
                logger.info("Running ZAP AJAX spider...")
                await self._api_call("/JSON/ajaxSpider/action/scan/", {"url": target})
                await self._wait_for_ajax_spider()

            logger.info("Running ZAP active scan...")
            scan_params: dict[str, Any] = {"url": target}
            if scan_policy:
                scan_params["scanPolicyName"] = scan_policy
            if auth_cfg:
                scan_params["contextId"] = str(
                    await self._get_context_id(
                        auth_cfg.get("context_name", "checkmate-auth")
                    )
                    or ""
                )

            scan_result = await self._api_call(
                "/JSON/ascan/action/scan/",
                scan_params,
            )
            ascan_id = scan_result.get("scan", "0")

            await self._wait_for_active_scan(ascan_id)

            logger.info("Retrieving ZAP alerts...")
            alerts = await self._get_alerts(target)
            # Drop any alerts that still landed on excluded paths
            from core.destructive_actions import path_matches_exclusion

            if excluded_paths:
                alerts = [
                    a
                    for a in alerts
                    if not path_matches_exclusion(
                        str(a.get("url") or ""), excluded_paths
                    )
                ]
            findings = self._parse_alerts(alerts, target)

            self._emit(
                EVENT_ZAP_SCAN_COMPLETED,
                scan_id=scan_id,
                target=target,
                finding_count=len(findings),
                alerts_count=len(alerts),
            )

            return ToolResult(
                tool_name=self.name,
                target=target,
                success=True,
                data={
                    "findings": [f.model_dump_for_state() for f in findings],
                    "finding_count": len(findings),
                    "alerts_count": len(alerts),
                    "scan_id": ascan_id,
                    "auth": auth_meta,
                    "zap_event": EVENT_ZAP_SCAN_COMPLETED,
                    "zap_session": self._session_name,
                },
            )

        except Exception as e:
            event = _classify_zap_error(e)
            error_message: str
            timed_out = event == EVENT_ZAP_SCAN_TIMEOUT
            if event == EVENT_ZAP_UNREACHABLE:
                error_message = f"ZAP unreachable: {e}"
                self._emit(
                    EVENT_ZAP_UNREACHABLE,
                    scan_id=scan_id,
                    target=target,
                    error=str(e),
                )
            elif timed_out:
                error_message = f"ZAP scan timed out after {self.timeout}s"
                self._emit(
                    EVENT_ZAP_SCAN_TIMEOUT,
                    scan_id=scan_id,
                    target=target,
                    timeout_seconds=self.timeout,
                )
            else:
                error_message = f"ZAP API error: {e}"
                self._emit(
                    EVENT_ZAP_SCAN_FAILED,
                    scan_id=scan_id,
                    target=target,
                    error=str(e),
                )
                logger.error("ZAP API error: %s", e)

            data: dict[str, Any] = {
                "auth": auth_meta,
                "zap_event": event,
            }
            if event == EVENT_ZAP_UNREACHABLE:
                data["coverage_note"] = ZAP_UNAVAILABLE_COVERAGE_NOTE

            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=error_message,
                timed_out=timed_out,
                data=data,
            )
        finally:
            await self._teardown_session()

    async def configure_form_authentication(
        self,
        *,
        target: str,
        auth_cfg: dict[str, Any],
        excluded_paths: list[str] | None = None,
    ) -> bool:
        """Configure ZAP's built-in form-based authentication context.

        Uses ZAP context + formBasedAuthentication + cookie session management
        + forced user mode — not a custom session reimplementation.
        Returns True if authentication appears to have succeeded.
        """
        context_name = str(auth_cfg.get("context_name") or "checkmate-auth")
        login_url = str(auth_cfg["login_url"])
        username = str(auth_cfg["username"])
        password = str(auth_cfg["password"])
        username_field = str(auth_cfg.get("username_field") or "username")
        password_field = str(auth_cfg.get("password_field") or "password")

        # Remove existing context if present (best-effort)
        try:
            await self._api_call(
                "/JSON/context/action/removeContext/",
                {"contextName": context_name},
            )
        except Exception:
            pass

        await self._api_call(
            "/JSON/context/action/newContext/",
            {"contextName": context_name},
        )
        if context_name not in self._context_names:
            self._context_names.append(context_name)
        context_id = await self._get_context_id(context_name)

        parsed = urlparse(target)
        include_regex = (
            f"https?://{re.escape(parsed.hostname or '')}.*"
            if parsed.hostname
            else f"{re.escape(target)}.*"
        )
        await self._api_call(
            "/JSON/context/action/includeInContext/",
            {"contextName": context_name, "regex": include_regex},
        )

        for path in excluded_paths or []:
            await self._exclude_path_from_context(context_name, target, path)

        # ZAP formBasedAuthentication: loginRequestData uses {%username%} /
        # {%password%} placeholders bound to HTML form field *names*.
        from urllib.parse import quote

        login_request_data = (
            f"{quote(username_field)}={{%username%}}"
            f"&{quote(password_field)}={{%password%}}"
        )
        auth_params = (
            f"loginUrl={quote(login_url, safe=':/?=&')}&"
            f"loginRequestData={quote(login_request_data, safe='')}"
        )
        await self._api_call(
            "/JSON/authentication/action/setAuthenticationMethod/",
            {
                "contextId": str(context_id),
                "authMethodName": "formBasedAuthentication",
                "authMethodConfigParams": auth_params,
            },
        )
        await self._api_call(
            "/JSON/sessionManagement/action/setSessionManagementMethod/",
            {
                "contextId": str(context_id),
                "methodName": "cookieBasedSessionManagement",
            },
        )

        user_result = await self._api_call(
            "/JSON/users/action/newUser/",
            {"contextId": str(context_id), "name": "checkmate-user"},
        )
        user_id = user_result.get("userId") or user_result.get("user") or "0"

        cred_params = f"username={quote(username)}&password={quote(password)}"
        await self._api_call(
            "/JSON/users/action/setAuthenticationCredentials/",
            {
                "contextId": str(context_id),
                "userId": str(user_id),
                "authCredentialsConfigParams": cred_params,
            },
        )
        await self._api_call(
            "/JSON/users/action/setUserEnabled/",
            {
                "contextId": str(context_id),
                "userId": str(user_id),
                "enabled": "true",
            },
        )
        await self._api_call(
            "/JSON/forcedUser/action/setForcedUser/",
            {"contextId": str(context_id), "userId": str(user_id)},
        )
        await self._api_call(
            "/JSON/forcedUser/action/setForcedUserModeEnabled/",
            {"boolean": "true"},
        )

        # Attempt authentication and inspect state
        try:
            await self._api_call(
                "/JSON/users/action/authenticateAsUser/",
                {"contextId": str(context_id), "userId": str(user_id)},
            )
        except Exception as exc:
            logger.warning("ZAP authenticateAsUser failed: %s", exc)
            return False

        try:
            state = await self._api_call(
                "/JSON/users/view/getAuthenticationState/",
                {"contextId": str(context_id), "userId": str(user_id)},
            )
            auth_state = str(
                state.get("authenticationState")
                or state.get("authState")
                or state.get("state")
                or ""
            ).upper()
            if "LOGGED_IN" in auth_state or auth_state == "AUTHENTICATED":
                return True
            # Some ZAP versions return empty after success — treat access of
            # login URL via forced user as soft-success when no explicit logout.
            if not auth_state or auth_state in {"", "UNKNOWN"}:
                return True
            logger.warning("ZAP authentication state: %s", auth_state)
            return False
        except Exception as exc:
            logger.warning("Could not read ZAP auth state: %s", exc)
            # Soft-fail open for older ZAP builds that lack the view endpoint
            return True

    async def _get_context_id(self, context_name: str) -> int | None:
        try:
            result = await self._api_call("/JSON/context/view/contextList/")
            names = result.get("contextList") or []
            if context_name not in names:
                return None
            detail = await self._api_call(
                "/JSON/context/view/context/",
                {"contextName": context_name},
            )
            ctx = detail.get("context") or detail
            cid = ctx.get("id") if isinstance(ctx, dict) else None
            return int(cid) if cid is not None else None
        except Exception:
            return None

    async def _exclude_path_from_context(
        self, context_name: str, target: str, path: str
    ) -> None:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target.rstrip("/")
        normalized = path if path.startswith("/") else f"/{path}"
        regex = re.escape(f"{base}{normalized}") + ".*"
        try:
            await self._api_call(
                "/JSON/context/action/excludeFromContext/",
                {"contextName": context_name, "regex": regex},
            )
        except Exception as exc:
            logger.debug("excludeFromContext failed for %s: %s", path, exc)

    async def _apply_exclude_paths(
        self,
        *,
        context_name: str,
        target: str,
        excluded_paths: list[str],
        ensure_context: bool,
    ) -> None:
        if ensure_context:
            try:
                await self._api_call(
                    "/JSON/context/action/newContext/",
                    {"contextName": context_name},
                )
                if context_name not in self._context_names:
                    self._context_names.append(context_name)
            except Exception:
                pass
            parsed = urlparse(target)
            if parsed.hostname:
                include_regex = f"https?://{re.escape(parsed.hostname)}.*"
                try:
                    await self._api_call(
                        "/JSON/context/action/includeInContext/",
                        {"contextName": context_name, "regex": include_regex},
                    )
                except Exception:
                    pass
        for path in excluded_paths:
            await self._exclude_path_from_context(context_name, target, path)

    async def _wait_for_spider(self, spider_id: str) -> None:
        """Wait for spider to complete."""
        elapsed = 0.0
        while elapsed < self.timeout:
            result = await self._api_call(
                "/JSON/spider/view/status/",
                {"scanId": spider_id},
            )
            status = int(result.get("status", "100"))
            if status >= 100:
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise asyncio.TimeoutError("Spider timed out")

    async def _wait_for_ajax_spider(self) -> None:
        """Wait for AJAX spider to complete."""
        elapsed = 0.0
        while elapsed < self.timeout:
            result = await self._api_call("/JSON/ajaxSpider/view/status/")
            status = result.get("status", "stopped")
            if status == "stopped":
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise asyncio.TimeoutError("AJAX Spider timed out")

    async def _wait_for_active_scan(self, scan_id: str) -> None:
        """Wait for active scan to complete."""
        elapsed = 0.0
        while elapsed < self.timeout:
            result = await self._api_call(
                "/JSON/ascan/view/status/",
                {"scanId": scan_id},
            )
            status = int(result.get("status", "100"))
            logger.debug(f"ZAP active scan progress: {status}%")
            if status >= 100:
                return
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise asyncio.TimeoutError("Active scan timed out")

    async def _get_alerts(self, target: str) -> list[dict[str, Any]]:
        """Retrieve alerts for the target."""
        result = await self._api_call(
            "/JSON/core/view/alerts/",
            {"baseurl": target},
        )
        return result.get("alerts", [])

    def _parse_alerts(
        self,
        alerts: list[dict[str, Any]],
        target: str,
    ) -> list[Finding]:
        """Parse ZAP alerts into normalized Finding objects."""
        findings: list[Finding] = []

        for alert in alerts:
            try:
                risk = str(alert.get("risk", "0"))
                severity = ZAP_RISK_MAP.get(risk, Severity.INFO)

                alert_name = alert.get("alert", "Unknown")
                cwe_id = alert.get("cweid")
                if cwe_id:
                    try:
                        cwe_id = int(cwe_id)
                    except (ValueError, TypeError):
                        cwe_id = None

                if not cwe_id:
                    for pattern, cwe in ZAP_CWE_MAP.items():
                        if pattern.lower() in alert_name.lower():
                            cwe_id = cwe
                            break

                evidence = alert.get("evidence", "")
                if not evidence:
                    evidence = alert.get("other", "")

                finding = Finding(
                    tool="zap",
                    type=f"zap-{alert.get('pluginId', 'unknown')}",
                    url=alert.get("url", target),
                    param=alert.get("param"),
                    severity=severity,
                    description=f"{alert_name}: {alert.get('description', '')}",
                    evidence=evidence[:500] if evidence else None,
                    cwe_id=cwe_id,
                    raw_data=alert,
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse ZAP alert: {e}")
                continue

        return findings

