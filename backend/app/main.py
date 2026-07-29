"""checkmate API."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import sys
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from agents.orchestrator import get_orchestrator, resolve_approved_tools
from core.accounts import (
    create_extension_token,
    deactivate_site,
    delete_site_auth_credentials,
    extension_token_to_dict,
    find_org_id_by_email,
    claim_webhook_event,
    get_org_scan_usage,
    get_organization,
    get_scan_record,
    get_site_auth_credentials,
    get_user,
    list_stale_active_scans,
    list_org_risk_trend,
    list_org_scans,
    list_org_sites,
    list_org_targets,
    init_accounts_schema,
    CREATOR_PLAN_ID,
    org_has_creator_member,
    QuotaExceededError,
    reserve_scan_quota_and_create_records,
    resolve_extension_token,
    revoke_extension_tokens_for_user,
    scan_to_dict,
    set_watch_emails_enabled,
    site_auth_public_dict,
    site_to_dict,
    update_organization_plan,
    update_scan_record,
    update_site_excluded_paths,
    upsert_site_auth_credentials,
    upsert_user_from_firebase,
    user_to_dict,
)
from core.audit import log_scan_triggered
from core.config import get_settings, validate_startup_settings
from core.credential_crypto import encrypt_credentials, redact_username
from core.firebase_auth import (
    AuthenticatedUser,
    ensure_email_verified,
    require_firebase_user,
    require_verified_firebase_user,
    try_verify_bearer_token,
)
from core.plans import (
    can_use_authenticated_scanning,
    plan_supports_watch,
    watch_cadence_for_plan,
)
from core.watch_agent.scheduler import (
    on_plan_changed,
    on_site_added,
    on_site_removed,
    shutdown_scheduler,
    start_scheduler,
)
from core.toolchain import (
    ensure_toolchain_ready,
    get_toolchain_report,
    validate_toolchain_at_startup,
    warm_nuclei_templates,
)
from core.logging import bind_request_id, configure_logging, get_request_id
from core.scope import enforce_scope
from core.ssrf import (
    SSRFError,
    normalize_scan_target,
    validate_login_url_for_site,
    validate_scan_target,
)

logger = logging.getLogger(__name__)

if sys.platform == "win32":
    # Recon/detection tools spawn external CLI binaries via asyncio subprocesses.
    # Those only work on the ProactorEventLoop. Some launchers (and older
    # defaults) leave asyncio on the SelectorEventLoop, which raises
    # NotImplementedError and forces a blocking thread fallback that can hang on
    # a tool's orphaned child processes (the "stuck in recon" symptom). Pin the
    # Proactor policy before any event loop is created so the async path is used.
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:  # noqa: BLE001 - never block startup on loop policy setup
        logger.warning("Could not set WindowsProactorEventLoopPolicy", exc_info=True)

_TARGETS_FILE = Path(__file__).resolve().parent.parent / "data" / "targets.json"


def _normalize_target_entry(entry: str) -> str:
    """Normalize a target to a bare lowercase hostname."""
    value = str(entry).strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    from urllib.parse import urlparse

    parsed = urlparse(value)
    return parsed.hostname or ""


class TargetsStore:
    """Runtime allowlist store (informational while enforcement is disabled).

    Persists to backend/data/targets.json so the Options UI edits survive
    restarts. Enforcement itself lives in core/scope.py and is currently off.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    def _seed_from_settings(self) -> list[str]:
        settings = get_settings()
        seeded = [
            _normalize_target_entry(t) for t in settings.authorized_target_list
        ]
        return sorted({t for t in seeded if t})

    def _read(self) -> list[str]:
        if _TARGETS_FILE.exists():
            try:
                raw = json.loads(_TARGETS_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    raw = raw.get("targets", [])
                if isinstance(raw, list):
                    cleaned = [_normalize_target_entry(t) for t in raw]
                    return sorted({t for t in cleaned if t})
            except (json.JSONDecodeError, OSError):
                logger.warning("targets.json unreadable; falling back to settings")
        return self._seed_from_settings()

    def _write(self, targets: list[str]) -> None:
        _TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _TARGETS_FILE.write_text(
            json.dumps({"targets": targets}, indent=2), encoding="utf-8"
        )

    async def get(self) -> list[str]:
        async with self._lock:
            return self._read()

    async def set(self, targets: list[str]) -> list[str]:
        cleaned = sorted({_normalize_target_entry(t) for t in targets if str(t).strip()})
        cleaned = [t for t in cleaned if t]
        async with self._lock:
            self._write(cleaned)
            return cleaned


_targets_store = TargetsStore()


class TargetsRequest(BaseModel):
    targets: list[str] = Field(default_factory=list)


class TargetsResponse(BaseModel):
    targets: list[str]
    enforcement_enabled: bool


class ScanCreateRequest(BaseModel):
    target: str = Field(..., description="URL or hostname to scan")
    confirmed_authorized: bool = Field(
        default=False,
        description=(
            "Caller must explicitly confirm they own or are authorized to scan "
            "this target. The scan will be rejected if this is False or missing."
        ),
    )


class ScanCreateResponse(BaseModel):
    scan_id: str
    target: str
    status: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    current_node: str | None = None
    next_nodes: list[str] = Field(default_factory=list)
    human_approval_needed: bool = False
    human_approved: bool = False
    approved_tools: list[str] = Field(default_factory=list)
    rejected_tools: list[str] = Field(default_factory=list)
    pending_interrupt: dict[str, Any] | None = None
    findings_count: int = 0
    is_complete: bool = False
    created_at: str
    updated_at: str
    error: dict[str, str] | None = None


class ScanApprovalRequest(BaseModel):
    target: str | None = Field(
        default=None, description="Optional scan target for scope re-validation"
    )
    approved: bool = Field(
        default=False,
        description=(
            "Legacy bulk approve/reject flag: approves every planned active "
            "tool when true. Ignored when `approved_tools` is provided; "
            "defaults to False (reject) when neither is set."
        ),
    )
    approved_tools: list[str] | None = Field(
        default=None,
        description=(
            "Per-tool approval: names of planned_active_tests to allow, e.g. "
            "['sqlmap'] to approve sqlmap while rejecting zap. Takes "
            "precedence over `approved` when present, including an empty "
            "list (reject all)."
        ),
    )


class ScanApprovalResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    human_approved: bool
    approved_tools: list[str] = Field(default_factory=list)
    rejected_tools: list[str] = Field(default_factory=list)
    is_complete: bool


class ScanReportResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    findings: list[dict[str, Any]]
    report: dict[str, Any] | None
    generated_at: str
    verify_fix_summaries: dict[str, dict[str, Any]] = Field(default_factory=dict)
    coverage: dict[str, Any] | None = None


class ScanHistoryItem(BaseModel):
    id: str
    target: str
    status: str
    current_node: str | None = None
    overall_risk_score: float | None = None
    severity: str | None = None
    findings_count: int | None = None
    critical_high_count: int | None = None
    created_at: str
    updated_at: str


class ScanHistoryResponse(BaseModel):
    scans: list[ScanHistoryItem]
    page: int
    page_size: int
    total: int
    total_pages: int
    target_count: int
    scans_this_month: int
    targets: list[str]


class RiskTrendPoint(BaseModel):
    scan_id: str
    target: str
    created_at: str
    overall_risk_score: float
    severity: str | None = None
    findings_count: int | None = None
    critical_high_count: int | None = None


class RiskTrendResponse(BaseModel):
    target: str | None = None
    points: list[RiskTrendPoint]


class VerifyFixResponse(BaseModel):
    scan_id: str
    finding_id: str
    result: str
    evidence: str | None = None
    verification: dict[str, Any] | None = None
    confidence: float | None = None
    checked_at: str
    quota_consumed: bool = False
    history: list[dict[str, Any]] = Field(default_factory=list)
    attempt_count: int = 0
    finding: dict[str, Any] = Field(default_factory=dict)

class ScanRateLimiter:
    """In-memory /scan limiter by client identity and global concurrency."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._active_per_client: dict[str, int] = defaultdict(int)
        self._active_global: int = 0

    async def acquire(self, client_id: str) -> None:
        settings = get_settings()
        now = asyncio.get_running_loop().time()
        window = float(settings.scan_rate_limit_window_seconds)
        max_requests = int(settings.scan_rate_limit_max_requests)
        max_per_client = int(settings.scan_rate_limit_max_concurrent_per_client)
        max_global = int(settings.scan_rate_limit_max_concurrent_global)

        async with self._lock:
            events = self._events[client_id]
            while events and (now - events[0]) > window:
                events.popleft()

            if len(events) >= max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "scan_rate_limit_exceeded",
                        "message": (
                            f"Too many scan requests for this client. "
                            f"Limit: {max_requests} per {int(window)}s."
                        ),
                    },
                )

            if self._active_per_client[client_id] >= max_per_client:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "scan_concurrency_exceeded",
                        "message": (
                            f"Too many concurrent scans for this client. "
                            f"Limit: {max_per_client}."
                        ),
                    },
                )

            if self._active_global >= max_global:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "global_scan_concurrency_exceeded",
                        "message": (
                            f"Global concurrent scan limit reached ({max_global}). "
                            "Try again later."
                        ),
                    },
                )

            events.append(now)
            self._active_per_client[client_id] += 1
            self._active_global += 1

    async def release(self, client_id: str) -> None:
        async with self._lock:
            if self._active_per_client.get(client_id, 0) > 0:
                self._active_per_client[client_id] -= 1
            if self._active_global > 0:
                self._active_global -= 1


class SlidingWindowRateLimiter:
    """Small in-memory limiter for low-cost auth/session endpoints."""

    def __init__(self, *, error_code: str) -> None:
        self._lock = asyncio.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._error_code = error_code

    async def acquire(
        self,
        key: str,
        *,
        max_requests: int,
        window_seconds: int,
        label: str,
    ) -> None:
        now = asyncio.get_running_loop().time()
        window = float(window_seconds)
        async with self._lock:
            events = self._events[key]
            while events and (now - events[0]) > window:
                events.popleft()
            if len(events) >= max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": self._error_code,
                        "message": (
                            f"Too many auth requests for this {label}. "
                            f"Limit: {max_requests} per {int(window)}s."
                        ),
                    },
                )
            events.append(now)


def _extract_bearer_or_api_key(request: Request) -> str:
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        return api_key
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def _account_from_extension_token(raw_token: str):
    ext = resolve_extension_token(raw_token)
    if ext is None:
        return None
    return get_user(ext.user_id)


def _get_client_identity(request: Request) -> str:
    """Resolve client identity for rate limits and scan ownership.

    Prefer a *verified* Firebase ID token (``org:<id>``). Registered Chrome
    extension tokens also map to the owning org. Legacy opaque API keys remain
    supported as ``api_key:<token>``. Never trust a client-supplied user id
    query/body field.
    """
    raw = _extract_bearer_or_api_key(request)
    if raw:
        firebase_user = try_verify_bearer_token(raw)
        if firebase_user is not None:
            account = _account_for_firebase_user(firebase_user)
            return f"org:{account.org_id}"
        ext_account = _account_from_extension_token(raw)
        if ext_account is not None:
            return f"org:{ext_account.org_id}"
        # Legacy opaque keys (and X-API-Key that isn't an extension token).
        api_key = request.headers.get("X-API-Key", "").strip()
        if api_key:
            return f"api_key:{api_key}"
        return f"api_key:{raw}"
    host = request.client.host if request.client else "unknown"
    return f"ip:{host}"


def _require_firebase_if_configured(
    request: Request,
) -> AuthenticatedUser | None:
    """When REQUIRE_FIREBASE_AUTH=true, require Firebase JWT or extension token."""
    settings = get_settings()
    if not settings.require_firebase_auth:
        return None
    raw = _extract_bearer_or_api_key(request)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "missing_token",
                "message": "Authorization Bearer token is required.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    firebase_user = try_verify_bearer_token(raw)
    if firebase_user is not None:
        return firebase_user
    if resolve_extension_token(raw) is not None:
        # Extension credentials satisfy the auth gate; scan routes resolve
        # the org account separately.
        return None
    from core.firebase_auth import verify_id_token

    return verify_id_token(raw)


def _resolve_scan_account(request: Request, firebase_user: AuthenticatedUser | None):
    """Return the SaaS account for quota/ownership when available."""
    if firebase_user is not None:
        return _account_for_firebase_user(firebase_user)
    raw = _extract_bearer_or_api_key(request)
    if not raw:
        return None
    verified = try_verify_bearer_token(raw)
    if verified is not None:
        return _account_for_firebase_user(verified)
    return _account_from_extension_token(raw)


def _account_for_firebase_user(user: AuthenticatedUser):
    record = get_user(user.uid)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "user_not_found",
                "message": "Complete account sync with terms acceptance first.",
            },
        )
    return record


def _ensure_verified_for_sensitive_action(
    firebase_user: AuthenticatedUser | None,
    account,
) -> None:
    """Require a verified email for scans, tokens, and org mutations."""
    if firebase_user is not None:
        ensure_email_verified(firebase_user)
        return
    if account is not None and not account.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "email_not_verified",
                "message": (
                    "Verify your email address before using this feature. "
                    "Check your inbox (and spam folder) for the verification link."
                ),
            },
        )


def _risk_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


async def _sync_persisted_scan(scan_id: str) -> dict[str, Any] | None:
    """Refresh dashboard metadata from the authoritative graph snapshot."""
    orchestrator = get_orchestrator()
    summary = await orchestrator.get_status_summary(scan_id)
    if summary is None:
        return None
    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    values = dict(snapshot.values) if (snapshot and snapshot.values) else {}
    score_value = (values.get("severity_scores") or {}).get("overall_risk_score")
    score = float(score_value) if score_value is not None else None
    severity_counts = (values.get("severity_scores") or {}).get("severity_counts") or {}
    findings = values.get("findings") or []
    findings_count = len(findings) if findings else None
    critical_high = None
    if isinstance(severity_counts, dict) and severity_counts:
        critical_high = int(severity_counts.get("critical") or 0) + int(
            severity_counts.get("high") or 0
        )
    if summary.get("pending_interrupt") is not None:
        display_status = "awaiting_approval"
    elif summary.get("is_complete"):
        display_status = "failed" if summary.get("status") == "failed" else "completed"
    else:
        display_status = str(summary.get("status") or "pending")
    update_scan_record(
        scan_id,
        status=display_status,
        current_node=summary.get("current_node"),
        overall_risk_score=score,
        severity=_risk_severity(score),
        findings_count=findings_count,
        critical_high_count=critical_high,
    )
    return {
        **summary,
        "status": display_status,
        "overall_risk_score": score,
        "severity": _risk_severity(score),
        "findings_count": findings_count,
        "critical_high_count": critical_high,
    }


_scan_rate_limiter = ScanRateLimiter()
_auth_rate_limiter = SlidingWindowRateLimiter(error_code="auth_rate_limit_exceeded")


async def _enforce_auth_ip_rate_limit(request: Request) -> None:
    settings = get_settings()
    host = request.client.host if request.client else "unknown"
    await _auth_rate_limiter.acquire(
        f"ip:{host}",
        max_requests=int(settings.auth_rate_limit_max_requests_per_ip),
        window_seconds=int(settings.auth_rate_limit_window_seconds),
        label="IP",
    )


async def _enforce_auth_account_rate_limit(user: AuthenticatedUser) -> None:
    settings = get_settings()
    await _auth_rate_limiter.acquire(
        f"account:{user.uid}",
        max_requests=int(settings.auth_rate_limit_max_requests_per_account),
        window_seconds=int(settings.auth_rate_limit_window_seconds),
        label="account",
    )


class InflightScanRegistry:
    """Prevent duplicate in-flight scans for the same client + target."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._by_key: dict[str, str] = {}
        self._scan_keys: dict[str, str] = {}

    @staticmethod
    def _dedup_key(client_id: str, normalized_target: str) -> str:
        return f"{client_id}:{normalized_target}"

    async def get_inflight(
        self,
        client_id: str,
        normalized_target: str,
    ) -> str | None:
        key = self._dedup_key(client_id, normalized_target)
        async with self._lock:
            return self._by_key.get(key)

    async def register(
        self,
        client_id: str,
        normalized_target: str,
        scan_id: str,
    ) -> None:
        key = self._dedup_key(client_id, normalized_target)
        async with self._lock:
            self._by_key[key] = scan_id
            self._scan_keys[scan_id] = key

    async def release(self, scan_id: str) -> None:
        async with self._lock:
            key = self._scan_keys.pop(scan_id, None)
            if key and self._by_key.get(key) == scan_id:
                del self._by_key[key]


_inflight_scans = InflightScanRegistry()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
    validate_startup_settings(settings)
    validate_toolchain_at_startup(settings)
    init_accounts_schema()
    orchestrator = get_orchestrator()
    await orchestrator.setup()
    recovered_scans = await orchestrator.recover_stale_scans()
    if recovered_scans:
        logger.warning(
            "Recovered stale in-progress scans after startup",
            extra={"scan_ids": recovered_scans},
        )
    # Warm templates in the background so the API accepts connections immediately.
    # Blocking here left the port bound-but-dead for up to ~180s (connection refused).
    warm_task = asyncio.create_task(warm_nuclei_templates())
    if settings.watch_scheduler_enabled:
        try:
            start_scheduler()
        except Exception:  # noqa: BLE001
            logger.exception("Failed to start Watch Agent scheduler")
    logger.info("Starting %s", settings.app_name, extra={"app_env": settings.app_env})
    yield
    warm_task.cancel()
    try:
        await warm_task
    except asyncio.CancelledError:
        pass
    try:
        shutdown_scheduler()
    except Exception:  # noqa: BLE001
        logger.exception("Failed to shut down Watch Agent scheduler")
    await orchestrator.teardown()
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title="checkmate",
    description="Multi-agent web vulnerability scanner API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Apply security headers so this API passes its own header-checks rules."""
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'",
    )
    response.headers.setdefault(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    incoming = request.headers.get("X-Request-ID")
    bind_request_id(incoming)
    response = await call_next(request)
    response.headers["X-Request-ID"] = get_request_id()
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Check backend logs for details.",
        },
    )


class AuthSyncBody(BaseModel):
    """Optional terms acceptance recorded when creating (or refreshing) an account."""

    terms_accepted: bool = False
    terms_version: str | None = None


@app.post("/auth/sync")
async def auth_sync(
    request: Request,
    _ip_rate_limit: None = Depends(_enforce_auth_ip_rate_limit),
    user: AuthenticatedUser = Depends(require_firebase_user),
    body: AuthSyncBody = Body(default_factory=AuthSyncBody),
):
    """Upsert the authenticated Firebase user into our users/organizations tables.

    New accounts receive an implicit free-plan organization (limits match the
    web pricing catalog). The Firebase UID comes from the verified ID token —
    never from the request body. New accounts must include terms_accepted=true.
    """
    del request, _ip_rate_limit
    await _enforce_auth_account_rate_limit(user)
    existing = get_user(user.uid)
    if existing is None and not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "email_not_verified",
                "message": (
                    "Verify your email address before signing in. "
                    "Check your inbox (and spam folder) for the verification link."
                ),
            },
        )
    if existing is None and not body.terms_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "terms_required",
                "message": (
                    "You must accept the Terms of Use and Privacy Policy "
                    "before creating an account."
                ),
            },
        )

    record, created = upsert_user_from_firebase(
        uid=user.uid,
        email=user.email,
        display_name=user.name,
        email_verified=user.email_verified,
        auth_provider=user.sign_in_provider,
        terms_accepted=body.terms_accepted,
        terms_version=body.terms_version,
    )
    return {"user": user_to_dict(record), "created": created}


@app.get("/auth/me")
async def auth_me(
    user: AuthenticatedUser = Depends(require_firebase_user),
):
    """Return the backend profile for the verified Firebase user."""
    record = get_user(user.uid)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "user_not_found",
                "message": "Complete account sync with terms acceptance first.",
            },
        )
    org = get_organization(record.org_id)
    payload = user_to_dict(record)
    payload["watch_emails_enabled"] = (
        org.watch_emails_enabled if org else True
    )
    payload["watch_cadence"] = watch_cadence_for_plan(record.plan_id)
    return {"user": payload}


class ExtensionTokenCreateBody(BaseModel):
    label: str | None = Field(default="chrome-extension", max_length=64)


@app.post("/auth/extension/token")
async def mint_extension_token(
    request: Request,
    _ip_rate_limit: None = Depends(_enforce_auth_ip_rate_limit),
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
    body: ExtensionTokenCreateBody = Body(default_factory=ExtensionTokenCreateBody),
):
    """Mint a long-lived API key for the Chrome extension after webapp sign-in.

    The plaintext token is returned once. The extension stores it and sends it
    as Authorization Bearer / X-API-Key on subsequent API calls.
    """
    del request, _ip_rate_limit
    await _enforce_auth_account_rate_limit(user)
    account = get_user(user.uid)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "user_not_found",
                "message": "Complete account sync with terms acceptance first.",
            },
        )
    record, raw_token = create_extension_token(
        org_id=account.org_id,
        user_id=account.id,
        label=(body.label or "chrome-extension").strip() or "chrome-extension",
    )
    return {
        "token": raw_token,
        "token_meta": extension_token_to_dict(record),
        "backend_hint": None,
    }


@app.post("/auth/extension/revoke")
async def revoke_extension_tokens(
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    """Revoke all active Chrome extension tokens for the signed-in user."""
    account = get_user(user.uid)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "user_not_found",
                "message": "Complete account sync with terms acceptance first.",
            },
        )
    revoked = revoke_extension_tokens_for_user(account.id)
    return {"revoked": revoked}


class OrgSettingsUpdate(BaseModel):
    watch_emails_enabled: bool | None = None
    brand_name: str | None = Field(default=None, max_length=80)
    # Optional PNG/JPEG/WebP logo as a data-URL or raw base64 (Agency white-label).
    brand_logo_base64: str | None = None
    clear_brand_logo: bool | None = None


def _org_settings_payload(org) -> dict:
    from core.plans import (
        can_use_white_label_reports,
        watch_cadence_for_plan,
    )

    return {
        "org_id": org.id,
        "plan_id": org.plan_id,
        "watch_emails_enabled": org.watch_emails_enabled,
        "watch_cadence": watch_cadence_for_plan(org.plan_id),
        "white_label_reports_allowed": can_use_white_label_reports(org.id),
        "brand_name": org.brand_name,
        "brand_logo_configured": bool(org.brand_logo_path),
    }


@app.get("/orgs/me/settings")
async def get_org_settings(
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    account = _account_for_firebase_user(user)
    org = get_organization(account.org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "organization_not_found"},
        )
    return _org_settings_payload(org)


@app.put("/orgs/me/settings")
async def update_org_settings(
    body: OrgSettingsUpdate,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    from core.accounts import branding_assets_dir, update_organization_branding
    from core.plans import can_use_white_label_reports

    account = _account_for_firebase_user(user)
    if body.watch_emails_enabled is not None:
        org = set_watch_emails_enabled(account.org_id, body.watch_emails_enabled)
    else:
        org = get_organization(account.org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "organization_not_found"},
        )

    branding_touched = (
        body.brand_name is not None
        or body.brand_logo_base64 is not None
        or body.clear_brand_logo
    )
    if branding_touched:
        if not can_use_white_label_reports(account.org_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "white_label_reports_not_on_plan"},
            )
        logo_path: str | None = None
        clear_logo = bool(body.clear_brand_logo)
        if body.brand_logo_base64:
            raw = body.brand_logo_base64.strip()
            if "," in raw and raw.lower().startswith("data:"):
                raw = raw.split(",", 1)[1]
            try:
                logo_bytes = base64.b64decode(raw, validate=True)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": "invalid_brand_logo"},
                ) from exc
            if len(logo_bytes) > 512_000:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": "brand_logo_too_large"},
                )
            # Basic magic-byte sniff for image types we accept in reports.
            if logo_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                ext = ".png"
            elif logo_bytes.startswith(b"\xff\xd8\xff"):
                ext = ".jpg"
            elif logo_bytes.startswith(b"RIFF") and b"WEBP" in logo_bytes[:16]:
                ext = ".webp"
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": "unsupported_brand_logo_type"},
                )
            dest = branding_assets_dir() / f"{account.org_id}{ext}"
            dest.write_bytes(logo_bytes)
            logo_path = str(dest)
            clear_logo = False
        brand_name = body.brand_name
        if brand_name is not None:
            brand_name = brand_name.strip() or None
        org = update_organization_branding(
            account.org_id,
            brand_name=brand_name,
            brand_logo_path=logo_path,
            clear_logo=clear_logo,
        )
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "organization_not_found"},
            )

    return _org_settings_payload(org)


@app.get("/orgs/me/sites")
async def get_org_sites(
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    account = _account_for_firebase_user(user)
    sites = list_org_sites(account.org_id, active_only=False)
    return {
        "sites": [site_to_dict(s) for s in sites],
        "watch_cadence": watch_cadence_for_plan(account.plan_id),
        "authenticated_scanning_allowed": can_use_authenticated_scanning(
            account.org_id
        ),
    }


class SiteCredentialsRequest(BaseModel):
    """Form-based auth credentials matching ZAP formBasedAuthentication.

    ``username_field`` / ``password_field`` are HTML form ``name`` attributes
    (not CSS selectors), as required by ZAP's loginRequestData format.
    """

    login_url: str = Field(..., description="Login form page / POST URL")
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    username_field: str = Field(
        default="username",
        description="HTML form name attribute for the username/email field",
    )
    password_field: str = Field(
        default="password",
        description="HTML form name attribute for the password field",
    )
    excluded_paths: list[str] = Field(
        default_factory=list,
        description="Paths/actions to exclude from crawl and active tests",
    )
    credentials_authorized: bool = Field(
        default=False,
        description=(
            "Mandatory consent: caller confirms they are authorized to use "
            "these specific credentials for security testing."
        ),
    )


class SiteExcludedPathsRequest(BaseModel):
    excluded_paths: list[str] = Field(default_factory=list)


@app.put("/orgs/me/sites/{site_id}/credentials")
async def put_site_credentials(
    site_id: str,
    body: SiteCredentialsRequest,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    account = _account_for_firebase_user(user)
    if not can_use_authenticated_scanning(account.org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "authenticated_scanning_not_on_plan",
                "message": (
                    "Authenticated scanning requires a Pro or Agency plan. "
                    "Upgrade to configure login credentials."
                ),
                "plan_id": account.plan_id,
            },
        )
    if not body.credentials_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "credentials_consent_required",
                "message": (
                    "You must confirm you are authorized to use these specific "
                    "credentials for security testing "
                    "(credentials_authorized=true)."
                ),
            },
        )

    sites = {s.id: s for s in list_org_sites(account.org_id, active_only=False)}
    site = sites.get(site_id)
    if site is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "site_not_found", "site_id": site_id},
        )

    try:
        safe_login_url = validate_login_url_for_site(
            body.login_url.strip(),
            site.target,
        )
    except SSRFError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_login_url",
                "message": str(exc),
                "login_url": body.login_url,
            },
        ) from exc

    blob = encrypt_credentials(body.username, body.password)
    record = upsert_site_auth_credentials(
        site_id=site.id,
        org_id=account.org_id,
        login_url=safe_login_url,
        username_field=body.username_field.strip() or "username",
        password_field=body.password_field.strip() or "password",
        encrypted_data_key=blob.encrypted_data_key,
        encrypted_payload=blob.ciphertext,
        username_hint=redact_username(body.username),
        credentials_consent_user_id=account.id,
        excluded_paths=body.excluded_paths,
    )
    return {
        "ok": True,
        "site_id": site_id,
        "authenticated_scanning": site_auth_public_dict(record),
    }


@app.delete("/orgs/me/sites/{site_id}/credentials")
async def remove_site_credentials(
    site_id: str,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    account = _account_for_firebase_user(user)
    sites = {s.id: s for s in list_org_sites(account.org_id, active_only=False)}
    if site_id not in sites:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "site_not_found", "site_id": site_id},
        )
    deleted = delete_site_auth_credentials(site_id)
    return {"ok": True, "site_id": site_id, "deleted": deleted}


@app.put("/orgs/me/sites/{site_id}/excluded-paths")
async def put_site_excluded_paths(
    site_id: str,
    body: SiteExcludedPathsRequest,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    account = _account_for_firebase_user(user)
    sites = {s.id: s for s in list_org_sites(account.org_id, active_only=False)}
    if site_id not in sites:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "site_not_found", "site_id": site_id},
        )
    existing = get_site_auth_credentials(site_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "credentials_not_configured",
                "message": "Configure credentials before editing excluded paths.",
                "site_id": site_id,
            },
        )
    record = update_site_excluded_paths(site_id, body.excluded_paths)
    return {
        "ok": True,
        "site_id": site_id,
        "authenticated_scanning": site_auth_public_dict(record),
    }


@app.delete("/orgs/me/sites/{site_id}")
async def delete_org_site(
    site_id: str,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
):
    account = _account_for_firebase_user(user)
    sites = {s.id: s for s in list_org_sites(account.org_id, active_only=False)}
    site = sites.get(site_id)
    if site is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "site_not_found", "site_id": site_id},
        )
    delete_site_auth_credentials(site_id)
    deactivate_site(site_id)
    on_site_removed(site_id)
    return {"ok": True, "site_id": site_id}


class DodoWebhookPayload(BaseModel):
    """Minimal Dodo Payments webhook shape for plan sync.

    Accepts either ``org_id`` or ``customer_email`` to locate the organization.
    """

    event: str = Field(..., description="e.g. subscription.active, subscription.cancelled")
    org_id: str | None = None
    customer_email: str | None = None
    plan_id: str | None = None


@app.post("/webhooks/dodo")
async def dodo_webhook(body: DodoWebhookPayload, request: Request):
    """Apply plan changes from Dodo and reschedule Watch Agent jobs.

    Subscription state is webhook-driven only. Requests without a configured
    shared secret are rejected outside local development/test. When a secret
    is configured, the header must match via constant-time comparison.
    """
    settings = get_settings()
    if not settings.dodo_webhook_secret:
        if settings.app_env in ("production", "staging"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "webhook_not_configured",
                    "message": "DODO_WEBHOOK_SECRET is required to accept billing webhooks.",
                },
            )
        logger.warning(
            "Accepting unsigned Dodo webhook because DODO_WEBHOOK_SECRET is unset "
            "(allowed only in %s)",
            settings.app_env,
        )
    else:
        provided = request.headers.get("X-Dodo-Webhook-Secret", "").strip()
        if not provided or not hmac.compare_digest(
            provided, settings.dodo_webhook_secret
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_webhook_secret"},
            )

    org_id = body.org_id
    if org_id is None and body.customer_email:
        org_id = find_org_id_by_email(body.customer_email)

    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "org_not_resolved"},
        )

    payload_hash = hashlib.sha256(
        body.model_dump_json(exclude_none=True).encode("utf-8")
    ).hexdigest()
    if not claim_webhook_event(payload_hash):
        org = get_organization(org_id)
        return {
            "ok": True,
            "duplicate": True,
            "org_id": org_id,
            "plan_id": org.plan_id if org else None,
            "watch_jobs": None,
        }

    event = body.event.lower()
    if "cancel" in event or event.endswith(".cancelled"):
        if org_has_creator_member(org_id):
            org = get_organization(org_id)
            return {
                "ok": True,
                "skipped": True,
                "reason": "creator_plan_protected",
                "org_id": org_id,
                "plan_id": org.plan_id if org else CREATOR_PLAN_ID,
                "watch_jobs": None,
            }
        plan_id = "free"
    else:
        plan_id = (body.plan_id or "starter").lower()
        if plan_id not in {"free", "starter", "pro", "agency"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "invalid_plan_id", "plan_id": plan_id},
            )

    org = update_organization_plan(org_id, plan_id=plan_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "organization_not_found"},
        )
    sync_result = on_plan_changed(org_id)
    return {
        "ok": True,
        "org_id": org_id,
        "plan_id": org.plan_id,
        "watch_jobs": sync_result,
    }


@app.get("/orgs/me/scans", response_model=ScanHistoryResponse)
async def get_org_scan_history(
    page: int = 1,
    page_size: int = 10,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
) -> ScanHistoryResponse:
    """List only scans belonging to the verified user's organization."""
    if page < 1 or page_size < 1 or page_size > 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_pagination"},
        )
    account = _account_for_firebase_user(user)
    records, total = list_org_scans(
        account.org_id,
        page=page,
        page_size=page_size,
    )
    # Scan graph state is authoritative; the relational rows are the durable,
    # tenant-scoped history/index used for pagination and quota accounting.
    for record in records:
        await _sync_persisted_scan(record.id)
    records, total = list_org_scans(
        account.org_id,
        page=page,
        page_size=page_size,
    )
    items = [
        ScanHistoryItem(
            **{
                key: value
                for key, value in scan_to_dict(record).items()
                if key != "org_id"
            }
        )
        for record in records
    ]
    target_count, scans_this_month = get_org_scan_usage(account.org_id)
    return ScanHistoryResponse(
        scans=items,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=max(1, (total + page_size - 1) // page_size),
        target_count=target_count,
        scans_this_month=scans_this_month,
        targets=list_org_targets(account.org_id),
    )


@app.get("/orgs/me/risk-trend", response_model=RiskTrendResponse)
async def get_org_risk_trend(
    target: str | None = None,
    user: AuthenticatedUser = Depends(require_verified_firebase_user),
) -> RiskTrendResponse:
    """Risk score over time for completed full vulnerability scans (not watch jobs)."""
    account = _account_for_firebase_user(user)
    records = list_org_risk_trend(account.org_id, target=target)
    points = [
        RiskTrendPoint(
            scan_id=r.id,
            target=r.target,
            created_at=r.created_at,
            overall_risk_score=float(r.overall_risk_score or 0.0),
            severity=r.severity,
            findings_count=r.findings_count,
            critical_high_count=r.critical_high_count,
        )
        for r in records
    ]
    return RiskTrendResponse(target=target, points=points)


async def _probe_firecrawl(settings) -> dict[str, Any]:
    if not settings.firecrawl_enabled:
        return {"configured": False, "reachable": None, "status": "disabled"}
    if not settings.firecrawl_api_key:
        return {"configured": False, "reachable": False, "status": "missing_api_key"}
    base = (settings.firecrawl_api_url or "https://api.firecrawl.dev").rstrip("/")
    url = f"{base}/v1/team/credit-usage"
    headers = {"Authorization": f"Bearer {settings.firecrawl_api_key}"}
    try:
        async with httpx.AsyncClient(timeout=settings.upstream_health_timeout_seconds) as client:
            response = await client.get(url, headers=headers)
        return {
            "configured": True,
            "reachable": response.status_code < 500,
            "status_code": response.status_code,
        }
    except Exception as exc:  # noqa: BLE001 - health probe must never raise
        return {"configured": True, "reachable": False, "error": str(exc)}


async def _probe_dodo(settings) -> dict[str, Any]:
    if not settings.dodo_api_key:
        return {"configured": False, "reachable": None, "status": "missing_api_key"}
    base = settings.dodo_api_url.rstrip("/")
    url = f"{base}/v1/products"
    headers = {"Authorization": f"Bearer {settings.dodo_api_key}"}
    try:
        async with httpx.AsyncClient(timeout=settings.upstream_health_timeout_seconds) as client:
            response = await client.get(url, headers=headers)
        return {
            "configured": True,
            "reachable": response.status_code < 500,
            "status_code": response.status_code,
        }
    except Exception as exc:  # noqa: BLE001 - health probe must never raise
        return {"configured": True, "reachable": False, "error": str(exc)}


@app.get("/health")
async def health() -> dict[str, Any]:
    """Live readiness probe — re-checks binaries, ZAP, DB, and migrations each call."""
    from core.accounts import probe_accounts_db
    from core.migrations import probe_migrations
    from core.toolchain import inspect_toolchain

    orchestrator = get_orchestrator()
    ready = orchestrator._graph is not None  # noqa: SLF001 - health probe
    # Fresh probe (not the startup cache) so rolling ZAP restarts show up here.
    toolchain = inspect_toolchain().as_dict()
    db_ok, db_error = probe_accounts_db()
    migrations_ok, migrations_error = probe_migrations()
    settings = get_settings()
    firecrawl_probe, dodo_probe = await asyncio.gather(
        _probe_firecrawl(settings),
        _probe_dodo(settings),
    )
    upstreams_ok = all(
        probe.get("reachable") is not False for probe in (firecrawl_probe, dodo_probe)
    )
    all_ok = (
        ready
        and toolchain.get("ready", False)
        and db_ok
        and migrations_ok
        and upstreams_ok
    )
    payload: dict[str, Any] = {
        "status": "ok" if all_ok else "degraded",
        "service": settings.app_name,
        "version": app.version,
        "orchestrator_ready": ready,
        "toolchain": toolchain,
        "zap_ready": bool(toolchain.get("zap_ready")),
        "database_ready": db_ok,
        "migrations_current": migrations_ok,
        "upstreams": {
            "firecrawl": firecrawl_probe,
            "dodo": dodo_probe,
        },
    }
    if db_error:
        payload["database_error"] = db_error
    if migrations_error:
        payload["migrations_error"] = migrations_error
    return payload


@app.get("/targets", response_model=TargetsResponse)
async def get_targets(request: Request) -> TargetsResponse:
    """List authorized targets. Requires auth when REQUIRE_FIREBASE_AUTH is on."""
    from core.scope import is_enforcement_enabled

    _require_firebase_if_configured(request)
    return TargetsResponse(
        targets=await _targets_store.get(),
        enforcement_enabled=is_enforcement_enabled(),
    )


@app.put("/targets", response_model=TargetsResponse)
async def put_targets(body: TargetsRequest, request: Request) -> TargetsResponse:
    """Replace authorized targets. Requires auth when REQUIRE_FIREBASE_AUTH is on."""
    from core.scope import is_enforcement_enabled

    _require_firebase_if_configured(request)
    updated = await _targets_store.set(body.targets)
    return TargetsResponse(
        targets=updated,
        enforcement_enabled=is_enforcement_enabled(),
    )


def _targets_match(stored: str, provided: str) -> bool:
    """Compare scan targets after canonical normalization."""
    try:
        return normalize_scan_target(stored, resolve_dns=False) == normalize_scan_target(
            provided, resolve_dns=False
        )
    except SSRFError:
        return stored == provided


def _assert_scan_owner(scan_id: str, request: Request) -> None:
    """Reject access when the caller did not create the scan (IDOR mitigation)."""
    _require_firebase_if_configured(request)
    orchestrator = get_orchestrator()
    owner = orchestrator.get_scan_owner(scan_id)
    if owner is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )
    caller = _get_client_identity(request)
    if owner != caller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )


@app.post("/scan", response_model=ScanCreateResponse, status_code=202)
async def create_scan(body: ScanCreateRequest, request: Request) -> ScanCreateResponse:
    firebase_user = _require_firebase_if_configured(request)
    if firebase_user is None:
        auth_header = request.headers.get("Authorization", "").strip()
        if auth_header.lower().startswith("bearer "):
            firebase_user = try_verify_bearer_token(auth_header[7:].strip())
    try:
        ensure_toolchain_ready()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "toolchain_not_ready",
                "message": str(exc),
                "toolchain": get_toolchain_report().as_dict(),
            },
        ) from exc
    if not body.confirmed_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "authorization_not_confirmed",
                "message": (
                    "You must confirm that you own or are explicitly authorized to "
                    "scan this target before a scan can proceed. Set "
                    "'confirmed_authorized' to true in the request body."
                ),
                "target": body.target,
            },
        )
    try:
        normalized_target = normalize_scan_target(body.target)
    except SSRFError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_scan_target",
                "message": str(exc),
                "target": body.target,
            },
        ) from exc
    enforce_scope(normalized_target)
    account = _resolve_scan_account(request, firebase_user)
    _ensure_verified_for_sensitive_action(firebase_user, account)
    client_id = f"org:{account.org_id}" if account else _get_client_identity(request)
    orchestrator = get_orchestrator()

    existing_scan_id = await _inflight_scans.get_inflight(client_id, normalized_target)
    if existing_scan_id:
        summary = await orchestrator.get_status_summary(existing_scan_id)
        if summary and not summary.get("is_complete"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "scan_already_in_progress",
                    "message": (
                        "A scan for this target is already in progress. "
                        "Poll its status or wait for it to finish."
                    ),
                    "scan_id": existing_scan_id,
                    "target": normalized_target,
                },
            )
        await _inflight_scans.release(existing_scan_id)

    await _scan_rate_limiter.acquire(client_id)

    scan_id = str(uuid.uuid4())
    try:
        await _inflight_scans.register(client_id, normalized_target, scan_id)
        if account is not None:
            try:
                reservation = reserve_scan_quota_and_create_records(
                    scan_id=scan_id,
                    org_id=account.org_id,
                    target=normalized_target,
                    max_targets=account.max_targets,
                    scans_per_month=account.scans_per_month,
                )
            except QuotaExceededError as exc:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": exc.code,
                        "message": str(exc),
                        "limit": exc.limit,
                    },
                ) from exc
            orchestrator.register_scan(scan_id, normalized_target, owner_id=client_id)
            # Register the target as a monitored site; paid plans get a watch job.
            site = reservation.site
            if plan_supports_watch(account.plan_id):
                on_site_added(site.id)
            task = orchestrator.schedule_scan(
                scan_id,
                normalized_target,
                org_id=account.org_id,
                site_id=site.id,
            )
        else:
            orchestrator.register_scan(scan_id, normalized_target, owner_id=client_id)
            task = orchestrator.schedule_scan(scan_id, normalized_target)
    except Exception:
        await _inflight_scans.release(scan_id)
        await _scan_rate_limiter.release(client_id)
        raise

    def _release_slot(_task: asyncio.Task[None]) -> None:
        async def _cleanup() -> None:
            await _inflight_scans.release(scan_id)
            await _scan_rate_limiter.release(client_id)

        asyncio.create_task(_cleanup())

    task.add_done_callback(_release_slot)

    log_scan_triggered(
        scan_id=scan_id,
        target=normalized_target,
        client_id=client_id,
    )
    logger.info(
        "Scan queued",
        extra={"scan_id": scan_id, "target": normalized_target},
    )
    return ScanCreateResponse(
        scan_id=scan_id,
        target=normalized_target,
        status="pending",
    )


@app.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    request: Request,
    target: str | None = None,
) -> ScanStatusResponse:
    _assert_scan_owner(scan_id, request)
    orchestrator = get_orchestrator()
    summary = await orchestrator.get_status_summary(scan_id)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )

    if target is not None:
        enforce_scope(target)
        if not _targets_match(summary["target"], target):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "scan_not_found", "scan_id": scan_id},
            )

    persisted = await _sync_persisted_scan(scan_id)
    return ScanStatusResponse(**(persisted or summary))


@app.post("/scan/{scan_id}/approve", response_model=ScanApprovalResponse)
async def approve_scan(
    scan_id: str,
    body: ScanApprovalRequest,
    request: Request,
) -> ScanApprovalResponse:
    _assert_scan_owner(scan_id, request)
    orchestrator = get_orchestrator()
    registered_target = orchestrator.get_registered_target(scan_id)
    if registered_target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )

    if body.target is not None:
        enforce_scope(body.target)
        if body.target is not None and not _targets_match(registered_target, body.target):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "scan_not_found", "scan_id": scan_id},
            )

    summary = await orchestrator.get_status_summary(scan_id)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )

    if summary["is_complete"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "scan_already_complete", "scan_id": scan_id},
        )

    if summary["pending_interrupt"] is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "not_awaiting_approval",
                "scan_id": scan_id,
                "current_node": summary.get("current_node"),
            },
        )

    planned_active_tests: list[str] = list(
        (summary["pending_interrupt"].get("value") or {}).get("planned_active_tests", [])
    )

    if body.approved_tools is not None:
        requested = {str(t).strip().lower() for t in body.approved_tools if str(t).strip()}
        unknown = sorted(requested - set(planned_active_tests))
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "unknown_active_tool",
                    "message": (
                        "approved_tools contains tools that are not part of "
                        "this scan's planned active tests."
                    ),
                    "unknown_tools": unknown,
                    "planned_active_tests": planned_active_tests,
                },
            )

    approved_tools = resolve_approved_tools(
        planned_active_tests,
        approved=body.approved,
        approved_tools=body.approved_tools,
    )
    rejected_tools = [t for t in planned_active_tests if t not in approved_tools]
    human_approved = bool(approved_tools)

    # Resume the graph in the background. The remaining pipeline (active
    # detection via sqlmap/ZAP, verification, scoring, reporting) can take
    # minutes; awaiting it here would block the HTTP response and freeze the
    # extension's approval dialog. The client polls /status for progress.
    orchestrator.schedule_resume(
        scan_id,
        approved=human_approved,
        approved_tools=approved_tools,
    )

    return ScanApprovalResponse(
        scan_id=scan_id,
        target=body.target or registered_target,
        status="running" if human_approved else "rejected",
        human_approved=human_approved,
        approved_tools=approved_tools,
        rejected_tools=rejected_tools,
        is_complete=False,
    )


@app.get("/scan/{scan_id}/report", response_model=ScanReportResponse)
async def get_scan_report(
    scan_id: str,
    request: Request,
    target: str | None = None,
) -> ScanReportResponse:
    _assert_scan_owner(scan_id, request)
    orchestrator = get_orchestrator()
    summary = await orchestrator.get_status_summary(scan_id)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )

    if target is not None:
        enforce_scope(target)
        if not _targets_match(summary["target"], target):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "scan_not_found", "scan_id": scan_id},
            )

    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    values = dict(snapshot.values) if (snapshot and snapshot.values) else {}

    from agents.reporting import build_coverage_section
    from core.verify_fix import get_scan_verify_summaries

    report = values.get("report")
    coverage: dict[str, Any] | None = None
    if isinstance(report, dict):
        coverage = report.get("coverage") or build_coverage_section(report)
    elif values.get("severity_scores"):
        coverage = build_coverage_section(
            {"severity_scores": values.get("severity_scores") or {}}
        )

    return ScanReportResponse(
        scan_id=scan_id,
        target=summary["target"],
        status=values.get("status", summary["status"]),
        findings=values.get("findings", []),
        report=report,
        generated_at=datetime.now(timezone.utc).isoformat(),
        verify_fix_summaries=get_scan_verify_summaries(scan_id),
        coverage=coverage,
    )


@app.get("/scan/{scan_id}/report/{report_format}", response_model=None)
async def get_scan_report_format(
    scan_id: str,
    report_format: str,
    request: Request,
    target: str | None = None,
) -> Response:
    _assert_scan_owner(scan_id, request)
    report_format = report_format.lower()
    if report_format not in {"json", "md", "html", "pdf"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_report_format",
                "message": "Supported formats: json, md, html, pdf",
            },
        )

    orchestrator = get_orchestrator()
    summary = await orchestrator.get_status_summary(scan_id)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )

    effective_target = target or summary["target"]
    enforce_scope(effective_target)

    if not _targets_match(summary["target"], effective_target):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "scan_not_found", "scan_id": scan_id},
        )

    reports_root = Path(__file__).resolve().parent.parent / "reports" / scan_id
    artifact_map = {
        "json": reports_root / "report.json",
        "md": reports_root / "report.md",
        "html": reports_root / "report.html",
        "pdf": reports_root / "report.pdf",
    }
    report_path = artifact_map[report_format]

    if not report_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "report_not_ready",
                "message": "Report artifacts are not available yet for this scan.",
                "scan_id": scan_id,
            },
        )

    if report_format == "json":
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        return JSONResponse(content=report_data)
    if report_format == "md":
        return PlainTextResponse(report_path.read_text(encoding="utf-8"), media_type="text/markdown")
    if report_format == "pdf":
        return FileResponse(
            report_path,
            media_type="application/pdf",
            filename=f"checkmate-{scan_id}.pdf",
        )
    return FileResponse(report_path, media_type="text/html")


async def _load_scan_findings(scan_id: str) -> list[dict[str, Any]]:
    """Load findings from graph state, falling back to the on-disk JSON report."""
    orchestrator = get_orchestrator()
    snapshot = await orchestrator.get_graph_snapshot(scan_id)
    values = dict(snapshot.values) if (snapshot and snapshot.values) else {}
    findings = values.get("findings")
    if isinstance(findings, list) and findings:
        return [dict(f) for f in findings if isinstance(f, dict)]

    report_path = Path(__file__).resolve().parent.parent / "reports" / scan_id / "report.json"
    if report_path.is_file():
        data = json.loads(report_path.read_text(encoding="utf-8"))
        by_sev = data.get("findings_by_severity") or {}
        flat: list[dict[str, Any]] = []
        for severity in ("critical", "high", "medium", "low", "info"):
            for finding in by_sev.get(severity) or []:
                if isinstance(finding, dict):
                    flat.append(dict(finding))
        if flat:
            return flat
    return []


def _org_id_for_scan_request(request: Request, scan_id: str) -> str:
    """Resolve the org that owns this scan (for verify-fix history rows)."""
    firebase_user = _require_firebase_if_configured(request)
    if firebase_user is not None:
        account = _account_for_firebase_user(firebase_user)
        return account.org_id
    record = get_scan_record(scan_id)
    if record is not None:
        return record.org_id
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": "scan_not_found", "scan_id": scan_id},
    )


@app.post(
    "/scan/{scan_id}/findings/{finding_id}/verify-fix",
    response_model=VerifyFixResponse,
)
async def verify_finding_fix(
    scan_id: str,
    finding_id: str,
    request: Request,
) -> VerifyFixResponse:
    """Narrow single-finding re-check. Does not consume monthly scan quota."""
    from core.verify_fix import (
        FindingNotFound,
        VerifyFixRateLimited,
        get_scan_verify_summaries,
        run_verify_fix,
    )

    _assert_scan_owner(scan_id, request)
    org_id = _org_id_for_scan_request(request, scan_id)
    findings = await _load_scan_findings(scan_id)
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "findings_not_ready",
                "message": "Findings are not available yet for this scan.",
                "scan_id": scan_id,
            },
        )

    # Snapshot usage before the check so tests can assert quota is unchanged.
    usage_before = get_org_scan_usage(org_id)

    try:
        result = await run_verify_fix(
            scan_id=scan_id,
            org_id=org_id,
            finding_id=finding_id,
            findings=findings,
        )
    except FindingNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": exc.code, "message": exc.message, "finding_id": finding_id},
        ) from exc
    except VerifyFixRateLimited as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": exc.code,
                "message": exc.message,
                "retry_after_seconds": exc.retry_after_seconds,
            },
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc

    usage_after = get_org_scan_usage(org_id)
    if usage_after != usage_before:
        # Defensive: verify-fix must never create a full-scan quota row.
        logger.error(
            "Verify Fix unexpectedly changed scan quota",
            extra={"scan_id": scan_id, "before": usage_before, "after": usage_after},
        )

    # Touch summaries so future GET report enrichment stays warm.
    get_scan_verify_summaries(scan_id)
    return VerifyFixResponse(**result)


@app.get("/scan/{scan_id}/findings/{finding_id}/verify-fix")
async def get_finding_verify_fix_history(
    scan_id: str,
    finding_id: str,
    request: Request,
) -> dict[str, Any]:
    """Return verification history for a finding (latest first)."""
    from core.accounts import list_finding_fix_verifications
    from core.verify_fix import get_scan_verify_summaries

    _assert_scan_owner(scan_id, request)
    history = list_finding_fix_verifications(scan_id, finding_id)
    summaries = get_scan_verify_summaries(scan_id)
    latest = summaries.get(finding_id)
    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "latest": latest,
        "history": history,
        "attempt_count": len(history),
        "quota_consumed": False,
    }


@app.get("/scan/{scan_id}/verify-fix/summaries")
async def get_scan_verify_fix_summaries(
    scan_id: str,
    request: Request,
) -> dict[str, Any]:
    """Latest Verify Fix status for every finding on a scan."""
    from core.verify_fix import get_scan_verify_summaries

    _assert_scan_owner(scan_id, request)
    return {
        "scan_id": scan_id,
        "summaries": get_scan_verify_summaries(scan_id),
    }
