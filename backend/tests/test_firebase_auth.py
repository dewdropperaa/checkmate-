"""Tests for Firebase auth sync, free-plan org creation, and token verification."""

from __future__ import annotations

import pytest
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from core.accounts import (
    FREE_MAX_TARGETS,
    FREE_PLAN_ID,
    FREE_SCANS_PER_MONTH,
    configure_accounts_db,
    get_user,
    init_accounts_schema,
)
from core.firebase_auth import AuthenticatedUser


@pytest.fixture
def accounts_db(tmp_path):
    db_path = tmp_path / "accounts.db"
    configure_accounts_db(db_path)
    init_accounts_schema()
    yield db_path
    configure_accounts_db(None)


def _fake_user(
    *,
    uid: str = "firebase-uid-1",
    email: str = "user@example.com",
    provider: str = "password",
    email_verified: bool = True,
) -> AuthenticatedUser:
    return AuthenticatedUser(
        uid=uid,
        email=email,
        email_verified=email_verified,
        name="Test User",
        picture=None,
        sign_in_provider=provider,
        claims={"uid": uid, "email": email},
    )


@pytest.fixture
def auth_client(accounts_db, monkeypatch: pytest.MonkeyPatch):
    """TestClient with Firebase verification mocked."""
    from core.config import get_settings
    import core.firebase_auth as fa

    get_settings.cache_clear()

    def _verify(token: str) -> AuthenticatedUser:
        if token in {"invalid", "expired", ""}:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "invalid_token",
                    "message": "Invalid or expired authentication token.",
                },
            )
        if token == "google-token":
            return _fake_user(
                uid="google-uid-1",
                email="g@example.com",
                provider="google.com",
            )
        if token == "unverified-token":
            return _fake_user(
                uid="firebase-uid-1",
                email="user@example.com",
                provider="password",
                email_verified=False,
            )
        return _fake_user(
            uid="firebase-uid-1",
            email="user@example.com",
            provider="password",
        )

    monkeypatch.setattr(fa, "verify_id_token", _verify)

    from app.main import app

    with TestClient(app) as client:
        yield client
    get_settings.cache_clear()


def test_auth_sync_creates_user_and_free_org(auth_client: TestClient):
    response = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer valid-token"},
        json={"terms_accepted": True, "terms_version": "2026-07-17"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["created"] is True
    user = body["user"]
    assert user["id"] == "firebase-uid-1"
    assert user["email"] == "user@example.com"
    assert user["plan_id"] == FREE_PLAN_ID
    assert user["max_targets"] == FREE_MAX_TARGETS
    assert user["scans_per_month"] == FREE_SCANS_PER_MONTH
    assert user["org_id"]
    assert user["terms_accepted_at"]
    assert user["terms_version"] == "2026-07-17"

    stored = get_user("firebase-uid-1")
    assert stored is not None
    assert stored.plan_id == FREE_PLAN_ID
    assert stored.terms_version == "2026-07-17"


def test_auth_sync_rejects_new_user_without_terms(auth_client: TestClient):
    response = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer valid-token"},
        json={},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "terms_required"
    assert get_user("firebase-uid-1") is None


def test_auth_sync_rejects_unverified_new_user(auth_client: TestClient):
    response = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer unverified-token"},
        json={"terms_accepted": True, "terms_version": "2026-07-17"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "email_not_verified"
    assert get_user("firebase-uid-1") is None


def test_sensitive_route_rejects_unverified_firebase_user(auth_client: TestClient):
    response = auth_client.post(
        "/auth/extension/token",
        headers={"Authorization": "Bearer unverified-token"},
        json={},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "email_not_verified"


def test_auth_sync_is_idempotent(auth_client: TestClient):
    first = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer valid-token"},
        json={"terms_accepted": True, "terms_version": "2026-07-17"},
    )
    second = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer valid-token"},
        json={},
    )
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert first.json()["user"]["org_id"] == second.json()["user"]["org_id"]


def test_google_sign_in_creates_backend_user(auth_client: TestClient):
    response = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer google-token"},
        json={"terms_accepted": True, "terms_version": "2026-07-17"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["created"] is True
    assert body["user"]["id"] == "google-uid-1"
    assert body["user"]["auth_provider"] == "google.com"
    assert body["user"]["plan_id"] == FREE_PLAN_ID
    assert body["user"]["terms_version"] == "2026-07-17"


def test_invalid_token_rejected(auth_client: TestClient):
    response = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer invalid"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "invalid_token"


def test_auth_sync_ip_rate_limit_returns_429(auth_client: TestClient):
    from app import main as api_main
    from core.config import get_settings

    settings = get_settings()
    old_ip_limit = settings.auth_rate_limit_max_requests_per_ip
    old_account_limit = settings.auth_rate_limit_max_requests_per_account
    settings.auth_rate_limit_max_requests_per_ip = 1
    settings.auth_rate_limit_max_requests_per_account = 100
    api_main._auth_rate_limiter._events.clear()  # noqa: SLF001 - isolate boundary test
    try:
        first = auth_client.post(
            "/auth/sync",
            headers={"Authorization": "Bearer invalid"},
        )
        second = auth_client.post(
            "/auth/sync",
            headers={"Authorization": "Bearer invalid"},
        )
    finally:
        settings.auth_rate_limit_max_requests_per_ip = old_ip_limit
        settings.auth_rate_limit_max_requests_per_account = old_account_limit
        api_main._auth_rate_limiter._events.clear()  # noqa: SLF001

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.json()["detail"]["error"] == "auth_rate_limit_exceeded"


def test_expired_token_rejected(auth_client: TestClient):
    response = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer expired"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "invalid_token"


def test_missing_token_rejected(auth_client: TestClient):
    response = auth_client.post("/auth/sync")
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "missing_token"


def test_atomic_scan_quota_allows_exactly_one_concurrent_trigger(
    auth_client: TestClient,
    accounts_db,
    public_dns: None,
    fast_scan: None,
):
    sync = auth_client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer valid-token"},
        json={"terms_accepted": True, "terms_version": "2026-07-17"},
    )
    assert sync.status_code == 200
    org_id = sync.json()["user"]["org_id"]
    with sqlite3.connect(accounts_db) as conn:
        conn.execute(
            "UPDATE organizations SET max_targets = NULL, scans_per_month = 1 WHERE id = ?",
            (org_id,),
        )
        conn.commit()

    from core.config import get_settings

    settings = get_settings()
    old_per_client = settings.scan_rate_limit_max_concurrent_per_client
    old_global = settings.scan_rate_limit_max_concurrent_global
    old_require_auth = settings.require_firebase_auth
    settings.scan_rate_limit_max_concurrent_per_client = 10
    settings.scan_rate_limit_max_concurrent_global = 10
    settings.require_firebase_auth = True

    payloads = [
        {"target": "https://race-a.authorized.example.com", "confirmed_authorized": True},
        {"target": "https://race-b.authorized.example.com", "confirmed_authorized": True},
    ]

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(
                    lambda payload: auth_client.post(
                        "/scan",
                        headers={"Authorization": "Bearer valid-token"},
                        json=payload,
                    ),
                    payloads,
                )
            )
    finally:
        settings.scan_rate_limit_max_concurrent_per_client = old_per_client
        settings.scan_rate_limit_max_concurrent_global = old_global
        settings.require_firebase_auth = old_require_auth

    statuses = sorted(response.status_code for response in responses)
    assert statuses == [202, 429]
    errors = [
        response.json()["detail"]["error"]
        for response in responses
        if response.status_code == 429
    ]
    assert errors == ["scan_quota_exceeded"]


def test_verify_id_token_rejects_empty():
    from core.firebase_auth import verify_id_token

    with pytest.raises(HTTPException) as excinfo:
        verify_id_token("")
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail["error"] == "missing_token"


def test_missing_credentials_path_returns_503_not_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
):
    """Laptop Windows paths on a Linux container must not look like bad JWTs."""
    import core.firebase_auth as fa
    from core.config import Settings, get_settings

    get_settings.cache_clear()
    fa._firebase_ready = False  # noqa: SLF001
    monkeypatch.setattr(
        fa,
        "get_settings",
        lambda: Settings(
            app_env="development",
            firebase_project_id="checkmate-68921",
            firebase_credentials_path="C:/Users/pc/Desktop/scan/missing-sa.json",
            firebase_credentials_json=None,
        ),
    )
    # Ensure no leftover Admin app from other tests.
    import firebase_admin

    for app in list(firebase_admin._apps.values()):  # type: ignore[attr-defined]
        firebase_admin.delete_app(app)

    with pytest.raises(HTTPException) as excinfo:
        fa.verify_id_token("header.payload.sig")
    assert excinfo.value.status_code == 503
    assert excinfo.value.detail["error"] == "auth_misconfigured"
    get_settings.cache_clear()
    fa._firebase_ready = False  # noqa: SLF001
