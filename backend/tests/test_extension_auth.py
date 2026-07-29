"""Tests for Chrome extension token minting and identity resolution."""

from __future__ import annotations

import pytest
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from core.accounts import (
    configure_accounts_db,
    init_accounts_schema,
    resolve_extension_token,
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
) -> AuthenticatedUser:
    return AuthenticatedUser(
        uid=uid,
        email=email,
        email_verified=True,
        name="Test User",
        picture=None,
        sign_in_provider="password",
        claims={"uid": uid, "email": email},
    )


@pytest.fixture
def auth_client(accounts_db, monkeypatch: pytest.MonkeyPatch):
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
        return _fake_user()

    monkeypatch.setattr(fa, "verify_id_token", _verify)

    from app.main import app

    with TestClient(app) as client:
        yield client
    get_settings.cache_clear()


def _sync(client: TestClient) -> None:
    response = client.post(
        "/auth/sync",
        headers={"Authorization": "Bearer valid-token"},
        json={"terms_accepted": True, "terms_version": "2026-07-17"},
    )
    assert response.status_code == 200


def test_mint_extension_token_requires_auth(auth_client: TestClient):
    response = auth_client.post("/auth/extension/token")
    assert response.status_code == 401


def test_mint_extension_token_requires_synced_user(auth_client: TestClient):
    response = auth_client.post(
        "/auth/extension/token",
        headers={"Authorization": "Bearer valid-token"},
    )
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "user_not_found"


def test_mint_and_resolve_extension_token(auth_client: TestClient):
    _sync(auth_client)
    response = auth_client.post(
        "/auth/extension/token",
        headers={"Authorization": "Bearer valid-token"},
        json={"label": "chrome-extension"},
    )
    assert response.status_code == 200
    body = response.json()
    token = body["token"]
    assert token.startswith("cmext_")
    assert body["token_meta"]["key_prefix"] == token[:12]

    resolved = resolve_extension_token(token)
    assert resolved is not None
    assert resolved.user_id == "firebase-uid-1"
    assert resolved.org_id == body["token_meta"]["org_id"]


def test_extension_token_mint_rate_limit_returns_429(auth_client: TestClient):
    _sync(auth_client)
    from app import main as api_main
    from core.config import get_settings

    settings = get_settings()
    old_account_limit = settings.auth_rate_limit_max_requests_per_account
    old_ip_limit = settings.auth_rate_limit_max_requests_per_ip
    settings.auth_rate_limit_max_requests_per_account = 1
    settings.auth_rate_limit_max_requests_per_ip = 100
    api_main._auth_rate_limiter._events.clear()  # noqa: SLF001 - isolate boundary test
    try:
        first = auth_client.post(
            "/auth/extension/token",
            headers={"Authorization": "Bearer valid-token"},
        )
        second = auth_client.post(
            "/auth/extension/token",
            headers={"Authorization": "Bearer valid-token"},
        )
    finally:
        settings.auth_rate_limit_max_requests_per_account = old_account_limit
        settings.auth_rate_limit_max_requests_per_ip = old_ip_limit
        api_main._auth_rate_limiter._events.clear()  # noqa: SLF001

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["error"] == "auth_rate_limit_exceeded"


def test_revoke_extension_tokens(auth_client: TestClient):
    _sync(auth_client)
    minted = auth_client.post(
        "/auth/extension/token",
        headers={"Authorization": "Bearer valid-token"},
    )
    token = minted.json()["token"]
    assert resolve_extension_token(token) is not None

    revoked = auth_client.post(
        "/auth/extension/revoke",
        headers={"Authorization": "Bearer valid-token"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] >= 1
    assert resolve_extension_token(token) is None


def test_extension_token_maps_to_org_identity(auth_client: TestClient):
    _sync(auth_client)
    minted = auth_client.post(
        "/auth/extension/token",
        headers={"Authorization": "Bearer valid-token"},
    )
    token = minted.json()["token"]
    org_id = minted.json()["token_meta"]["org_id"]

    from app.main import _get_client_identity
    from starlette.requests import Request

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/health",
        "raw_path": b"/health",
        "query_string": b"",
        "headers": [
            (b"authorization", f"bearer {token}".encode()),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    request = Request(scope)
    assert _get_client_identity(request) == f"org:{org_id}"
