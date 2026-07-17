"""Tests for Firebase auth sync, free-plan org creation, and token verification."""

from __future__ import annotations

import pytest
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
) -> AuthenticatedUser:
    return AuthenticatedUser(
        uid=uid,
        email=email,
        email_verified=True,
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


def test_verify_id_token_rejects_empty():
    from core.firebase_auth import verify_id_token

    with pytest.raises(HTTPException) as excinfo:
        verify_id_token("")
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail["error"] == "missing_token"
