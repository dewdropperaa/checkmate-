"""IDOR and scan ownership tests."""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient

from core.accounts import (
    configure_accounts_db,
    create_scan_record,
    init_accounts_schema,
    upsert_user_from_firebase,
)
from core.firebase_auth import AuthenticatedUser


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock DNS so example.com resolves to a public IP."""
    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: fake_results)


def test_scan_idor_cross_client_denied(client: TestClient, public_dns: None) -> None:
    """Client A cannot read or approve Client B's scan by UUID alone."""
    owner_headers = {"X-API-Key": "org-a-key"}
    attacker_headers = {"X-API-Key": "org-b-key"}

    create = client.post(
        "/scan",
        json={"target": "https://example.com", "confirmed_authorized": True},
        headers=owner_headers,
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    status = client.get(f"/scan/{scan_id}/status", headers=attacker_headers)
    assert status.status_code == 404
    assert status.json()["detail"]["error"] == "scan_not_found"

    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"approved": True},
        headers=attacker_headers,
    )
    assert approve.status_code == 404

    report = client.get(f"/scan/{scan_id}/report", headers=attacker_headers)
    assert report.status_code == 404


def test_scan_owner_can_access(client: TestClient, public_dns: None) -> None:
    headers = {"X-API-Key": "same-client"}
    create = client.post(
        "/scan",
        json={"target": "https://example.com", "confirmed_authorized": True},
        headers=headers,
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    status = client.get(f"/scan/{scan_id}/status", headers=headers)
    assert status.status_code == 200


def test_scan_idor_cross_client_denied_with_bearer_tokens(
    client: TestClient,
    public_dns: None,
) -> None:
    """Bearer tokens map to the same ownership model as X-API-Key."""
    owner_headers = {"Authorization": "Bearer tenant-a"}
    attacker_headers = {"Authorization": "Bearer tenant-b"}

    create = client.post(
        "/scan",
        json={"target": "https://example.com", "confirmed_authorized": True},
        headers=owner_headers,
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    status = client.get(f"/scan/{scan_id}/status", headers=attacker_headers)
    assert status.status_code == 404
    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"approved": True},
        headers=attacker_headers,
    )
    assert approve.status_code == 404
    report = client.get(f"/scan/{scan_id}/report", headers=attacker_headers)
    assert report.status_code == 404


def test_scan_history_only_returns_authenticated_org_scans(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The history route derives its org from the verified token, not input."""
    configure_accounts_db(tmp_path / "accounts.db")
    init_accounts_schema()
    try:
        user_a, _ = upsert_user_from_firebase(
            uid="user-a",
            email="a@example.com",
            display_name="A",
            email_verified=True,
            auth_provider="password",
        )
        user_b, _ = upsert_user_from_firebase(
            uid="user-b",
            email="b@example.com",
            display_name="B",
            email_verified=True,
            auth_provider="password",
        )
        create_scan_record(
            scan_id="scan-a",
            org_id=user_a.org_id,
            target="https://a.example.com",
        )
        create_scan_record(
            scan_id="scan-b",
            org_id=user_b.org_id,
            target="https://b.example.com",
        )

        def _verify(token: str) -> AuthenticatedUser:
            uid = "user-a" if token == "token-a" else "user-b"
            return AuthenticatedUser(
                uid=uid,
                email=f"{uid}@example.com",
                email_verified=True,
                name=uid,
                picture=None,
                sign_in_provider="password",
                claims={"uid": uid},
            )

        monkeypatch.setattr("core.firebase_auth.verify_id_token", _verify)
        from app.main import app

        with TestClient(app) as test_client:
            response = test_client.get(
                "/orgs/me/scans",
                headers={"Authorization": "Bearer token-a"},
            )

        assert response.status_code == 200
        assert [scan["id"] for scan in response.json()["scans"]] == ["scan-a"]
        assert response.json()["total"] == 1
    finally:
        configure_accounts_db(None)
