"""IDOR and scan ownership tests."""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient


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
