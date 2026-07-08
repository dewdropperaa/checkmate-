"""API smoke tests."""

from fastapi.testclient import TestClient


def test_scan_accepts_out_of_scope_target(client: TestClient) -> None:
    """Allowlist enforcement is disabled; any target is accepted with 202."""
    response = client.post("/scan", json={"target": "https://evil.example.com"})
    assert response.status_code == 202
    body = response.json()
    assert "scan_id" in body
    assert body["status"] == "pending"


def test_scan_accepts_authorized_target(client: TestClient) -> None:
    response = client.post("/scan", json={"target": "https://authorized.example.com"})
    assert response.status_code == 202
    body = response.json()
    assert "scan_id" in body
    assert body["status"] == "pending"


def test_approve_endpoint_resumes_scan(client: TestClient) -> None:
    import time

    target = "https://authorized.example.com"
    create = client.post("/scan", json={"target": target})
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    deadline = time.monotonic() + 5.0
    status_body: dict | None = None
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status", params={"target": target})
        assert status.status_code == 200
        status_body = status.json()
        if status_body.get("pending_interrupt"):
            break
        time.sleep(0.05)

    assert status_body is not None
    assert status_body["pending_interrupt"] is not None

    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"target": target, "approved": True},
    )
    assert approve.status_code == 200
    assert approve.json()["is_complete"] is True
    assert approve.json()["human_approved"] is True


def test_status_and_approve_work_without_target(client: TestClient) -> None:
    """Extension calls status/approve without resending the target."""
    import time

    target = "https://authorized.example.com"
    create = client.post("/scan", json={"target": target})
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    deadline = time.monotonic() + 5.0
    status_body: dict | None = None
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status")
        assert status.status_code == 200
        status_body = status.json()
        if status_body.get("pending_interrupt"):
            break
        time.sleep(0.05)

    assert status_body is not None
    assert status_body["pending_interrupt"] is not None

    approve = client.post(f"/scan/{scan_id}/approve", json={"approved": True})
    assert approve.status_code == 200
    assert approve.json()["is_complete"] is True


def test_targets_get_and_put(client: TestClient) -> None:
    """The /targets endpoint the extension relies on exists and round-trips."""
    initial = client.get("/targets")
    assert initial.status_code == 200
    body = initial.json()
    assert "targets" in body
    assert "enforcement_enabled" in body

    updated = client.put("/targets", json={"targets": ["example.com", "https://app.test.io/x"]})
    assert updated.status_code == 200
    saved = updated.json()["targets"]
    assert "example.com" in saved
    assert "app.test.io" in saved
