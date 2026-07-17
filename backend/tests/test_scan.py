"""API smoke tests."""

import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def test_scan_accepts_out_of_scope_target(client: TestClient, fast_scan: None) -> None:
    """Allowlist enforcement is disabled; any public target is accepted with 202."""
    response = client.post(
        "/scan",
        json={"target": "https://evil.example.com", "confirmed_authorized": True},
    )
    assert response.status_code == 202
    body = response.json()
    assert "scan_id" in body
    assert body["status"] == "pending"


def test_scan_accepts_authorized_target(client: TestClient, fast_scan: None) -> None:
    response = client.post(
        "/scan",
        json={"target": "https://authorized.example.com", "confirmed_authorized": True},
    )
    assert response.status_code == 202
    body = response.json()
    assert "scan_id" in body
    assert body["status"] == "pending"


def test_approve_endpoint_resumes_scan(client: TestClient, fast_scan: None) -> None:
    import time

    target = "https://authorized.example.com"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
    )
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
    # Approval returns immediately; the scan resumes in the background.
    assert approve.status_code == 200
    assert approve.json()["human_approved"] is True

    deadline = time.monotonic() + 5.0
    completed = False
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status", params={"target": target})
        assert status.status_code == 200
        if status.json().get("is_complete"):
            completed = True
            break
        time.sleep(0.05)
    assert completed is True


def test_status_and_approve_work_without_target(client: TestClient, fast_scan: None) -> None:
    """Extension calls status/approve without resending the target."""
    import time

    target = "https://authorized.example.com"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
    )
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
    # Approval returns immediately; the scan resumes in the background.
    assert approve.status_code == 200
    assert approve.json()["human_approved"] is True

    deadline = time.monotonic() + 5.0
    completed = False
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status")
        assert status.status_code == 200
        if status.json().get("is_complete"):
            completed = True
            break
        time.sleep(0.05)
    assert completed is True


def test_approve_endpoint_allows_per_tool_selection(client: TestClient, fast_scan: None) -> None:
    """Approving sqlmap only should reject zap and still resume to completion."""
    import time

    target = "https://authorized.example.com"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
    )
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
    planned = status_body["pending_interrupt"]["value"]["planned_active_tests"]
    assert set(planned) == {"sqlmap", "zap"}

    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"target": target, "approved_tools": ["sqlmap"]},
    )
    assert approve.status_code == 200
    body = approve.json()
    assert body["human_approved"] is True
    assert body["approved_tools"] == ["sqlmap"]
    assert body["rejected_tools"] == ["zap"]

    deadline = time.monotonic() + 5.0
    completed = False
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status", params={"target": target})
        assert status.status_code == 200
        status_body = status.json()
        if status_body.get("is_complete"):
            completed = True
            break
        time.sleep(0.05)
    assert completed is True
    assert status_body["approved_tools"] == ["sqlmap"]
    assert status_body["rejected_tools"] == ["zap"]


def test_approve_endpoint_rejects_unknown_tool_name(client: TestClient, fast_scan: None) -> None:
    """approved_tools must be a subset of this scan's planned_active_tests."""
    import time

    target = "https://authorized.example.com"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    deadline = time.monotonic() + 5.0
    status_body: dict | None = None
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status", params={"target": target})
        status_body = status.json()
        if status_body.get("pending_interrupt"):
            break
        time.sleep(0.05)
    assert status_body is not None and status_body.get("pending_interrupt")

    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"target": target, "approved_tools": ["nmap"]},
    )
    assert approve.status_code == 400
    assert approve.json()["detail"]["error"] == "unknown_active_tool"


def test_approve_endpoint_empty_approved_tools_rejects_all(
    client: TestClient, fast_scan: None
) -> None:
    """An explicit empty approved_tools list rejects every active tool."""
    import time

    target = "https://authorized.example.com"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    deadline = time.monotonic() + 5.0
    status_body: dict | None = None
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status", params={"target": target})
        status_body = status.json()
        if status_body.get("pending_interrupt"):
            break
        time.sleep(0.05)
    assert status_body is not None and status_body.get("pending_interrupt")

    approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"target": target, "approved_tools": []},
    )
    assert approve.status_code == 200
    body = approve.json()
    assert body["human_approved"] is False
    assert body["approved_tools"] == []


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


def test_failed_approval_post_does_not_resume_scan(
    client: TestClient,
    fast_scan: None,
) -> None:
    """If approval POST fails, scan must remain paused at approval gate."""
    import time

    headers = {"X-API-Key": "approval-contract"}
    target = "https://authorized.example.com"
    create = client.post(
        "/scan",
        json={"target": target, "confirmed_authorized": True},
        headers=headers,
    )
    assert create.status_code == 202
    scan_id = create.json()["scan_id"]

    deadline = time.monotonic() + 5.0
    paused = None
    while time.monotonic() < deadline:
        status = client.get(f"/scan/{scan_id}/status", headers=headers)
        assert status.status_code == 200
        paused = status.json()
        if paused.get("pending_interrupt"):
            break
        time.sleep(0.05)
    assert paused is not None
    assert paused["pending_interrupt"] is not None
    assert paused["status"] == "awaiting_approval"

    failed_approve = client.post(
        f"/scan/{scan_id}/approve",
        json={"approved_tools": ["not-a-real-tool"]},
        headers=headers,
    )
    assert failed_approve.status_code == 400

    # Contract guarantee for extension auto-approve failures: no successful
    # approve call means the backend must keep the scan paused.
    time.sleep(0.2)
    status_after = client.get(f"/scan/{scan_id}/status", headers=headers)
    assert status_after.status_code == 200
    body = status_after.json()
    assert body["pending_interrupt"] is not None
    assert body["status"] == "awaiting_approval"
    assert body["is_complete"] is False


@pytest.mark.asyncio
async def test_targets_persist_across_store_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Options /targets data survives backend restart via targets.json."""
    from app.main import TargetsStore

    targets_file = tmp_path / "targets.json"
    monkeypatch.setattr("app.main._TARGETS_FILE", targets_file)

    store_a = TargetsStore()
    saved = await store_a.set(["example.com", "https://api.example.com/v1"])
    assert saved == ["api.example.com", "example.com"]
    assert targets_file.exists()

    store_b = TargetsStore()
    loaded = await store_b.get()
    assert loaded == ["api.example.com", "example.com"]
