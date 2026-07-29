"""Authenticated scanning: encryption, exclusions, plan gates, pipeline coverage."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from core.accounts import (
    configure_accounts_db,
    delete_site_auth_credentials,
    get_site_auth_credentials,
    init_accounts_schema,
    update_organization_plan,
    upsert_site,
    upsert_site_auth_credentials,
    upsert_user_from_firebase,
)
from core.auth_scan import (
    build_public_auth_meta,
    load_runtime_auth,
    redact_auth_fields_from_state,
)
from core.credential_crypto import (
    decrypt_credentials,
    encrypt_credentials,
    redact_username,
)
from core.destructive_actions import (
    detect_destructive_paths,
    filter_excluded_urls,
    is_destructive_form,
    path_matches_exclusion,
)
from core.firebase_auth import AuthenticatedUser
from core.plans import can_use_authenticated_scanning, plan_supports_authenticated_scanning
from tools.base import ToolResult
from tools.schemas import Finding, Severity


@pytest.fixture
def accounts_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / "accounts.db"
    configure_accounts_db(db)
    init_accounts_schema()
    monkeypatch.setenv(
        "CREDENTIALS_MASTER_KEY",
        Fernet.generate_key().decode(),
    )
    yield db
    configure_accounts_db(None)


@pytest.fixture
def pro_org(accounts_db):
    user, _ = upsert_user_from_firebase(
        uid="user-pro-auth",
        email="pro@example.com",
        display_name="Pro User",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    update_organization_plan(user.org_id, plan_id="pro")
    return user


@pytest.fixture
def starter_org(accounts_db):
    user, _ = upsert_user_from_firebase(
        uid="user-starter-auth",
        email="starter@example.com",
        display_name="Starter User",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    update_organization_plan(user.org_id, plan_id="starter")
    return user


def _auth_user(user) -> AuthenticatedUser:
    return AuthenticatedUser(
        uid=user.id,
        email=user.email,
        email_verified=True,
        name=user.display_name,
        picture=None,
        sign_in_provider="password",
        claims={"uid": user.id, "email": user.email},
    )


def test_envelope_encryption_roundtrip(accounts_db, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    blob = encrypt_credentials("alice@example.com", "s3cret-pass!")
    assert isinstance(blob.encrypted_data_key, bytes)
    assert isinstance(blob.ciphertext, bytes)
    assert b"alice" not in blob.ciphertext
    assert b"s3cret" not in blob.ciphertext
    assert b"alice" not in blob.encrypted_data_key

    plain = decrypt_credentials(blob)
    assert plain.username == "alice@example.com"
    assert plain.password == "s3cret-pass!"


def test_credentials_never_plaintext_in_db(accounts_db, pro_org, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    site = upsert_site(org_id=pro_org.org_id, target="https://authorized.example.com/")
    username = "scan-user@example.com"
    password = "SuperSecretPassword99!"
    blob = encrypt_credentials(username, password)
    upsert_site_auth_credentials(
        site_id=site.id,
        org_id=pro_org.org_id,
        login_url="https://authorized.example.com/login",
        username_field="email",
        password_field="password",
        encrypted_data_key=blob.encrypted_data_key,
        encrypted_payload=blob.ciphertext,
        username_hint=redact_username(username),
        credentials_consent_user_id=pro_org.id,
        excluded_paths=["/delete-account"],
    )

    conn = sqlite3.connect(str(accounts_db))
    raw = conn.execute("SELECT * FROM site_auth_credentials").fetchone()
    conn.close()
    dumped = repr(raw)
    assert username not in dumped
    assert password not in dumped

    record = get_site_auth_credentials(site.id)
    assert record is not None
    assert record.username_hint == "s***@example.com"
    assert password.encode() not in record.encrypted_payload


def test_remove_credentials_deletes_record(accounts_db, pro_org, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    site = upsert_site(org_id=pro_org.org_id, target="https://authorized.example.com/")
    blob = encrypt_credentials("u", "p")
    upsert_site_auth_credentials(
        site_id=site.id,
        org_id=pro_org.org_id,
        login_url="https://authorized.example.com/login",
        username_field="username",
        password_field="password",
        encrypted_data_key=blob.encrypted_data_key,
        encrypted_payload=blob.ciphertext,
        username_hint="u***",
        credentials_consent_user_id=pro_org.id,
    )
    assert get_site_auth_credentials(site.id) is not None
    assert delete_site_auth_credentials(site.id) is True
    assert get_site_auth_credentials(site.id) is None


def test_detect_destructive_paths_defaults():
    urls = [
        "https://example.com/",
        "https://example.com/account",
        "https://example.com/delete-account",
        "https://example.com/settings/cancel-subscription",
        "https://example.com/api/purge",
    ]
    found = detect_destructive_paths(urls)
    assert "/delete-account" in found
    assert any("cancel-subscription" in p for p in found)
    assert any("purge" in p for p in found)


def test_exclusion_enforced_on_urls():
    excluded = ["/delete-account", "/cancel-subscription"]
    urls = [
        "https://example.com/dashboard",
        "https://example.com/delete-account",
        "https://example.com/delete-account/confirm",
        "https://example.com/ok",
    ]
    kept = filter_excluded_urls(urls, excluded)
    assert kept == [
        "https://example.com/dashboard",
        "https://example.com/ok",
    ]
    assert path_matches_exclusion(
        "https://example.com/app/delete-account", ["/delete-account"]
    )


def test_destructive_form_keyword_layer():
    assert is_destructive_form(action="/account/delete")
    assert is_destructive_form(field_names=["confirm_purge"])
    assert not is_destructive_form(action="/account/profile", field_names=["email"])


@pytest.mark.asyncio
async def test_active_tools_never_target_excluded_path(monkeypatch):
    from agents.detection import run_active_tools
    from agents.state import ScanState

    captured: dict = {}

    async def fake_zap_run(self, target, scope):
        captured["zap_scope"] = scope
        return ToolResult(
            tool_name="zap",
            target=target,
            success=True,
            data={
                "findings": [
                    Finding(
                        tool="zap",
                        type="zap-1",
                        url="https://authorized.example.com/delete-account",
                        severity=Severity.HIGH,
                        description="should be filtered",
                    ).model_dump_for_state(),
                    Finding(
                        tool="zap",
                        type="zap-2",
                        url="https://authorized.example.com/dashboard",
                        severity=Severity.LOW,
                        description="ok",
                    ).model_dump_for_state(),
                ],
                "auth": {"login_succeeded": True},
            },
        )

    async def close_async(self):
        return None

    monkeypatch.setattr("agents.detection.ZAPTool.run", fake_zap_run)
    monkeypatch.setattr(
        "agents.detection.ZAPTool.probe_ready",
        AsyncMock(return_value=(True, None)),
    )
    monkeypatch.setattr("agents.detection.ZAPTool.close", close_async)
    monkeypatch.setattr(
        "agents.detection.find_injectable_urls",
        lambda recon: [
            "https://authorized.example.com/delete-account?id=1",
            "https://authorized.example.com/item?id=1",
        ],
    )

    sqlmap_urls: list[str] = []

    async def fake_sqlmap_batch(self, urls, scope):
        sqlmap_urls.extend(urls)
        return ToolResult(
            tool_name="sqlmap",
            target="batch",
            success=True,
            data={"findings": []},
        )

    monkeypatch.setattr("agents.detection.SQLMapTool.run_batch", fake_sqlmap_batch)

    state: ScanState = {
        "scan_id": "s1",
        "target": "https://authorized.example.com/",
        "planned_active_tests": ["zap", "sqlmap"],
        "approved_tools": ["zap", "sqlmap"],
        "human_approved": True,
        "recon_results": {
            "urls": [
                "https://authorized.example.com/dashboard",
                "https://authorized.example.com/delete-account",
            ],
            "excluded_paths": ["/delete-account"],
        },
        "auth_scan": {
            "configured": False,
            "enabled": False,
            "excluded_paths": ["/delete-account"],
        },
    }
    findings, _errors, _auth_meta, _notes = await run_active_tools(state)
    assert "/delete-account" in (captured.get("zap_scope") or {}).get(
        "excluded_paths", []
    )
    assert all("delete-account" not in (f.url or "") for f in findings)
    assert all("delete-account" not in u for u in sqlmap_urls)
    assert any("item?id=1" in u for u in sqlmap_urls)


def test_plan_flags():
    assert plan_supports_authenticated_scanning("pro")
    assert plan_supports_authenticated_scanning("agency")
    assert not plan_supports_authenticated_scanning("free")
    assert not plan_supports_authenticated_scanning("starter")


def test_can_use_authenticated_scanning(pro_org, starter_org):
    assert can_use_authenticated_scanning(pro_org.org_id) is True
    assert can_use_authenticated_scanning(starter_org.org_id) is False


def test_starter_cannot_submit_credentials_via_api(accounts_db, starter_org, monkeypatch):
    """Crafted request bypassing UI must still be rejected server-side."""
    from app.main import app, require_firebase_user

    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    site = upsert_site(
        org_id=starter_org.org_id, target="https://authorized.example.com/"
    )

    app.dependency_overrides[require_firebase_user] = lambda: _auth_user(starter_org)
    client = TestClient(app)
    try:
        resp = client.put(
            f"/orgs/me/sites/{site.id}/credentials",
            json={
                "login_url": "https://authorized.example.com/login",
                "username": "u",
                "password": "p",
                "credentials_authorized": True,
            },
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "authenticated_scanning_not_on_plan"
    finally:
        app.dependency_overrides.clear()


def test_pro_can_submit_credentials_with_consent(accounts_db, pro_org, monkeypatch):
    from app.main import app, require_firebase_user

    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    site = upsert_site(org_id=pro_org.org_id, target="https://authorized.example.com/")

    app.dependency_overrides[require_firebase_user] = lambda: _auth_user(pro_org)
    client = TestClient(app)
    try:
        denied = client.put(
            f"/orgs/me/sites/{site.id}/credentials",
            json={
                "login_url": "https://authorized.example.com/login",
                "username": "test@example.com",
                "password": "SecretPass1!",
                "credentials_authorized": False,
            },
        )
        assert denied.status_code == 403
        assert denied.json()["detail"]["error"] == "credentials_consent_required"

        ok = client.put(
            f"/orgs/me/sites/{site.id}/credentials",
            json={
                "login_url": "https://authorized.example.com/login",
                "username": "test@example.com",
                "password": "SecretPass1!",
                "username_field": "email",
                "password_field": "password",
                "excluded_paths": ["/delete-account"],
                "credentials_authorized": True,
            },
        )
        assert ok.status_code == 200
        body = ok.json()
        assert body["authenticated_scanning"]["configured"] is True
        assert body["authenticated_scanning"]["username_hint"] == "t***@example.com"
        assert "SecretPass1!" not in str(body)
        assert get_site_auth_credentials(site.id) is not None
    finally:
        app.dependency_overrides.clear()


def test_downgrade_falls_back_to_unauthenticated(accounts_db, pro_org, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    site = upsert_site(org_id=pro_org.org_id, target="https://authorized.example.com/")
    blob = encrypt_credentials("keep-me@example.com", "StillStored!")
    upsert_site_auth_credentials(
        site_id=site.id,
        org_id=pro_org.org_id,
        login_url="https://authorized.example.com/login",
        username_field="username",
        password_field="password",
        encrypted_data_key=blob.encrypted_data_key,
        encrypted_payload=blob.ciphertext,
        username_hint=redact_username("keep-me@example.com"),
        credentials_consent_user_id=pro_org.id,
    )

    update_organization_plan(pro_org.org_id, plan_id="free")
    assert get_site_auth_credentials(site.id) is not None

    meta = build_public_auth_meta(org_id=pro_org.org_id, site_id=site.id)
    assert meta.configured is True
    assert meta.enabled is False
    assert meta.fallback_reason == "plan_downgrade"
    assert any("unauthenticated" in w.lower() for w in meta.warnings)

    runtime = load_runtime_auth(org_id=pro_org.org_id, site_id=site.id)
    assert runtime.credentials is None
    assert runtime.meta.enabled is False


def test_redact_auth_fields_from_state():
    dirty = {
        "target": "https://example.com",
        "password": "secret",
        "auth_scan": {"username_hint": "a***", "password": "nope"},
        "nested": {"username": "alice", "ok": 1},
    }
    clean = redact_auth_fields_from_state(dirty)
    assert "password" not in clean
    assert "password" not in clean["auth_scan"]
    assert "username" not in clean["nested"]
    assert clean["nested"]["ok"] == 1
    assert clean["auth_scan"]["username_hint"] == "a***"


def test_login_failed_coverage_warning_in_scoring():
    from agents.reporting import _executive_summary
    from agents.scoring import run_scoring
    from agents.state import ScanState

    state: ScanState = {
        "scan_id": "s-login-fail",
        "target": "https://authorized.example.com/",
        "findings": [],
        "recon_results": {"tool_results": {}},
        "detection_metadata": {},
        "auth_scan": {
            "configured": True,
            "enabled": True,
            "login_succeeded": False,
            "username_hint": "t***@example.com",
            "excluded_paths": ["/delete-account"],
            "warnings": [
                "Login failed; scan proceeded as an unauthenticated visitor."
            ],
            "fallback_reason": "login_failed",
        },
    }
    result = run_scoring(state)
    coverage = result["severity_scores"]["scan_coverage"]["authenticated_scanning"]
    assert coverage["login_succeeded"] is False
    assert "unauthenticated visitor" in coverage["coverage_warning"].lower()

    bits = _executive_summary(
        {
            "severity_scores": result["severity_scores"],
            "findings_by_severity": {},
            "outcome": "completed",
        }
    )
    notes = " ".join(bits.get("notes") or [])
    assert "unauthenticated" in notes.lower()
    assert "StillStored" not in notes


def test_scan_without_credentials_after_removal(accounts_db, pro_org, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_MASTER_KEY", Fernet.generate_key().decode())
    site = upsert_site(org_id=pro_org.org_id, target="https://authorized.example.com/")
    blob = encrypt_credentials("u", "p")
    upsert_site_auth_credentials(
        site_id=site.id,
        org_id=pro_org.org_id,
        login_url="https://authorized.example.com/login",
        username_field="username",
        password_field="password",
        encrypted_data_key=blob.encrypted_data_key,
        encrypted_payload=blob.ciphertext,
        username_hint="u***",
        credentials_consent_user_id=pro_org.id,
    )
    delete_site_auth_credentials(site.id)

    meta = build_public_auth_meta(org_id=pro_org.org_id, site_id=site.id)
    assert meta.configured is False
    assert meta.enabled is False
    runtime = load_runtime_auth(org_id=pro_org.org_id, site_id=site.id)
    assert runtime.credentials is None
