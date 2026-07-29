"""Tests for creator email plan overrides."""

from __future__ import annotations

import pytest

from core.accounts import (
    CREATOR_PLAN_ID,
    configure_accounts_db,
    get_user,
    init_accounts_schema,
    org_has_creator_member,
    upsert_user_from_firebase,
)
from core.config import get_settings


@pytest.fixture
def accounts_db(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "accounts.db"
    configure_accounts_db(db_path)
    init_accounts_schema()
    monkeypatch.setenv("CREATOR_EMAILS", "creator@example.com")
    get_settings.cache_clear()
    yield db_path
    configure_accounts_db(None)
    get_settings.cache_clear()


def test_new_creator_gets_agency_plan(accounts_db) -> None:
    record, created = upsert_user_from_firebase(
        uid="creator-uid",
        email="creator@example.com",
        display_name="Creator",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    assert created is True
    assert record.plan_id == CREATOR_PLAN_ID
    assert record.max_targets is None
    assert record.scans_per_month is None


def test_existing_creator_upgraded_on_login(accounts_db) -> None:
    upsert_user_from_firebase(
        uid="creator-uid",
        email="user@example.com",
        display_name="User",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    record, _ = upsert_user_from_firebase(
        uid="creator-uid",
        email="creator@example.com",
        display_name="Creator",
        email_verified=True,
        auth_provider="password",
    )
    assert record.plan_id == CREATOR_PLAN_ID


def test_org_has_creator_member(accounts_db) -> None:
    record, _ = upsert_user_from_firebase(
        uid="creator-uid",
        email="creator@example.com",
        display_name="Creator",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    assert org_has_creator_member(record.org_id) is True

    regular, _ = upsert_user_from_firebase(
        uid="regular-uid",
        email="regular@example.com",
        display_name="Regular",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    assert org_has_creator_member(regular.org_id) is False
