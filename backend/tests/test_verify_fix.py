"""Tests for per-finding Verify Fix (quota-free, rate-limited re-check)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

import httpx
import pytest

os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")

from core.accounts import (
    create_scan_record,
    get_org_scan_usage,
    get_organization,
    init_accounts_schema,
    upsert_user_from_firebase,
)
from core.verify_fix import (
    FIX_CHANGED,
    FIX_FIXED,
    FIX_STILL_PRESENT,
    FindingNotFound,
    VerifyFixRateLimited,
    map_verifier_to_fix_result,
    run_verify_fix,
)

_BASE_URL = "https://authorized.example.com/"


def _finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": "header-checks-0",
        "tool": "header-checks",
        "type": "cors-wildcard",
        "url": _BASE_URL,
        "severity": "low",
        "description": "CORS wildcard",
        "evidence": "Access-Control-Allow-Origin: *",
        "raw_data": {},
    }
    base.update(overrides)
    return base


def _response(
    *,
    headers: dict[str, str] | None = None,
    text: str = "",
    status_code: int = 200,
) -> httpx.Response:
    return httpx.Response(status_code, headers=list((headers or {}).items()), text=text)


class FakeClient:
    def __init__(self, responses: dict[str, httpx.Response]) -> None:
        self._responses = responses
        self.requested: list[str] = []

    async def get(self, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        self.requested.append(url)
        if url in self._responses:
            return self._responses[url]
        raise httpx.ConnectError("no route to host")

    async def aclose(self) -> None:
        pass


@pytest.fixture()
def org_and_scan(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from core.accounts import configure_accounts_db

    configure_accounts_db(tmp_path / "accounts.db")
    init_accounts_schema()
    user, _ = upsert_user_from_firebase(
        uid="verify-fix-user",
        email="verify-fix@example.com",
        display_name="Verify",
        email_verified=True,
        auth_provider="password",
    )
    org = get_organization(user.org_id)
    assert org is not None
    scan = create_scan_record(
        scan_id="scan-verify-fix",
        org_id=org.id,
        target=_BASE_URL,
        kind="full",
    )
    return org, scan


class TestMapVerifierToFixResult:
    def test_refuted_maps_to_fixed(self) -> None:
        result, evidence = map_verifier_to_fix_result(
            original=_finding(),
            verified={
                "verification": {
                    "status": "refuted",
                    "evidence": "Access-Control-Allow-Origin: https://ok",
                }
            },
        )
        assert result == FIX_FIXED
        assert evidence is not None

    def test_confirmed_maps_to_still_present(self) -> None:
        result, _ = map_verifier_to_fix_result(
            original=_finding(),
            verified={
                "verification": {
                    "status": "confirmed",
                    "evidence": "Access-Control-Allow-Origin: *",
                }
            },
        )
        assert result == FIX_STILL_PRESENT

    def test_unreachable_maps_to_changed(self) -> None:
        result, evidence = map_verifier_to_fix_result(
            original=_finding(),
            verified={
                "verification": {
                    "status": "unreachable",
                    "reason": "Target URL could not be fetched",
                }
            },
        )
        assert result == FIX_CHANGED
        assert "unreachable" in (evidence or "")


class TestRunVerifyFix:
    @pytest.mark.asyncio
    async def test_transitions_fixed_still_present_changed(
        self, org_and_scan
    ) -> None:
        org, scan = org_and_scan
        finding = _finding()

        # Still present: wildcard CORS remains.
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )
        still = await run_verify_fix(
            scan_id=scan.id,
            org_id=org.id,
            finding_id=finding["id"],
            findings=[finding],
            client=client,
        )
        assert still["result"] == FIX_STILL_PRESENT
        assert still["quota_consumed"] is False

        # Bypass cooldown for the next state transitions.
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        with patch(
            "core.verify_fix.get_latest_finding_fix_verification",
            return_value={"checked_at": past},
        ):
            client_fixed = FakeClient(
                {
                    _BASE_URL: _response(
                        headers={"access-control-allow-origin": "https://trusted.example"}
                    )
                }
            )
            fixed = await run_verify_fix(
                scan_id=scan.id,
                org_id=org.id,
                finding_id=finding["id"],
                findings=[finding],
                client=client_fixed,
            )
            assert fixed["result"] == FIX_FIXED

        with patch(
            "core.verify_fix.get_latest_finding_fix_verification",
            return_value={"checked_at": past},
        ):
            client_down = FakeClient({})
            changed = await run_verify_fix(
                scan_id=scan.id,
                org_id=org.id,
                finding_id=finding["id"],
                findings=[finding],
                client=client_down,
            )
            assert changed["result"] == FIX_CHANGED
            assert changed["attempt_count"] >= 3
            assert len(changed["history"]) >= 3

    @pytest.mark.asyncio
    async def test_does_not_consume_scan_quota(self, org_and_scan) -> None:
        org, scan = org_and_scan
        before = get_org_scan_usage(org.id)
        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )
        result = await run_verify_fix(
            scan_id=scan.id,
            org_id=org.id,
            finding_id="header-checks-0",
            findings=[_finding()],
            client=client,
        )
        after = get_org_scan_usage(org.id)
        assert result["quota_consumed"] is False
        assert after == before

    @pytest.mark.asyncio
    async def test_rate_limited_per_finding(
        self, org_and_scan, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        org, scan = org_and_scan
        from core.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "verify_fix_cooldown_seconds", 180)

        client = FakeClient(
            {_BASE_URL: _response(headers={"access-control-allow-origin": "*"})}
        )
        await run_verify_fix(
            scan_id=scan.id,
            org_id=org.id,
            finding_id="header-checks-0",
            findings=[_finding()],
            client=client,
        )
        with pytest.raises(VerifyFixRateLimited) as exc:
            await run_verify_fix(
                scan_id=scan.id,
                org_id=org.id,
                finding_id="header-checks-0",
                findings=[_finding()],
                client=client,
            )
        assert exc.value.retry_after_seconds >= 1

    @pytest.mark.asyncio
    async def test_missing_finding_raises(self, org_and_scan) -> None:
        org, scan = org_and_scan
        with pytest.raises(FindingNotFound):
            await run_verify_fix(
                scan_id=scan.id,
                org_id=org.id,
                finding_id="missing",
                findings=[_finding()],
                client=FakeClient({}),
            )
