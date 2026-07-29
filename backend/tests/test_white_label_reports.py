"""Agency white-label report branding."""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.reporting import resolve_report_branding, run_reporting
from core.accounts import (
    configure_accounts_db,
    upsert_user_from_firebase,
    update_organization_branding,
    update_organization_plan,
)
from core.plans import (
    can_use_white_label_reports,
    plan_supports_white_label_reports,
)


@pytest.fixture
def accounts_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "accounts.db"
    configure_accounts_db(db_path)
    monkeypatch.setenv("ACCOUNTS_DB_PATH", str(db_path))
    yield db_path
    configure_accounts_db(None)


def _agency_org(accounts_db: Path):
    user, _ = upsert_user_from_firebase(
        uid="user-agency-wl",
        email="agency@example.com",
        display_name="Agency User",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    update_organization_plan(user.org_id, plan_id="agency")
    return user


def _pro_org(accounts_db: Path):
    user, _ = upsert_user_from_firebase(
        uid="user-pro-wl",
        email="pro-wl@example.com",
        display_name="Pro User",
        email_verified=True,
        auth_provider="password",
        terms_accepted=True,
    )
    update_organization_plan(user.org_id, plan_id="pro")
    return user


def _base_state(**overrides):
    state = {
        "scan_id": "scan-wl-1",
        "org_id": "org-wl",
        "target": "https://example.com",
        "status": "scored",
        "human_approved": True,
        "findings": [],
        "severity_scores": {
            "overall_risk_score": 0.0,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "likely_false_positives": 0,
        },
        "ai_synthesis": {},
    }
    state.update(overrides)
    return state


def test_plan_gates_white_label():
    assert plan_supports_white_label_reports("agency")
    assert not plan_supports_white_label_reports("pro")
    assert not plan_supports_white_label_reports("free")


def test_agency_branding_injected_into_reports(
    tmp_path: Path, monkeypatch, accounts_db
):
    reports_root = tmp_path / "reports"
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", reports_root)

    user = _agency_org(accounts_db)
    org_id = user.org_id
    assert can_use_white_label_reports(org_id)

    logo = tmp_path / "agency-logo.png"
    # 1x1 PNG — fpdf/Pillow require a real image, not just a magic header.
    import base64

    logo.write_bytes(
        base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
        )
    )
    update_organization_branding(
        org_id,
        brand_name="Acme Security",
        brand_logo_path=str(logo),
    )

    branding = resolve_report_branding(org_id)
    assert branding.white_label is True
    assert branding.brand_name == "Acme Security"
    assert branding.logo_path == logo

    result = run_reporting(_base_state(org_id=org_id, scan_id="scan-wl-agency"))
    report = result["report"]
    assert report["branding"]["white_label"] is True
    assert report["branding"]["brand_name"] == "Acme Security"

    md = Path(report["artifacts"]["md"]).read_text(encoding="utf-8")
    html = Path(report["artifacts"]["html"]).read_text(encoding="utf-8")
    assert "Acme Security Report" in md
    assert "Acme Security Report" in html
    assert "Acme Security Vulnerability Assessment" in html


def test_non_agency_keeps_checkmate_branding(
    tmp_path: Path, monkeypatch, accounts_db
):
    reports_root = tmp_path / "reports"
    monkeypatch.setattr("agents.reporting._REPORTS_ROOT", reports_root)

    user = _pro_org(accounts_db)
    org_id = user.org_id
    update_organization_branding(org_id, brand_name="Should Not Appear")

    branding = resolve_report_branding(org_id)
    assert branding.white_label is False
    assert branding.brand_name == "Checkmate"

    result = run_reporting(_base_state(org_id=org_id, scan_id="scan-wl-pro"))
    md = Path(result["report"]["artifacts"]["md"]).read_text(encoding="utf-8")
    assert "# Checkmate Report" in md
    assert "Should Not Appear" not in md
