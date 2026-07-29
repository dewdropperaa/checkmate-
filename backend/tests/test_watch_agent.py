"""Tests for Watch Agent: diff, CVE matching, job sync, Resend retries."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.accounts import (
    configure_accounts_db,
    enqueue_email,
    get_organization,
    has_cve_alert,
    init_accounts_schema,
    list_due_emails,
    record_cve_alert,
    set_watch_emails_enabled,
    update_organization_plan,
    upsert_site,
    upsert_user_from_firebase,
)
from core.watch_agent.cve_job import run_cve_watch_for_site
from core.watch_agent.diff import diff_findings
from core.watch_agent.email_notify import (
    WatchAlertPayload,
    process_email_outbox,
    queue_watch_alert,
    render_watch_email_html,
)
from core.watch_agent.nvd_client import NvdClient, cve_affects_version, version_in_range
from core.watch_agent.scheduler import (
    cancel_site_watch_job,
    configure_scheduler_db,
    on_plan_changed,
    schedule_site_watch_job,
    shutdown_scheduler,
    sync_org_watch_jobs,
    watch_scan_job_id,
)


@pytest.fixture()
def accounts_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / "accounts.db"
    configure_accounts_db(db)
    init_accounts_schema()
    monkeypatch.setenv("WATCH_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("RESEND_API_KEY", "test-resend-key")
    yield db
    configure_accounts_db(None)


@pytest.fixture()
def org_with_user(accounts_db: Path):
    user, _ = upsert_user_from_firebase(
        uid="uid-watch-1",
        email="owner@example.com",
        display_name="Owner",
        email_verified=True,
        auth_provider="password",
    )
    update_organization_plan(user.org_id, plan_id="pro")
    return user


def _finding(
    *,
    url: str = "https://authorized.example.com/",
    ftype: str = "missing-header",
    severity: str = "low",
) -> dict[str, Any]:
    return {
        "tool": "header-checks",
        "type": ftype,
        "url": url,
        "severity": severity,
        "description": f"{ftype} at {url}",
        "evidence": None,
        "cwe_id": None,
        "confidence": 1.0,
        "verification": None,
        "raw_data": {},
    }


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------


def test_diff_categorizes_new_worsened_and_fixed() -> None:
    previous = [
        _finding(ftype="missing-csp", severity="low"),
        _finding(ftype="missing-hsts", severity="medium"),
        _finding(ftype="insecure-cookie", severity="low"),
    ]
    current = [
        _finding(ftype="missing-csp", severity="high"),  # worsened
        _finding(ftype="exposed-env-file", severity="high"),  # new
        # missing-hsts fixed; insecure-cookie unchanged
        _finding(ftype="insecure-cookie", severity="low"),
    ]
    diff = diff_findings(previous, current)
    assert len(diff.newly_appeared) == 1
    assert diff.newly_appeared[0]["type"] == "exposed-env-file"
    assert len(diff.severity_increased) == 1
    assert diff.severity_increased[0]["type"] == "missing-csp"
    assert diff.severity_increased[0]["previous_severity"] == "low"
    assert len(diff.fixed) == 1
    assert diff.fixed[0]["type"] == "missing-hsts"
    assert diff.should_alert is True


def test_diff_no_alert_on_unchanged() -> None:
    findings = [_finding(ftype="missing-csp", severity="low")]
    diff = diff_findings(findings, findings)
    assert diff.newly_appeared == []
    assert diff.severity_increased == []
    assert diff.fixed == []
    assert diff.should_alert is False


def test_diff_no_alert_on_improvements_only() -> None:
    previous = [
        _finding(ftype="missing-csp", severity="low"),
        _finding(ftype="exposed-env-file", severity="high"),
    ]
    current = [_finding(ftype="missing-csp", severity="low")]
    diff = diff_findings(previous, current)
    assert diff.fixed
    assert not diff.newly_appeared
    assert not diff.severity_increased
    assert diff.should_alert is False


@pytest.mark.asyncio
async def test_email_triggered_only_when_diff_should_alert(
    org_with_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queued: list[WatchAlertPayload] = []

    async def _capture(payload: WatchAlertPayload) -> list[str]:
        queued.append(payload)
        return ["email-1"]

    monkeypatch.setattr(
        "core.watch_agent.scan_job.queue_watch_alert",
        _capture,
    )

    async def _fake_modules(target: str):
        return [_finding(ftype="new-issue", severity="medium")], []

    monkeypatch.setattr(
        "core.watch_agent.scan_job.run_watch_modules",
        _fake_modules,
    )
    monkeypatch.setattr(
        "core.watch_agent.scan_job.get_latest_findings_snapshot",
        lambda site_id: [_finding(ftype="old-issue", severity="low")],
    )

    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    from core.watch_agent.scan_job import run_watch_scan_for_site

    result = await run_watch_scan_for_site(site.id)
    assert result["should_alert"] is True
    assert queued and queued[0].alert_kind == "findings"

    queued.clear()

    async def _same_modules(target: str):
        return [_finding(ftype="old-issue", severity="low")], []

    monkeypatch.setattr(
        "core.watch_agent.scan_job.run_watch_modules",
        _same_modules,
    )
    monkeypatch.setattr(
        "core.watch_agent.scan_job.get_latest_findings_snapshot",
        lambda site_id: [_finding(ftype="old-issue", severity="low")],
    )
    result2 = await run_watch_scan_for_site(site.id)
    assert result2["should_alert"] is False
    assert queued == []


# ---------------------------------------------------------------------------
# CVE version matching
# ---------------------------------------------------------------------------


def _nvd_cve_with_range() -> dict[str, Any]:
    return {
        "id": "CVE-2024-9999",
        "descriptions": [{"lang": "en", "value": "WordPress XSS in versions before 6.4.2"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "6.0",
                                "versionEndExcluding": "6.4.2",
                            }
                        ],
                    }
                ]
            }
        ],
    }


def test_version_in_range_bounds() -> None:
    assert version_in_range(
        "6.3.0",
        start_including="6.0",
        end_excluding="6.4.2",
    )
    assert not version_in_range(
        "6.4.2",
        start_including="6.0",
        end_excluding="6.4.2",
    )
    assert not version_in_range(
        "5.9",
        start_including="6.0",
        end_excluding="6.4.2",
    )


def test_cve_affects_version_inside_vs_outside() -> None:
    cve = _nvd_cve_with_range()
    assert cve_affects_version(cve, product_name="WordPress", version="6.3.1")
    assert not cve_affects_version(cve, product_name="WordPress", version="6.5.0")
    assert not cve_affects_version(cve, product_name="WordPress", version="5.0")


def test_cve_affects_version_nested_cpe_range_payload() -> None:
    cve = {
        "id": "CVE-2025-0001",
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "children": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                                        "versionStartExcluding": "6.1",
                                        "versionEndIncluding": "6.4.1",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ],
    }
    assert cve_affects_version(cve, product_name="WordPress", version="6.4.1")
    assert not cve_affects_version(cve, product_name="WordPress", version="6.1")
    assert not cve_affects_version(cve, product_name="WordPress", version="6.4.2")


@pytest.mark.asyncio
async def test_nvd_search_consumes_all_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    class _Response:
        status_code = 200

        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def get(self, _url, *, params, headers):
            start = int(params["startIndex"])
            calls.append(start)
            if start == 0:
                return _Response(
                    {
                        "totalResults": 2,
                        "startIndex": 0,
                        "resultsPerPage": 1,
                        "vulnerabilities": [{"cve": {"id": "CVE-1"}}],
                    }
                )
            return _Response(
                {
                    "totalResults": 2,
                    "startIndex": 1,
                    "resultsPerPage": 1,
                    "vulnerabilities": [{"cve": {"id": "CVE-2"}}],
                }
            )

    monkeypatch.setattr("core.watch_agent.nvd_client.httpx.AsyncClient", _Client)
    client = NvdClient(api_key=None)
    records = await client.search_cves_for_product("WordPress", results_per_page=1)
    assert calls == [0, 1]
    assert [record["id"] for record in records] == ["CVE-1", "CVE-2"]


def test_cve_dedup_never_alerts_twice(org_with_user) -> None:
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    assert record_cve_alert(site_id=site.id, cve_id="CVE-2024-9999", product="WordPress")
    assert has_cve_alert(site.id, "CVE-2024-9999")
    assert not record_cve_alert(site_id=site.id, cve_id="CVE-2024-9999", product="WordPress")


@pytest.mark.asyncio
async def test_cve_watch_skips_already_alerted(
    org_with_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    from core.accounts import update_site_fingerprint

    update_site_fingerprint(
        site.id,
        [{"name": "WordPress", "version": "6.3.1", "source": "generator"}],
    )
    record_cve_alert(site_id=site.id, cve_id="CVE-2024-9999", product="WordPress")

    class FakeNvd:
        async def find_matching_cves(self, **kwargs):
            from core.watch_agent.nvd_client import CveMatch

            return [
                CveMatch(
                    cve_id="CVE-2024-9999",
                    summary="already alerted",
                    product="WordPress",
                    version="6.3.1",
                )
            ]

    queued: list[Any] = []

    async def _capture(payload: WatchAlertPayload) -> list[str]:
        queued.append(payload)
        return []

    monkeypatch.setattr("core.watch_agent.cve_job.queue_watch_alert", _capture)
    result = await run_cve_watch_for_site(site.id, client=FakeNvd())  # type: ignore[arg-type]
    assert result["new_alerts"] == []
    assert queued == []


# ---------------------------------------------------------------------------
# Scheduler job create / update / cancel
# ---------------------------------------------------------------------------


@pytest.fixture()
def scheduler_env(accounts_db: Path, tmp_path: Path):
    """Configure a persistent job store without starting the asyncio loop.

    Job CRUD (add/remove/get) works against the SQLAlchemy store before start().
    """
    configure_scheduler_db(tmp_path / "scheduler.db")
    from core.watch_agent.scheduler import _ensure_scheduler

    sched = _ensure_scheduler()
    yield sched
    shutdown_scheduler()


def test_schedule_created_on_site_add_for_paid_plan(org_with_user, scheduler_env) -> None:
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    assert schedule_site_watch_job(site.id, plan_id="pro") is True
    job = scheduler_env.get_job(watch_scan_job_id(site.id))
    assert job is not None


def test_schedule_canceled_on_site_remove(org_with_user, scheduler_env) -> None:
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    schedule_site_watch_job(site.id, plan_id="pro")
    assert cancel_site_watch_job(site.id) is True
    assert scheduler_env.get_job(watch_scan_job_id(site.id)) is None


def test_schedule_canceled_on_plan_downgrade(org_with_user, scheduler_env) -> None:
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    schedule_site_watch_job(site.id, plan_id="pro")
    assert scheduler_env.get_job(watch_scan_job_id(site.id)) is not None

    update_organization_plan(org_with_user.org_id, plan_id="free")
    result = on_plan_changed(org_with_user.org_id)
    assert result["canceled"] >= 1
    assert scheduler_env.get_job(watch_scan_job_id(site.id)) is None


def test_free_plan_does_not_schedule(org_with_user, scheduler_env) -> None:
    update_organization_plan(org_with_user.org_id, plan_id="free")
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    assert schedule_site_watch_job(site.id) is False
    assert scheduler_env.get_job(watch_scan_job_id(site.id)) is None


def test_plan_upgrade_schedules_existing_sites(org_with_user, scheduler_env) -> None:
    update_organization_plan(org_with_user.org_id, plan_id="free")
    site = upsert_site(org_id=org_with_user.org_id, target="https://authorized.example.com/")
    schedule_site_watch_job(site.id)
    assert scheduler_env.get_job(watch_scan_job_id(site.id)) is None

    update_organization_plan(org_with_user.org_id, plan_id="starter")
    sync = sync_org_watch_jobs(org_with_user.org_id)
    assert sync["scheduled"] == 1
    assert scheduler_env.get_job(watch_scan_job_id(site.id)) is not None


# ---------------------------------------------------------------------------
# Resend failure handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resend_failure_does_not_crash_and_is_retried(
    org_with_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enqueue_email(
        org_id=org_with_user.org_id,
        to_email="owner@example.com",
        subject="Watch Agent alert",
        html_body="<p>test</p>",
    )
    assert list_due_emails()

    async def _fail(**kwargs):
        return False, "resend_rate_limited:too many"

    monkeypatch.setattr(
        "core.watch_agent.email_notify.send_via_resend",
        _fail,
    )
    result = await process_email_outbox()
    assert result["retried"] == 1
    assert result["sent"] == 0
    due = list_due_emails(limit=50)
    # next_attempt_at is in the future, so not due yet — but row is in retry status
    from core.accounts import _connect, _lock

    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT status, attempts, last_error FROM email_outbox").fetchone()
            assert row["status"] == "retry"
            assert row["attempts"] == 1
            assert "resend_rate_limited" in (row["last_error"] or "")
        finally:
            conn.close()


@pytest.mark.asyncio
async def test_resend_success_marks_sent(
    org_with_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enqueue_email(
        org_id=org_with_user.org_id,
        to_email="owner@example.com",
        subject="ok",
        html_body="<p>ok</p>",
    )

    async def _ok(**kwargs):
        return True, None

    monkeypatch.setattr("core.watch_agent.email_notify.send_via_resend", _ok)
    result = await process_email_outbox()
    assert result["sent"] == 1


def test_email_template_covers_both_alert_kinds() -> None:
    findings_payload = WatchAlertPayload(
        site_target="https://authorized.example.com/",
        site_id="s1",
        org_id="o1",
        alert_kind="findings",
        items=[_finding(ftype="missing-csp", severity="high")],
        scan_id="scan-1",
    )
    subject, html_body = render_watch_email_html(findings_payload)
    assert "new findings" in subject.lower() or "Watch Agent" in subject
    assert "missing-csp" in html_body
    assert "automated Watch Agent" in html_body
    assert "full manual scan" in html_body

    cve_payload = WatchAlertPayload(
        site_target="https://authorized.example.com/",
        site_id="s1",
        org_id="o1",
        alert_kind="cve",
        items=[
            {
                "cve_id": "CVE-2024-9999",
                "product": "WordPress",
                "version": "6.3.1",
                "summary": "XSS",
                "severity": "high",
            }
        ],
    )
    subject2, html2 = render_watch_email_html(cve_payload)
    assert "CVE" in subject2
    assert "CVE-2024-9999" in html2
    assert "WordPress" in html2


@pytest.mark.asyncio
async def test_queue_respects_watch_emails_disabled(org_with_user) -> None:
    set_watch_emails_enabled(org_with_user.org_id, False)
    org = get_organization(org_with_user.org_id)
    assert org is not None and org.watch_emails_enabled is False
    ids = await queue_watch_alert(
        WatchAlertPayload(
            site_target="https://authorized.example.com/",
            site_id="s1",
            org_id=org_with_user.org_id,
            alert_kind="findings",
            items=[_finding()],
        )
    )
    assert ids == []
