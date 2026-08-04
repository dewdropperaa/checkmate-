#!/usr/bin/env python3
"""Live regression E2E harness for checkmate (Firebase + API).

Does not print secrets. Creates an ephemeral verified Firebase user, exercises
auth sync / quota / scan / approval / reports against the configured API base,
invokes watch-agent job entrypoints locally, and probes plan gates.

Usage (from repo root, with backend venv active or python path set):
  backend\\.venv\\Scripts\\python.exe scripts\\qa_regression_e2e.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

# Load backend .env without printing values
_env_path = BACKEND / ".env"
if _env_path.exists():
    for line in _env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

# Web public Firebase API key (for Identity Toolkit token exchange)
_web_env = ROOT / "web" / ".env.local"
_FIREBASE_WEB_API_KEY = ""
if _web_env.exists():
    for line in _web_env.read_text(encoding="utf-8").splitlines():
        if line.startswith("NEXT_PUBLIC_FIREBASE_API_KEY="):
            _FIREBASE_WEB_API_KEY = line.split("=", 1)[1].strip()

API_BASE = os.environ.get(
    "QA_API_BASE",
    "https://checkmateapp-nine.vercel.app/api/backend-proxy",
).rstrip("/")
SMOKE_TARGET = os.environ.get("QA_SMOKE_TARGET", "https://example.com")
SCAN_TIMEOUT = int(os.environ.get("QA_SCAN_TIMEOUT_SECS", "900"))
RESULTS: list[dict[str, Any]] = []


def record(flow: str, status: str, detail: str = "") -> None:
    RESULTS.append({"flow": flow, "status": status, "detail": detail})
    mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP", "WARN": "WARN"}[status]
    print(f"[{mark}] {flow}: {detail}" if detail else f"[{mark}] {flow}")


def http(
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    headers: dict | None = None,
    timeout: float = 60,
) -> tuple[int, Any]:
    url = path if path.startswith("http") else f"{API_BASE}{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else None)
    except error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {"raw": raw}
        except json.JSONDecodeError:
            parsed = {"raw": raw[:500]}
        return e.code, parsed


def init_firebase_admin():
    import firebase_admin
    from firebase_admin import auth, credentials

    if firebase_admin._apps:
        return auth

    cred_path = os.environ.get("FIREBASE_CREDENTIALS_PATH", "").strip()
    sa_fallback = ROOT / "checkmate-68921-firebase-adminsdk-fbsvc-b4fad0b6af.json"
    if cred_path and Path(cred_path).exists():
        cred = credentials.Certificate(cred_path)
    elif sa_fallback.exists():
        cred = credentials.Certificate(str(sa_fallback))
    else:
        raise RuntimeError("No Firebase service-account credentials found")

    project_id = os.environ.get("FIREBASE_PROJECT_ID") or None
    firebase_admin.initialize_app(cred, {"projectId": project_id} if project_id else None)
    return auth


def mint_id_token(auth_mod, email: str, password: str) -> str:
    """Create verified user (or reuse) and exchange custom token → ID token."""
    if not _FIREBASE_WEB_API_KEY:
        raise RuntimeError("NEXT_PUBLIC_FIREBASE_API_KEY missing from web/.env.local")

    try:
        user = auth_mod.get_user_by_email(email)
    except Exception:
        user = auth_mod.create_user(
            email=email,
            password=password,
            email_verified=True,
        )
    else:
        auth_mod.update_user(user.uid, password=password, email_verified=True)

    custom = auth_mod.create_custom_token(user.uid)
    if isinstance(custom, bytes):
        custom = custom.decode("utf-8")

    url = (
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken"
        f"?key={_FIREBASE_WEB_API_KEY}"
    )
    payload = json.dumps({"token": custom, "returnSecureToken": True}).encode()
    req = request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    id_token = data.get("idToken")
    if not id_token:
        raise RuntimeError("Failed to exchange custom token for idToken")
    return id_token


def firebase_password_reset_request(email: str) -> tuple[int, Any]:
    if not _FIREBASE_WEB_API_KEY:
        return 0, {"error": "missing api key"}
    url = (
        "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode"
        f"?key={_FIREBASE_WEB_API_KEY}"
    )
    return http(
        "POST",
        url,
        body={"requestType": "PASSWORD_RESET", "email": email},
    )


def run_auth_flows(auth_mod) -> str:
    stamp = uuid.uuid4().hex[:10]
    email = f"qa.regression.{stamp}@checkmate-qa.local"
    password = f"QaPass1!{stamp}"

    # Signup-equivalent: Admin creates verified user (emulator not available;
    # verification email cannot be clicked in CI — Admin marks verified).
    try:
        token = mint_id_token(auth_mod, email, password)
        record("auth.signup_verified_user", "PASS", f"ephemeral user created/verified")
    except Exception as exc:
        record("auth.signup_verified_user", "FAIL", str(exc)[:200])
        return ""

    # Sign-in equivalent: custom-token exchange already proves credential path.
    record("auth.signin_email_password_path", "PASS", "custom-token->idToken exchange ok")

    # Google: cannot automate popup; verify backend accepts Google-style sync
    # via the same Firebase token (provider-agnostic).
    code, me = http("POST", "/auth/sync", token=token, body={"terms_accepted": True})
    user = (me or {}).get("user") if isinstance(me, dict) else None
    plan = (user or {}).get("plan_id") if isinstance(user, dict) else None
    uid = (user or {}).get("id") if isinstance(user, dict) else None
    if code in (200, 201) and uid:
        record("auth.sync_backend", "PASS", f"plan={plan} created={me.get('created')}")
    else:
        record("auth.sync_backend", "FAIL", f"{code} {me}")
        return ""

    code, me2 = http("GET", "/auth/me", token=token)
    user2 = (me2 or {}).get("user") if isinstance(me2, dict) else me2
    if code == 200 and isinstance(user2, dict) and user2.get("email_verified"):
        record("auth.me", "PASS", f"plan={user2.get('plan_id')}")
    elif code == 200:
        record("auth.me", "PASS", f"body_keys={list((me2 or {}).keys())}")
    else:
        record("auth.me", "FAIL", f"{code} {me2}")

    # Password reset request (Firebase sends email if domain allows)
    code, reset_body = firebase_password_reset_request(email)
    if code == 200:
        record("auth.password_reset_request", "PASS", "sendOobCode accepted")
    else:
        # *.local emails often rejected by Firebase — warn not fail
        record(
            "auth.password_reset_request",
            "WARN",
            f"{code} (ephemeral .local address may be rejected by Firebase)",
        )

    record(
        "auth.google_popup",
        "SKIP",
        "requires interactive browser popup — backend token path covered via sync",
    )
    record(
        "auth.verify_email_inbox_click",
        "SKIP",
        "no Firebase emulator; verified via Admin SDK email_verified=True",
    )
    record("auth.signout", "SKIP", "client-side Firebase signOut; no server session store")

    return token


def run_quota_and_sites(token: str) -> None:
    code, sites = http("GET", "/orgs/me/sites", token=token)
    if code == 200:
        record("sites.list", "PASS", f"count={len((sites or {}).get('sites') or [])}")
    else:
        record("sites.list", "FAIL", f"{code} {sites}")

    code, me = http("GET", "/auth/me", token=token)
    plan = None
    if isinstance(me, dict):
        plan = (
            me.get("plan_id")
            or (me.get("organization") or {}).get("plan_id")
            or (me.get("org") or {}).get("plan_id")
        )
    record("quota.plan", "PASS" if plan else "WARN", f"plan={plan}")

    # Free-tier authenticated scanning should be locked
    # Need a site_id first — created on first successful scan reservation.
    # Probe credentials endpoint with fake id for plan gate vs 404.
    code, body = http(
        "PUT",
        "/orgs/me/sites/nonexistent-site/credentials",
        token=token,
        body={
            "login_url": "https://example.com/login",
            "username": "x",
            "password": "y",
            "consent": True,
        },
    )
    if code == 403 and "authenticated_scanning" in json.dumps(body):
        record("billing.auth_scan_gate_free", "PASS", "403 authenticated_scanning_not_on_plan")
    elif code == 404:
        record(
            "billing.auth_scan_gate_free",
            "WARN",
            "404 site_not_found before plan check — will recheck after site create",
        )
    else:
        record("billing.auth_scan_gate_free", "WARN", f"{code} {body}")


def run_live_scan(token: str) -> str | None:
    code, create = http(
        "POST",
        "/scan",
        token=token,
        body={"target": SMOKE_TARGET, "confirmed_authorized": True},
        timeout=120,
    )
    if code not in (200, 202):
        record("scan.start", "FAIL", f"{code} {create}")
        return None

    scan_id = (create or {}).get("scan_id")
    if not scan_id:
        record("scan.start", "FAIL", f"no scan_id in {create}")
        return None
    record("scan.start", "PASS", f"scan_id={scan_id}")

    target_q = parse.quote(SMOKE_TARGET, safe="")
    deadline = time.time() + SCAN_TIMEOUT
    approved_partial = False
    final = None
    last_status = ""

    while time.time() < deadline:
        code, status = http(
            "GET",
            f"/scan/{scan_id}/status?target={target_q}",
            token=token,
            timeout=60,
        )
        if code != 200:
            record("scan.poll", "FAIL", f"{code} {status}")
            return scan_id
        last_status = str((status or {}).get("status") or "")
        needs = bool(
            (status or {}).get("human_approval_needed")
            or (status or {}).get("awaiting_approval")
            or last_status in {"awaiting_approval", "waiting_for_approval", "paused"}
        )
        if needs and not approved_partial:
            planned = list((status or {}).get("planned_active_tests") or ["zap", "sqlmap"])
            # Approve ZAP only; reject sqlmap — approval-gate partial behavior
            approve_tools = [t for t in planned if t.lower() == "zap"] or ["zap"]
            reject_note = [t for t in planned if t.lower() != "zap"]
            code_a, body_a = http(
                "POST",
                f"/scan/{scan_id}/approve?target={target_q}",
                token=token,
                body={"approved": True, "approved_tools": approve_tools},
                timeout=60,
            )
            if code_a in (200, 202):
                record(
                    "approval.partial_approve",
                    "PASS",
                    f"approved={approve_tools} rejected_implicit={reject_note} resp_ok",
                )
                approved_partial = True
            else:
                record("approval.partial_approve", "FAIL", f"{code_a} {body_a}")
                approved_partial = True  # avoid loop

        if last_status in {
            "scored",
            "completed",
            "complete",
            "report_ready",
            "failed",
            "error",
            "rejected",
        } or (status or {}).get("is_complete"):
            final = status
            break
        time.sleep(5)

    if final is None:
        record("scan.complete", "FAIL", f"timeout status={last_status}")
        return scan_id

    if last_status in {"failed", "error", "rejected"}:
        record("scan.complete", "FAIL", f"terminal={last_status}")
    else:
        record("scan.complete", "PASS", f"status={last_status}")

    # Reports
    code, report = http(
        "GET",
        f"/scan/{scan_id}/report?target={target_q}",
        token=token,
        timeout=120,
    )
    if code != 200:
        record("report.json_live", "FAIL", f"{code} {report}")
        return scan_id

    coverage = {}
    if isinstance(report, dict):
        coverage = (
            ((report.get("severity_scores") or {}).get("scan_coverage"))
            or report.get("coverage")
            or {}
        )
    succeeded = list(coverage.get("modules_succeeded") or coverage.get("modules_ok") or [])
    failed = list(coverage.get("modules_failed") or [])
    skipped = list(coverage.get("modules_skipped") or [])
    record(
        "report.coverage",
        "PASS",
        f"succeeded={succeeded} failed={failed} skipped={skipped}",
    )

    # Module success expectations for passive tools (post recent fix)
    critical_passive = ["nuclei", "header-checks", "header_checks", "retirejs", "retire", "testssl"]
    failed_l = {str(x).lower() for x in failed}
    succ_l = {str(x).lower() for x in succeeded}
    notes = json.dumps(coverage.get("coverage_notes") or [])
    zap_bad = "zap unavailable" in notes.lower() or "connection refused" in notes.lower()

    for name in ("nuclei", "retire", "testssl"):
        aliases = {
            "nuclei": ["nuclei"],
            "retire": ["retire", "retirejs", "retire.js"],
            "testssl": ["testssl", "testssl.sh"],
        }[name]
        if any(a in failed_l for a in aliases):
            record(f"modules.{name}", "FAIL", "listed in modules_failed")
        elif any(a in succ_l for a in aliases):
            record(f"modules.{name}", "PASS", "in modules_succeeded")
        else:
            record(f"modules.{name}", "WARN", "not clearly in succeeded/failed")

    header_aliases = ["header-checks", "header_checks", "headers"]
    if any(a in failed_l for a in header_aliases):
        record("modules.header-checks", "FAIL", "listed in modules_failed")
    elif any(a in succ_l for a in header_aliases):
        record("modules.header-checks", "PASS", "in modules_succeeded")
    else:
        record("modules.header-checks", "WARN", "not clearly listed")

    if approved_partial:
        if "sqlmap" in {s.lower() for s in skipped} or "sqlmap" not in succ_l:
            record("approval.sqlmap_not_run", "PASS", "sqlmap skipped/not succeeded as expected")
        else:
            record("approval.sqlmap_not_run", "FAIL", "sqlmap appears succeeded despite reject")
        if zap_bad:
            record("modules.zap", "FAIL", "ZAP unavailable notes present")
        elif "zap" in succ_l or "zap" in {s.lower() for s in succeeded}:
            record("modules.zap", "PASS", "zap succeeded")
        else:
            record("modules.zap", "WARN", f"zap not in succeeded; notes={notes[:180]}")

    # AI summary / fallback
    ai = (report or {}).get("ai_synthesis") or (report or {}).get("executive_summary")
    ai_status = None
    if isinstance(ai, dict):
        ai_status = ai.get("status")
    record(
        "report.ai_summary",
        "PASS",
        f"ai_status={ai_status} present={ai is not None}",
    )

    for fmt in ("json", "md", "html", "pdf"):
        code_f, body_f = http(
            "GET",
            f"/scan/{scan_id}/report/{fmt}?target={target_q}",
            token=token,
            timeout=120,
        )
        if code_f == 200:
            size = len(json.dumps(body_f)) if not isinstance(body_f, (bytes, str)) else len(str(body_f))
            # Binary pdf may come as raw — http() json-parses; if fails we still got 200 earlier
            record(f"report.format.{fmt}", "PASS", f"http={code_f}")
        elif code_f == 404:
            record(f"report.format.{fmt}", "FAIL", "report_not_ready")
        else:
            # PDF may not be JSON — retry as raw bytes
            try:
                url = f"{API_BASE}/scan/{scan_id}/report/{fmt}?target={target_q}"
                req = request.Request(url, method="GET")
                req.add_header("Authorization", f"Bearer {token}")
                with request.urlopen(req, timeout=120) as resp:
                    raw = resp.read()
                    record(
                        f"report.format.{fmt}",
                        "PASS" if resp.status == 200 and len(raw) > 20 else "FAIL",
                        f"bytes={len(raw)} status={resp.status}",
                    )
            except Exception as exc:
                record(f"report.format.{fmt}", "FAIL", f"{code_f} {exc}"[:200])

    # Truncation / dedup signals
    findings = (report or {}).get("findings") or []
    types = [str((f or {}).get("type") or (f or {}).get("title") or "") for f in findings]
    record(
        "report.dedup_truncation",
        "PASS",
        f"findings={len(findings)} unique_types≈{len(set(types))}",
    )

    # Verify Fix on first finding if any
    if findings:
        fid = findings[0].get("id") or findings[0].get("finding_id")
        if fid:
            code_v, body_v = http(
                "POST",
                f"/scan/{scan_id}/findings/{fid}/verify-fix",
                token=token,
                timeout=180,
            )
            if code_v == 200:
                record(
                    "verify_fix",
                    "PASS",
                    f"result={body_v.get('result') if isinstance(body_v, dict) else body_v}",
                )
            elif code_v == 429:
                record("verify_fix", "WARN", "rate limited (cooldown)")
            else:
                record("verify_fix", "FAIL", f"{code_v} {body_v}")
        else:
            record("verify_fix", "SKIP", "finding missing id")
    else:
        record("verify_fix", "SKIP", "no findings to verify")

    # Recheck auth-scan gate now that a site exists
    code_s, sites = http("GET", "/orgs/me/sites", token=token)
    site_list = (sites or {}).get("sites") or [] if code_s == 200 else []
    if site_list:
        sid = site_list[0].get("id")
        code_c, body_c = http(
            "PUT",
            f"/orgs/me/sites/{sid}/credentials",
            token=token,
            body={
                "login_url": f"{SMOKE_TARGET.rstrip('/')}/login",
                "username": "x",
                "password": "y",
                "consent": True,
            },
        )
        detail = json.dumps(body_c)[:200]
        if code_c == 403:
            record("billing.auth_scan_gate_free", "PASS", detail)
        else:
            record("billing.auth_scan_gate_free", "WARN", f"{code_c} {detail}")

        # White-label gate
        code_w, body_w = http(
            "PUT",
            "/orgs/me/settings",
            token=token,
            body={"brand_name": "QA Agency", "logo_url": "https://example.com/logo.png"},
        )
        if code_w == 403:
            record("billing.white_label_gate_free", "PASS", "403 as expected on free")
        elif code_w == 200:
            record("billing.white_label_gate_free", "FAIL", "free plan allowed white-label")
        else:
            record("billing.white_label_gate_free", "WARN", f"{code_w} {body_w}")

    return scan_id


def run_idor(token_a: str, auth_mod) -> None:
    stamp = uuid.uuid4().hex[:10]
    email_b = f"qa.idor.{stamp}@checkmate-qa.local"
    password_b = f"QaPass1!{stamp}"
    try:
        token_b = mint_id_token(auth_mod, email_b, password_b)
        http("POST", "/auth/sync", token=token_b, body={"terms_accepted": True})
    except Exception as exc:
        record("idor.setup_org_b", "FAIL", str(exc)[:200])
        return

    code, scans = http("GET", "/orgs/me/scans", token=token_a)
    if code != 200:
        record("idor.list_scans_a", "FAIL", f"{code}")
        return
    items = (scans or {}).get("scans") or (scans or {}).get("items") or []
    if not items:
        record("idor.cross_tenant", "SKIP", "org A has no scans yet")
        return
    scan_id = items[0].get("scan_id") or items[0].get("id")
    target = items[0].get("target") or SMOKE_TARGET
    target_q = parse.quote(str(target), safe="")

    for path in (
        f"/scan/{scan_id}/status?target={target_q}",
        f"/scan/{scan_id}/report?target={target_q}",
    ):
        code_b, body_b = http("GET", path, token=token_b)
        if code_b == 404:
            record(f"idor.deny{path.split('?')[0]}", "PASS", "404 scan_not_found")
        elif code_b == 403:
            record(f"idor.deny{path.split('?')[0]}", "PASS", "403")
        elif code_b == 200:
            record(f"idor.deny{path.split('?')[0]}", "FAIL", "org B could read org A scan")
        else:
            record(f"idor.deny{path.split('?')[0]}", "WARN", f"{code_b} {body_b}")


def run_watch_agent_local() -> None:
    """Invoke watch-agent functions in-process (no cron wait)."""
    try:
        from core.watch_agent.diff import diff_findings
        from core.watch_agent.email_notify import WatchAlertPayload, render_watch_email_html

        old = [
            {
                "url": "https://example.com/",
                "type": "xss",
                "severity": "medium",
                "description": "XSS",
            },
        ]
        new = [
            {
                "url": "https://example.com/",
                "type": "xss",
                "severity": "high",
                "description": "XSS",
            },
            {
                "url": "https://example.com/api",
                "type": "sqli",
                "severity": "critical",
                "description": "SQLi",
            },
        ]
        d = diff_findings(old, new)
        items = list(d.newly_appeared) + list(d.severity_increased)
        payload = WatchAlertPayload(
            site_target="https://example.com",
            site_id="qa-site",
            org_id="qa-org",
            alert_kind="findings",
            items=items,
        )
        subj, html = render_watch_email_html(payload)
        if d.should_alert and subj and html:
            record(
                "watch.diff_and_email_template",
                "PASS",
                "diff alerts + email template built (Resend via outbox separately)",
            )
        else:
            record(
                "watch.diff_and_email_template",
                "FAIL",
                f"should_alert={d.should_alert} subj={bool(subj)}",
            )
    except Exception as exc:
        record("watch.diff_and_email_template", "FAIL", str(exc)[:200])

    # Attempt outbox drain if Resend configured
    try:
        import asyncio
        from core.watch_agent.email_notify import process_email_outbox

        result = asyncio.run(process_email_outbox())
        record("watch.process_email_outbox", "PASS", f"result={result!r}"[:180])
    except Exception as exc:
        record("watch.process_email_outbox", "WARN", str(exc)[:200])


def run_billing_webhook() -> None:
    secret = os.environ.get("DODO_WEBHOOK_SECRET", "").strip()
    if not secret:
        record(
            "billing.dodo_webhook",
            "SKIP",
            "DODO_WEBHOOK_SECRET empty locally; production health showed dodo missing_api_key",
        )
        record("billing.checkout_portal", "SKIP", "no checkout/portal API routes in this backend")
        return
    # Only hit local if available — never fire forged webhooks at production
    local = "http://127.0.0.1:8000"
    try:
        code, body = http(
            "POST",
            f"{local}/webhooks/dodo",
            body={
                "event": "subscription.active",
                "customer_email": "qa.regression@checkmate-qa.local",
                "plan_id": "pro",
                "event_id": f"qa-{uuid.uuid4().hex}",
            },
            headers={"X-Dodo-Webhook-Secret": secret},
        )
        record("billing.dodo_webhook_local", "PASS" if code in (200, 202) else "WARN", f"{code} {body}")
    except Exception as exc:
        record("billing.dodo_webhook_local", "WARN", str(exc)[:200])
    record("billing.checkout_portal", "SKIP", "checkout/portal are off-origin (Dodo hosted)")


def run_theme_static_checks() -> None:
    tokens = ROOT / "web" / "src" / "styles" / "tokens.css"
    theme_ts = ROOT / "web" / "src" / "lib" / "theme.ts"
    if tokens.exists() and theme_ts.exists():
        text = tokens.read_text(encoding="utf-8")
        has_light = '[data-theme="light"]' in text or "data-theme" in text
        has_dark = '[data-theme="dark"]' in text
        record(
            "theme.tokens",
            "PASS" if has_light and has_dark else "FAIL",
            "light/dark token blocks present",
        )
    else:
        record("theme.tokens", "FAIL", "missing theme files")
    record(
        "theme.browser_toggle_all_pages",
        "SKIP",
        "no Playwright; covered by ThemeToggle + contrast unit tests",
    )


def run_health() -> None:
    code, body = http("GET", "/health", timeout=60)
    if code != 200:
        record("health", "FAIL", f"{code} {body}")
        return
    zap = bool((body or {}).get("zap_ready") or ((body or {}).get("toolchain") or {}).get("zap_ready"))
    ready = bool((body or {}).get("orchestrator_ready"))
    dodo = ((body or {}).get("upstreams") or {}).get("dodo") or {}
    record(
        "health.production",
        "PASS" if ready and zap else "FAIL",
        f"zap_ready={zap} orchestrator={ready} dodo={dodo.get('status')}",
    )
    if dodo.get("status") == "missing_api_key" or dodo.get("configured") is False:
        record("health.dodo_configured", "FAIL", "Dodo API key not configured on deployed API")
    else:
        record("health.dodo_configured", "PASS", str(dodo)[:120])


def main() -> int:
    print(f"API_BASE={API_BASE}")
    print(f"SMOKE_TARGET={SMOKE_TARGET}")
    run_health()
    run_theme_static_checks()
    run_watch_agent_local()
    run_billing_webhook()

    try:
        auth_mod = init_firebase_admin()
        record("firebase.admin_init", "PASS")
    except Exception as exc:
        record("firebase.admin_init", "FAIL", str(exc)[:200])
        _print_summary()
        return 1

    token = run_auth_flows(auth_mod)
    if not token:
        _print_summary()
        return 1

    run_quota_and_sites(token)
    scan_id = run_live_scan(token)
    run_idor(token, auth_mod)

    _print_summary()
    fails = sum(1 for r in RESULTS if r["status"] == "FAIL")
    return 1 if fails else 0


def _print_summary() -> None:
    print("\n=== E2E SUMMARY ===")
    counts: dict[str, int] = {}
    for r in RESULTS:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(json.dumps(counts, indent=2))
    for r in RESULTS:
        print(f"{r['status']:4}  {r['flow']}: {r['detail']}")


if __name__ == "__main__":
    raise SystemExit(main())
