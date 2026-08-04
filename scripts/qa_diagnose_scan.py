#!/usr/bin/env python3
"""Fetch coverage/error details for the latest QA regression scan."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

for line in (BACKEND / ".env").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, _, v = line.partition("=")
    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

api_key = ""
for line in (ROOT / "web" / ".env.local").read_text(encoding="utf-8").splitlines():
    if line.startswith("NEXT_PUBLIC_FIREBASE_API_KEY="):
        api_key = line.split("=", 1)[1].strip()

import firebase_admin
from firebase_admin import auth, credentials

sa = ROOT / "checkmate-68921-firebase-adminsdk-fbsvc-b4fad0b6af.json"
cred_path = os.environ.get("FIREBASE_CREDENTIALS_PATH") or str(sa)
if not firebase_admin._apps:
    firebase_admin.initialize_app(
        credentials.Certificate(cred_path),
        {"projectId": os.environ.get("FIREBASE_PROJECT_ID")},
    )

qa_users = [
    u
    for u in auth.list_users().iterate_all()
    if u.email
    and u.email.startswith("qa.regression.")
    and u.email.endswith("@checkmate-qa.local")
]
if not qa_users:
    raise SystemExit("no qa.regression.* user found")

API = "https://checkmateapp-nine.vercel.app/api/backend-proxy"
preferred_scan = os.environ.get(
    "QA_SCAN_ID", "710bbf6c-f100-47db-811e-a58986f7c91e"
)
target_q = parse.quote("https://example.com", safe="")


def mint(uid: str) -> str:
    custom = auth.create_custom_token(uid)
    if isinstance(custom, bytes):
        custom = custom.decode()
    payload = json.dumps({"token": custom, "returnSecureToken": True}).encode()
    req = request.Request(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={api_key}",
        data=payload,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())["idToken"]


def get(path: str, id_token: str):
    req = request.Request(f"{API}{path}", method="GET")
    req.add_header("Authorization", f"Bearer {id_token}")
    try:
        with request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode())
    except error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:4000]


id_token = None
email = None
scan_id = preferred_scan
for u in qa_users:
    tok = mint(u.uid)
    code, scans = get("/orgs/me/scans", tok)
    items = []
    if isinstance(scans, dict):
        items = scans.get("scans") or scans.get("items") or []
    ids = {(it.get("scan_id") or it.get("id")) for it in items}
    print("TRY_USER", u.email, "scans", len(items), "has_preferred", preferred_scan in ids)
    if preferred_scan in ids or items:
        id_token = tok
        email = u.email
        if preferred_scan not in ids and items:
            scan_id = items[0].get("scan_id") or items[0].get("id")
        for it in items[:8]:
            print(
                "SCAN",
                it.get("scan_id") or it.get("id"),
                it.get("status"),
                it.get("target"),
            )
        if preferred_scan in ids:
            scan_id = preferred_scan
            break

if not id_token:
    raise SystemExit("no QA user owns a scan")

code, report = get(f"/scan/{scan_id}/report?target={target_q}", id_token)
print("REPORT_STATUS", code, "scan_id", scan_id, "user", email)
if not isinstance(report, dict):
    print(report)
    raise SystemExit(1)

cov = (report.get("severity_scores") or {}).get("scan_coverage") or report.get(
    "coverage"
) or {}
meta = report.get("detection_metadata") or {}
print("COVERAGE", json.dumps(cov, indent=2)[:5000])
print("META_ERRORS", json.dumps(meta.get("errors") or {}, indent=2)[:8000])
print("META_NOTES", json.dumps(meta.get("coverage_notes") or meta.get("notes") or [], indent=2)[:3000])
print("FINDINGS", len(report.get("findings") or []))

# Walk nested tool result bags commonly present on reports
for key in (
    "detection_results",
    "passive_results",
    "active_results",
    "tool_results",
    "recon_results",
):
    bag = report.get(key)
    if not isinstance(bag, dict):
        continue
    print(f"=== {key} ===")
    for k, v in bag.items():
        if not isinstance(v, dict):
            print(k, type(v).__name__)
            continue
        err = v.get("error") or v.get("message") or v.get("stderr") or ""
        print(
            f"{k}: success={v.get('success')} skipped={v.get('skipped')} "
            f"error={str(err)[:400]}"
        )

# Top-level errors list
for key in ("errors", "module_errors", "failed_modules"):
    if key in report:
        print(key, json.dumps(report[key], indent=2)[:4000])
