"""Add Firebase Auth authorized domains (uses Admin service account on disk)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2 import service_account

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CREDS = ROOT / "checkmate-68921-firebase-adminsdk-fbsvc-b4fad0b6af.json"
PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "checkmate-68921")
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def main() -> int:
    domains = sys.argv[1:]
    if not domains:
        print("Usage: firebase_add_authorized_domain.py domain1 [domain2 ...]", file=sys.stderr)
        return 1

    creds_path = Path(os.environ.get("FIREBASE_CREDENTIALS_PATH", str(DEFAULT_CREDS)))
    if not creds_path.is_file():
        print(f"Missing service account: {creds_path}", file=sys.stderr)
        return 1

    creds = service_account.Credentials.from_service_account_file(
        str(creds_path),
        scopes=SCOPES,
    )
    creds.refresh(Request())
    token = creds.token

    import urllib.request

    get_url = (
        f"https://identitytoolkit.googleapis.com/v2/projects/{PROJECT_ID}/config"
    )
    req = urllib.request.Request(get_url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        config = json.loads(resp.read().decode())

    existing = list(config.get("authorizedDomains") or [])
    merged = existing[:]
    added = []
    for d in domains:
        d = d.strip().lower()
        if d and d not in merged:
            merged.append(d)
            added.append(d)

    if not added:
        print("No new domains to add:", ", ".join(domains))
        return 0

    body = json.dumps({"authorizedDomains": merged}).encode()
    patch_url = (
        f"https://identitytoolkit.googleapis.com/v2/projects/{PROJECT_ID}/config"
        "?updateMask=authorizedDomains"
    )
    patch = urllib.request.Request(
        patch_url,
        data=body,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(patch, timeout=30) as resp:
        json.loads(resp.read().decode())

    print("Added authorized domains:", ", ".join(added))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
