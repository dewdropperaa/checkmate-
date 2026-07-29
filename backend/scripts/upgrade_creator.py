"""One-off: upgrade creator orgs to agency plan."""

from __future__ import annotations

from core.accounts import (
    configure_accounts_db,
    ensure_creator_plan_for_org,
    get_user,
    init_accounts_schema,
)
from core.config import get_settings

if __name__ == "__main__":
    get_settings.cache_clear()
    init_accounts_schema()
    for email in get_settings().creator_email_list:
        # Find user by email via direct query
        import sqlite3
        from pathlib import Path

        db = Path(__file__).resolve().parent.parent / "data" / "accounts.db"
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id FROM users WHERE lower(email) = ?", (email,)
        ).fetchone()
        conn.close()
        if row is None:
            print(f"no account for {email}")
            continue
        user = get_user(row["id"])
        if user is None:
            print(f"user not found for {email}")
            continue
        ensure_creator_plan_for_org(user.org_id, email)
        refreshed = get_user(row["id"])
        print(f"{email}: plan={refreshed.plan_id if refreshed else '?'}")
