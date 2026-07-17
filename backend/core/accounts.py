"""Users and organizations store for SaaS accounts + free-plan defaults.

Persists to SQLite under backend/data/accounts.db. New users automatically get
an organization on the free plan (limits mirrored from web/src/config/plans.ts).
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Free plan limits — keep in sync with web/src/config/plans.ts (plan id "free").
FREE_PLAN_ID = "free"
FREE_MAX_TARGETS = 1
FREE_SCANS_PER_MONTH = 5

_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "accounts.db"
_lock = threading.Lock()
_db_path: Path = _DEFAULT_DB_PATH


@dataclass(frozen=True)
class Organization:
    id: str
    name: str
    plan_id: str
    max_targets: int | None
    scans_per_month: int | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class UserRecord:
    id: str
    email: str | None
    display_name: str | None
    auth_provider: str | None
    org_id: str
    email_verified: bool
    created_at: str
    updated_at: str
    last_login_at: str | None
    plan_id: str = FREE_PLAN_ID
    max_targets: int | None = FREE_MAX_TARGETS
    scans_per_month: int | None = FREE_SCANS_PER_MONTH


def configure_accounts_db(path: Path | str | None = None) -> None:
    """Point the accounts store at a specific SQLite file (tests use temp paths)."""
    global _db_path
    _db_path = Path(path) if path else _DEFAULT_DB_PATH


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_accounts_schema() -> None:
    with _lock:
        conn = _connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    plan_id TEXT NOT NULL DEFAULT 'free',
                    max_targets INTEGER,
                    scans_per_month INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT,
                    display_name TEXT,
                    auth_provider TEXT,
                    org_id TEXT NOT NULL REFERENCES organizations(id),
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
                """
            )
            conn.commit()
        finally:
            conn.close()


def _row_to_user(row: sqlite3.Row, org: sqlite3.Row | None = None) -> UserRecord:
    return UserRecord(
        id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        auth_provider=row["auth_provider"],
        org_id=row["org_id"],
        email_verified=bool(row["email_verified"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_login_at=row["last_login_at"],
        plan_id=(org["plan_id"] if org else FREE_PLAN_ID),
        max_targets=(org["max_targets"] if org else FREE_MAX_TARGETS),
        scans_per_month=(org["scans_per_month"] if org else FREE_SCANS_PER_MONTH),
    )


def get_user(uid: str) -> UserRecord | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (uid,)
            ).fetchone()
            if row is None:
                return None
            org = conn.execute(
                "SELECT * FROM organizations WHERE id = ?", (row["org_id"],)
            ).fetchone()
            return _row_to_user(row, org)
        finally:
            conn.close()


def upsert_user_from_firebase(
    *,
    uid: str,
    email: str | None,
    display_name: str | None,
    email_verified: bool,
    auth_provider: str | None,
) -> tuple[UserRecord, bool]:
    """Create or update a user. New users get an implicit free-plan organization.

    Returns ``(user, created)``.
    """
    init_accounts_schema()
    now = _utc_now()

    with _lock:
        conn = _connect()
        try:
            existing = conn.execute(
                "SELECT * FROM users WHERE id = ?", (uid,)
            ).fetchone()

            if existing is None:
                org_id = str(uuid.uuid4())
                org_name = (email.split("@")[0] if email else "workspace")[:80]
                conn.execute(
                    """
                    INSERT INTO organizations (
                        id, name, plan_id, max_targets, scans_per_month,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        org_id,
                        f"{org_name}'s workspace",
                        FREE_PLAN_ID,
                        FREE_MAX_TARGETS,
                        FREE_SCANS_PER_MONTH,
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO users (
                        id, email, display_name, auth_provider, org_id,
                        email_verified, created_at, updated_at, last_login_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uid,
                        email,
                        display_name,
                        auth_provider,
                        org_id,
                        1 if email_verified else 0,
                        now,
                        now,
                        now,
                    ),
                )
                conn.commit()
                org = conn.execute(
                    "SELECT * FROM organizations WHERE id = ?", (org_id,)
                ).fetchone()
                row = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (uid,)
                ).fetchone()
                return _row_to_user(row, org), True

            conn.execute(
                """
                UPDATE users SET
                    email = COALESCE(?, email),
                    display_name = COALESCE(?, display_name),
                    auth_provider = COALESCE(?, auth_provider),
                    email_verified = ?,
                    updated_at = ?,
                    last_login_at = ?
                WHERE id = ?
                """,
                (
                    email,
                    display_name,
                    auth_provider,
                    1 if email_verified else 0,
                    now,
                    now,
                    uid,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (uid,)
            ).fetchone()
            org = conn.execute(
                "SELECT * FROM organizations WHERE id = ?", (row["org_id"],)
            ).fetchone()
            return _row_to_user(row, org), False
        finally:
            conn.close()


def user_to_dict(user: UserRecord) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "auth_provider": user.auth_provider,
        "org_id": user.org_id,
        "email_verified": user.email_verified,
        "plan_id": user.plan_id,
        "max_targets": user.max_targets,
        "scans_per_month": user.scans_per_month,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
        "last_login_at": user.last_login_at,
    }
