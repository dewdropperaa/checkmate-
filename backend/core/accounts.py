"""Users and organizations store for SaaS accounts + free-plan defaults.

Persists to SQLite under backend/data/accounts.db. New users automatically get
an organization on the free plan (limits mirrored from web/src/config/plans.ts).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.plans import get_plan_limits

CREATOR_PLAN_ID = "agency"

# Free plan limits — keep in sync with web/src/config/plans.ts (plan id "free").
FREE_PLAN_ID = "free"
FREE_MAX_TARGETS = 1
FREE_SCANS_PER_MONTH = 5

# Keep in sync with web/src/lib/terms.ts
CURRENT_TERMS_VERSION = "2026-07-17"

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
    watch_emails_enabled: bool = True
    brand_name: str | None = None
    brand_logo_path: str | None = None


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
    terms_accepted_at: str | None = None
    terms_version: str | None = None


@dataclass(frozen=True)
class ScanRecord:
    id: str
    org_id: str
    target: str
    status: str
    current_node: str | None
    overall_risk_score: float | None
    severity: str | None
    created_at: str
    updated_at: str
    kind: str = "full"  # full | watch
    findings_count: int | None = None
    critical_high_count: int | None = None


@dataclass(frozen=True)
class SiteRecord:
    id: str
    org_id: str
    target: str
    active: bool
    last_watch_at: str | None
    last_cve_check_at: str | None
    fingerprint_json: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class SiteAuthCredentialRecord:
    """Encrypted auth credentials + consent metadata for a monitored site.

    Never includes plaintext username/password — only ciphertext and a
    redacted username_hint safe for UI / approval / reports.
    """

    site_id: str
    org_id: str
    login_url: str
    username_field: str
    password_field: str
    encrypted_data_key: bytes
    encrypted_payload: bytes
    username_hint: str
    credentials_consent_user_id: str
    credentials_consent_at: str
    excluded_paths_json: str
    created_at: str
    updated_at: str

    @property
    def excluded_paths(self) -> list[str]:
        try:
            data = json.loads(self.excluded_paths_json or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        return [str(p) for p in data if str(p).strip()]


@dataclass(frozen=True)
class ExtensionTokenRecord:
    id: str
    org_id: str
    user_id: str
    key_prefix: str
    created_at: str
    revoked_at: str | None = None
    label: str | None = None


@dataclass(frozen=True)
class QuotaReservation:
    scan: ScanRecord
    site: SiteRecord


class QuotaExceededError(ValueError):
    """Raised when an atomic scan reservation would exceed plan quota."""

    def __init__(self, code: str, message: str, limit: int | None) -> None:
        super().__init__(message)
        self.code = code
        self.limit = limit


def configure_accounts_db(path: Path | str | None = None) -> None:
    """Point the accounts store at a specific SQLite file (tests use temp paths)."""
    global _db_path
    _db_path = Path(path) if path else _DEFAULT_DB_PATH


def get_accounts_db_path() -> Path:
    return _db_path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_accounts_schema() -> None:
    """Ensure the accounts database schema is at the latest Alembic revision."""
    from core.migrations import upgrade_database

    with _lock:
        upgrade_database()


def _row_to_user(row: sqlite3.Row, org: sqlite3.Row | None = None) -> UserRecord:
    keys = row.keys()
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
        terms_accepted_at=(
            row["terms_accepted_at"] if "terms_accepted_at" in keys else None
        ),
        terms_version=row["terms_version"] if "terms_version" in keys else None,
    )


def is_creator_email(email: str | None) -> bool:
    """True when *email* is listed in CREATOR_EMAILS (case-insensitive)."""
    if not email:
        return False
    from core.config import get_settings

    normalized = email.strip().lower()
    return normalized in get_settings().creator_email_list


def ensure_creator_plan_for_org(org_id: str, email: str | None) -> None:
    """Upgrade a creator's organization to agency tier when applicable."""
    if not is_creator_email(email):
        return
    org = get_organization(org_id)
    if org is None or org.plan_id == CREATOR_PLAN_ID:
        return
    update_organization_plan(org_id, plan_id=CREATOR_PLAN_ID)


def org_has_creator_member(org_id: str) -> bool:
    """True when any member of the org is a configured creator email."""
    for member_email in list_org_member_emails(org_id):
        if is_creator_email(member_email):
            return True
    return False


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


def get_or_create_user_from_firebase(
    *,
    uid: str,
    email: str | None,
    display_name: str | None,
    email_verified: bool,
    auth_provider: str | None,
) -> UserRecord:
    """Resolve an account for a verified token, creating it when necessary."""
    existing = get_user(uid)
    if existing is not None:
        return existing
    record, _ = upsert_user_from_firebase(
        uid=uid,
        email=email,
        display_name=display_name,
        email_verified=email_verified,
        auth_provider=auth_provider,
    )
    return record


def upsert_user_from_firebase(
    *,
    uid: str,
    email: str | None,
    display_name: str | None,
    email_verified: bool,
    auth_provider: str | None,
    terms_accepted: bool = False,
    terms_version: str | None = None,
) -> tuple[UserRecord, bool]:
    """Create or update a user. New users get an implicit free-plan organization.

    Returns ``(user, created)``.
    """
    init_accounts_schema()
    now = _utc_now()
    accepted_version = (terms_version or CURRENT_TERMS_VERSION).strip() or CURRENT_TERMS_VERSION
    terms_at = now if terms_accepted else None

    with _lock:
        conn = _connect()
        try:
            existing = conn.execute(
                "SELECT * FROM users WHERE id = ?", (uid,)
            ).fetchone()

            if existing is None:
                org_id = str(uuid.uuid4())
                org_name = (email.split("@")[0] if email else "workspace")[:80]
                if is_creator_email(email):
                    limits = get_plan_limits(CREATOR_PLAN_ID)
                else:
                    limits = get_plan_limits(FREE_PLAN_ID)
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
                        limits.plan_id,
                        limits.max_targets,
                        limits.scans_per_month,
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO users (
                        id, email, display_name, auth_provider, org_id,
                        email_verified, created_at, updated_at, last_login_at,
                        terms_accepted_at, terms_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        terms_at,
                        accepted_version if terms_accepted else None,
                    ),
                )
                conn.commit()
                org = conn.execute(
                    "SELECT * FROM organizations WHERE id = ?", (org_id,)
                ).fetchone()
                row = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (uid,)
                ).fetchone()
                user_record = _row_to_user(row, org)
                created = True
            else:
                if terms_accepted:
                    conn.execute(
                        """
                        UPDATE users SET
                            email = COALESCE(?, email),
                            display_name = COALESCE(?, display_name),
                            auth_provider = COALESCE(?, auth_provider),
                            email_verified = ?,
                            updated_at = ?,
                            last_login_at = ?,
                            terms_accepted_at = COALESCE(terms_accepted_at, ?),
                            terms_version = ?
                        WHERE id = ?
                        """,
                        (
                            email,
                            display_name,
                            auth_provider,
                            1 if email_verified else 0,
                            now,
                            now,
                            terms_at,
                            accepted_version,
                            uid,
                        ),
                    )
                else:
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
                user_record = _row_to_user(row, org)
                created = False
        finally:
            conn.close()

    ensure_creator_plan_for_org(user_record.org_id, email)
    refreshed = get_user(uid)
    return (refreshed if refreshed is not None else user_record), created


def _row_to_scan(row: sqlite3.Row) -> ScanRecord:
    keys = row.keys()
    findings_count = None
    critical_high_count = None
    if "findings_count" in keys and row["findings_count"] is not None:
        findings_count = int(row["findings_count"])
    if "critical_high_count" in keys and row["critical_high_count"] is not None:
        critical_high_count = int(row["critical_high_count"])
    return ScanRecord(
        id=row["id"],
        org_id=row["org_id"],
        target=row["target"],
        status=row["status"],
        current_node=row["current_node"],
        overall_risk_score=row["overall_risk_score"],
        severity=row["severity"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        kind=str(row["kind"]) if "kind" in keys and row["kind"] else "full",
        findings_count=findings_count,
        critical_high_count=critical_high_count,
    )


def _row_to_site(row: sqlite3.Row) -> SiteRecord:
    return SiteRecord(
        id=row["id"],
        org_id=row["org_id"],
        target=row["target"],
        active=bool(row["active"]),
        last_watch_at=row["last_watch_at"],
        last_cve_check_at=row["last_cve_check_at"],
        fingerprint_json=row["fingerprint_json"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def create_scan_record(
    *,
    scan_id: str,
    org_id: str,
    target: str,
    kind: str = "full",
) -> ScanRecord:
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO scans (
                    id, org_id, target, status, kind, created_at, updated_at
                ) VALUES (?, ?, ?, 'pending', ?, ?, ?)
                """,
                (scan_id, org_id, target, kind, now, now),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return _row_to_scan(row)
        finally:
            conn.close()


def reserve_scan_quota_and_create_records(
    *,
    scan_id: str,
    org_id: str,
    target: str,
    max_targets: int | None,
    scans_per_month: int | None,
) -> QuotaReservation:
    """Atomically reserve monthly scan/target quota and create scan/site rows.

    The BEGIN IMMEDIATE transaction takes SQLite's write lock before quota is
    counted, so concurrent requests cannot both observe the same under-limit
    usage and then insert usage rows.
    """
    init_accounts_schema()
    now = _utc_now()
    month_start = datetime.now(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).isoformat()

    with _lock:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            target_count = int(
                conn.execute(
                    """
                    SELECT COUNT(DISTINCT target) FROM (
                        SELECT target FROM scans WHERE org_id = ?
                        UNION
                        SELECT target FROM sites WHERE org_id = ? AND active = 1
                    )
                    """,
                    (org_id, org_id),
                ).fetchone()[0]
            )
            existing_target = conn.execute(
                """
                SELECT 1 FROM (
                    SELECT target FROM scans WHERE org_id = ?
                    UNION
                    SELECT target FROM sites WHERE org_id = ? AND active = 1
                )
                WHERE target = ?
                LIMIT 1
                """,
                (org_id, org_id, target),
            ).fetchone()
            monthly_scans = int(
                conn.execute(
                    """
                    SELECT COUNT(*) FROM scans
                    WHERE org_id = ?
                      AND created_at >= ?
                      AND COALESCE(kind, 'full') = 'full'
                    """,
                    (org_id, month_start),
                ).fetchone()[0]
            )

            if existing_target is None and max_targets is not None and target_count >= max_targets:
                conn.rollback()
                raise QuotaExceededError(
                    "target_quota_exceeded",
                    "Your plan's authorized target limit has been reached.",
                    max_targets,
                )
            if scans_per_month is not None and monthly_scans >= scans_per_month:
                conn.rollback()
                raise QuotaExceededError(
                    "scan_quota_exceeded",
                    "Your plan's monthly scan limit has been reached.",
                    scans_per_month,
                )

            conn.execute(
                """
                INSERT INTO scans (
                    id, org_id, target, status, kind, created_at, updated_at
                ) VALUES (?, ?, ?, 'pending', 'full', ?, ?)
                """,
                (scan_id, org_id, target, now, now),
            )

            existing_site = conn.execute(
                "SELECT * FROM sites WHERE org_id = ? AND target = ?",
                (org_id, target),
            ).fetchone()
            if existing_site is None:
                site_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO sites (
                        id, org_id, target, active, created_at, updated_at
                    ) VALUES (?, ?, ?, 1, ?, ?)
                    """,
                    (site_id, org_id, target, now, now),
                )
            else:
                site_id = existing_site["id"]
                conn.execute(
                    """
                    UPDATE sites SET active = 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, site_id),
                )

            conn.commit()
            scan_row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            site_row = conn.execute(
                "SELECT * FROM sites WHERE id = ?", (site_id,)
            ).fetchone()
            return QuotaReservation(
                scan=_row_to_scan(scan_row),
                site=_row_to_site(site_row),
            )
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()


def update_scan_record(
    scan_id: str,
    *,
    status: str,
    current_node: str | None,
    overall_risk_score: float | None = None,
    severity: str | None = None,
    findings_count: int | None = None,
    critical_high_count: int | None = None,
) -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE scans SET
                    status = ?,
                    current_node = ?,
                    overall_risk_score = COALESCE(?, overall_risk_score),
                    severity = COALESCE(?, severity),
                    findings_count = COALESCE(?, findings_count),
                    critical_high_count = COALESCE(?, critical_high_count),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    current_node,
                    overall_risk_score,
                    severity,
                    findings_count,
                    critical_high_count,
                    _utc_now(),
                    scan_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()


def list_org_scans(
    org_id: str,
    *,
    page: int = 1,
    page_size: int = 10,
) -> tuple[list[ScanRecord], int]:
    offset = (page - 1) * page_size
    with _lock:
        conn = _connect()
        try:
            total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM scans WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
            )
            rows = conn.execute(
                """
                SELECT * FROM scans
                WHERE org_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (org_id, page_size, offset),
            ).fetchall()
            return [_row_to_scan(row) for row in rows], total
        finally:
            conn.close()


def list_stale_active_scans(*, older_than_iso: str) -> list[ScanRecord]:
    """Return active scans that should be resolved during service startup."""
    active_statuses = (
        "pending",
        "running",
        "recon",
        "detecting",
        "scoring",
        "awaiting_approval",
        "in_progress",
    )
    placeholders = ",".join("?" for _ in active_statuses)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"""
                SELECT * FROM scans
                WHERE status IN ({placeholders})
                  AND updated_at < ?
                ORDER BY updated_at ASC
                """,
                (*active_statuses, older_than_iso),
            ).fetchall()
            return [_row_to_scan(row) for row in rows]
        finally:
            conn.close()


def get_org_scan_usage(org_id: str) -> tuple[int, int]:
    """Return distinct target count and full scans created in the current UTC month.

    Watch-agent automated checks do not consume the manual scan quota.
    """
    month_start = datetime.now(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    with _lock:
        conn = _connect()
        try:
            targets = int(
                conn.execute(
                    """
                    SELECT COUNT(DISTINCT target) FROM (
                        SELECT target FROM scans WHERE org_id = ?
                        UNION
                        SELECT target FROM sites WHERE org_id = ? AND active = 1
                    )
                    """,
                    (org_id, org_id),
                ).fetchone()[0]
            )
            monthly_scans = int(
                conn.execute(
                    """
                    SELECT COUNT(*) FROM scans
                    WHERE org_id = ?
                      AND created_at >= ?
                      AND COALESCE(kind, 'full') = 'full'
                    """,
                    (org_id, month_start),
                ).fetchone()[0]
            )
            return targets, monthly_scans
        finally:
            conn.close()


def org_has_target(org_id: str, target: str) -> bool:
    with _lock:
        conn = _connect()
        try:
            return (
                conn.execute(
                    """
                    SELECT 1 FROM scans
                    WHERE org_id = ? AND target = ?
                    LIMIT 1
                    """,
                    (org_id, target),
                ).fetchone()
                is not None
            )
        finally:
            conn.close()


def list_org_targets(org_id: str) -> list[str]:
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT DISTINCT target FROM scans
                WHERE org_id = ?
                ORDER BY target
                """,
                (org_id,),
            ).fetchall()
            return [str(row["target"]) for row in rows]
        finally:
            conn.close()


def scan_to_dict(scan: ScanRecord) -> dict[str, Any]:
    return {
        "id": scan.id,
        "org_id": scan.org_id,
        "target": scan.target,
        "status": scan.status,
        "current_node": scan.current_node,
        "overall_risk_score": scan.overall_risk_score,
        "severity": scan.severity,
        "kind": scan.kind,
        "findings_count": scan.findings_count,
        "critical_high_count": scan.critical_high_count,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


def get_scan_record(scan_id: str) -> ScanRecord | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            return _row_to_scan(row) if row else None
        finally:
            conn.close()


def list_org_risk_trend(
    org_id: str,
    *,
    target: str | None = None,
    limit: int = 50,
) -> list[ScanRecord]:
    """Completed full scans for risk-over-time charts (excludes watch jobs)."""
    with _lock:
        conn = _connect()
        try:
            if target:
                rows = conn.execute(
                    """
                    SELECT * FROM scans
                    WHERE org_id = ?
                      AND target = ?
                      AND COALESCE(kind, 'full') = 'full'
                      AND status = 'completed'
                      AND overall_risk_score IS NOT NULL
                    ORDER BY created_at ASC
                    LIMIT ?
                    """,
                    (org_id, target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM scans
                    WHERE org_id = ?
                      AND COALESCE(kind, 'full') = 'full'
                      AND status = 'completed'
                      AND overall_risk_score IS NOT NULL
                    ORDER BY created_at ASC
                    LIMIT ?
                    """,
                    (org_id, limit),
                ).fetchall()
            return [_row_to_scan(row) for row in rows]
        finally:
            conn.close()


# --- Verify Fix history persistence -------------------------------------------


def save_finding_fix_verification(
    *,
    record_id: str,
    scan_id: str,
    org_id: str,
    finding_id: str,
    finding_url: str,
    finding_type: str,
    result: str,
    evidence: str | None,
    verification_status: str | None,
) -> dict[str, Any]:
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO finding_fix_verifications (
                    id, scan_id, org_id, finding_id, finding_url, finding_type,
                    result, evidence, verification_status, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    scan_id,
                    org_id,
                    finding_id,
                    finding_url,
                    finding_type,
                    result,
                    evidence,
                    verification_status,
                    now,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM finding_fix_verifications WHERE id = ?",
                (record_id,),
            ).fetchone()
            return dict(row)
        finally:
            conn.close()


def get_latest_finding_fix_verification(
    scan_id: str, finding_id: str
) -> dict[str, Any] | None:
    init_accounts_schema()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT * FROM finding_fix_verifications
                WHERE scan_id = ? AND finding_id = ?
                ORDER BY checked_at DESC
                LIMIT 1
                """,
                (scan_id, finding_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_finding_fix_verifications(
    scan_id: str, finding_id: str, *, limit: int = 50
) -> list[dict[str, Any]]:
    init_accounts_schema()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM finding_fix_verifications
                WHERE scan_id = ? AND finding_id = ?
                ORDER BY checked_at DESC
                LIMIT ?
                """,
                (scan_id, finding_id, limit),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


def list_scan_fix_verification_summaries(scan_id: str) -> dict[str, dict[str, Any]]:
    """Latest verify-fix result + attempt count per finding_id."""
    init_accounts_schema()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT f.*
                FROM finding_fix_verifications f
                INNER JOIN (
                    SELECT finding_id, MAX(checked_at) AS max_checked
                    FROM finding_fix_verifications
                    WHERE scan_id = ?
                    GROUP BY finding_id
                ) latest
                  ON f.finding_id = latest.finding_id
                 AND f.checked_at = latest.max_checked
                WHERE f.scan_id = ?
                """,
                (scan_id, scan_id),
            ).fetchall()
            out: dict[str, dict[str, Any]] = {}
            for row in rows:
                rec = dict(row)
                count = int(
                    conn.execute(
                        """
                        SELECT COUNT(*) FROM finding_fix_verifications
                        WHERE scan_id = ? AND finding_id = ?
                        """,
                        (scan_id, rec["finding_id"]),
                    ).fetchone()[0]
                )
                rec["attempt_count"] = count
                out[str(rec["finding_id"])] = rec
            return out
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
        "terms_accepted_at": user.terms_accepted_at,
        "terms_version": user.terms_version,
    }


def get_organization(org_id: str) -> Organization | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM organizations WHERE id = ?", (org_id,)
            ).fetchone()
            if row is None:
                return None
            keys = row.keys()
            return Organization(
                id=row["id"],
                name=row["name"],
                plan_id=row["plan_id"],
                max_targets=row["max_targets"],
                scans_per_month=row["scans_per_month"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                watch_emails_enabled=bool(
                    row["watch_emails_enabled"]
                    if "watch_emails_enabled" in keys
                    else 1
                ),
                brand_name=(
                    row["brand_name"] if "brand_name" in keys else None
                ),
                brand_logo_path=(
                    row["brand_logo_path"] if "brand_logo_path" in keys else None
                ),
            )
        finally:
            conn.close()


def update_organization_branding(
    org_id: str,
    *,
    brand_name: str | None = None,
    brand_logo_path: str | None = None,
    clear_logo: bool = False,
) -> Organization | None:
    """Persist Agency white-label brand name and/or logo path."""
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM organizations WHERE id = ?", (org_id,)
            ).fetchone()
            if row is None:
                return None
            keys = row.keys()
            next_name = (
                brand_name
                if brand_name is not None
                else (row["brand_name"] if "brand_name" in keys else None)
            )
            if clear_logo:
                next_logo: str | None = None
            elif brand_logo_path is not None:
                next_logo = brand_logo_path
            else:
                next_logo = (
                    row["brand_logo_path"] if "brand_logo_path" in keys else None
                )
            conn.execute(
                """
                UPDATE organizations SET
                    brand_name = ?,
                    brand_logo_path = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (next_name, next_logo, now, org_id),
            )
            conn.commit()
        finally:
            conn.close()
    return get_organization(org_id)


def branding_assets_dir() -> Path:
    """Directory for uploaded Agency logos (under the accounts data root)."""
    path = get_accounts_db_path().parent / "branding"
    path.mkdir(parents=True, exist_ok=True)
    return path


def claim_webhook_event(event_hash: str) -> bool:
    """Return True when this webhook payload has not been processed before."""
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            existing = conn.execute(
                "SELECT 1 FROM processed_webhook_events WHERE event_hash = ?",
                (event_hash,),
            ).fetchone()
            if existing is not None:
                return False
            conn.execute(
                """
                INSERT INTO processed_webhook_events (event_hash, processed_at)
                VALUES (?, ?)
                """,
                (event_hash, now),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def update_organization_plan(
    org_id: str,
    *,
    plan_id: str,
) -> Organization | None:
    """Apply plan limits from the catalog and persist them on the organization."""
    init_accounts_schema()
    limits = get_plan_limits(plan_id)
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE organizations SET
                    plan_id = ?,
                    max_targets = ?,
                    scans_per_month = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    limits.plan_id,
                    limits.max_targets,
                    limits.scans_per_month,
                    now,
                    org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return get_organization(org_id)


def set_watch_emails_enabled(org_id: str, enabled: bool) -> Organization | None:
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE organizations SET
                    watch_emails_enabled = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (1 if enabled else 0, now, org_id),
            )
            conn.commit()
        finally:
            conn.close()
    return get_organization(org_id)


def list_org_member_emails(org_id: str) -> list[str]:
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT email FROM users
                WHERE org_id = ? AND email IS NOT NULL AND email != ''
                ORDER BY created_at
                """,
                (org_id,),
            ).fetchall()
            return [str(row["email"]) for row in rows if row["email"]]
        finally:
            conn.close()


def find_org_id_by_email(email: str) -> str | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT org_id FROM users WHERE email = ? LIMIT 1",
                (email,),
            ).fetchone()
            return str(row["org_id"]) if row else None
        finally:
            conn.close()


def upsert_site(*, org_id: str, target: str, active: bool = True) -> SiteRecord:
    """Create or reactivate a monitored site for an organization."""
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            existing = conn.execute(
                "SELECT * FROM sites WHERE org_id = ? AND target = ?",
                (org_id, target),
            ).fetchone()
            if existing is None:
                site_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO sites (
                        id, org_id, target, active, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (site_id, org_id, target, 1 if active else 0, now, now),
                )
            else:
                site_id = existing["id"]
                conn.execute(
                    """
                    UPDATE sites SET
                        active = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (1 if active else 0, now, site_id),
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM sites WHERE id = ?", (site_id,)
            ).fetchone()
            return _row_to_site(row)
        finally:
            conn.close()


def deactivate_site(site_id: str) -> SiteRecord | None:
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE sites SET active = 0, updated_at = ?
                WHERE id = ?
                """,
                (now, site_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM sites WHERE id = ?", (site_id,)
            ).fetchone()
            return _row_to_site(row) if row else None
        finally:
            conn.close()


def get_site(site_id: str) -> SiteRecord | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM sites WHERE id = ?", (site_id,)
            ).fetchone()
            return _row_to_site(row) if row else None
        finally:
            conn.close()


def get_site_by_target(org_id: str, target: str) -> SiteRecord | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM sites WHERE org_id = ? AND target = ?",
                (org_id, target),
            ).fetchone()
            return _row_to_site(row) if row else None
        finally:
            conn.close()


def list_org_sites(org_id: str, *, active_only: bool = True) -> list[SiteRecord]:
    with _lock:
        conn = _connect()
        try:
            if active_only:
                rows = conn.execute(
                    """
                    SELECT * FROM sites
                    WHERE org_id = ? AND active = 1
                    ORDER BY target
                    """,
                    (org_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM sites
                    WHERE org_id = ?
                    ORDER BY target
                    """,
                    (org_id,),
                ).fetchall()
            return [_row_to_site(row) for row in rows]
        finally:
            conn.close()


def list_watchable_sites() -> list[SiteRecord]:
    """Active sites whose org plan supports automated watch jobs."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT s.* FROM sites s
                JOIN organizations o ON o.id = s.org_id
                WHERE s.active = 1 AND o.plan_id IN ('starter', 'pro', 'agency')
                ORDER BY s.org_id, s.target
                """
            ).fetchall()
            return [_row_to_site(row) for row in rows]
        finally:
            conn.close()


def update_site_fingerprint(site_id: str, fingerprint: list[dict[str, Any]]) -> None:
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE sites SET
                    fingerprint_json = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(fingerprint), now, site_id),
            )
            conn.commit()
        finally:
            conn.close()


def touch_site_watch(site_id: str) -> None:
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE sites SET last_watch_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, site_id),
            )
            conn.commit()
        finally:
            conn.close()


def touch_site_cve_check(site_id: str) -> None:
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE sites SET last_cve_check_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, site_id),
            )
            conn.commit()
        finally:
            conn.close()


def save_findings_snapshot(
    *,
    site_id: str,
    org_id: str,
    findings: list[dict[str, Any]],
    source: str,
    scan_id: str | None = None,
) -> str:
    init_accounts_schema()
    snapshot_id = str(uuid.uuid4())
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO watch_findings_snapshots (
                    id, site_id, org_id, scan_id, source, findings_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    site_id,
                    org_id,
                    scan_id,
                    source,
                    json.dumps(findings),
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return snapshot_id


def get_latest_findings_snapshot(site_id: str) -> list[dict[str, Any]] | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT findings_json FROM watch_findings_snapshots
                WHERE site_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (site_id,),
            ).fetchone()
            if row is None:
                return None
            return list(json.loads(row["findings_json"]))
        finally:
            conn.close()


def save_watch_diff(
    *,
    site_id: str,
    org_id: str,
    newly_appeared: list[dict[str, Any]],
    severity_increased: list[dict[str, Any]],
    fixed: list[dict[str, Any]],
    should_alert: bool,
    scan_id: str | None = None,
) -> str:
    init_accounts_schema()
    diff_id = str(uuid.uuid4())
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO watch_diffs (
                    id, site_id, org_id, scan_id,
                    newly_appeared_json, severity_increased_json, fixed_json,
                    should_alert, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    diff_id,
                    site_id,
                    org_id,
                    scan_id,
                    json.dumps(newly_appeared),
                    json.dumps(severity_increased),
                    json.dumps(fixed),
                    1 if should_alert else 0,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return diff_id


def has_cve_alert(site_id: str, cve_id: str) -> bool:
    with _lock:
        conn = _connect()
        try:
            return (
                conn.execute(
                    """
                    SELECT 1 FROM site_cve_alerts
                    WHERE site_id = ? AND cve_id = ?
                    """,
                    (site_id, cve_id),
                ).fetchone()
                is not None
            )
        finally:
            conn.close()


def record_cve_alert(
    *,
    site_id: str,
    cve_id: str,
    product: str | None = None,
    version: str | None = None,
    summary: str | None = None,
) -> bool:
    """Insert a CVE alert row. Returns False if already alerted (dedup)."""
    init_accounts_schema()
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            try:
                conn.execute(
                    """
                    INSERT INTO site_cve_alerts (
                        site_id, cve_id, alerted_at, product, version, summary
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (site_id, cve_id, now, product, version, summary),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False
        finally:
            conn.close()


def enqueue_email(
    *,
    org_id: str,
    to_email: str,
    subject: str,
    html_body: str,
    next_attempt_at: str | None = None,
) -> str:
    init_accounts_schema()
    email_id = str(uuid.uuid4())
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO email_outbox (
                    id, org_id, to_email, subject, html_body,
                    status, attempts, next_attempt_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
                """,
                (
                    email_id,
                    org_id,
                    to_email,
                    subject,
                    html_body,
                    next_attempt_at or now,
                    now,
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return email_id


def list_due_emails(*, limit: int = 20) -> list[dict[str, Any]]:
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM email_outbox
                WHERE status IN ('pending', 'retry')
                  AND next_attempt_at <= ?
                  AND attempts < 8
                ORDER BY next_attempt_at
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


def mark_email_sent(email_id: str) -> None:
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE email_outbox SET
                    status = 'sent',
                    updated_at = ?
                WHERE id = ?
                """,
                (now, email_id),
            )
            conn.commit()
        finally:
            conn.close()


def mark_email_retry(email_id: str, *, error: str, delay_seconds: int) -> None:
    now_dt = datetime.now(timezone.utc)
    next_at = now_dt.timestamp() + delay_seconds
    next_iso = datetime.fromtimestamp(next_at, tz=timezone.utc).isoformat()
    now = now_dt.isoformat()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE email_outbox SET
                    status = 'retry',
                    attempts = attempts + 1,
                    last_error = ?,
                    next_attempt_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (error[:2000], next_iso, now, email_id),
            )
            conn.commit()
        finally:
            conn.close()


def _row_to_site_auth(row: sqlite3.Row) -> SiteAuthCredentialRecord:
    return SiteAuthCredentialRecord(
        site_id=row["site_id"],
        org_id=row["org_id"],
        login_url=row["login_url"],
        username_field=row["username_field"],
        password_field=row["password_field"],
        encrypted_data_key=bytes(row["encrypted_data_key"]),
        encrypted_payload=bytes(row["encrypted_payload"]),
        username_hint=row["username_hint"],
        credentials_consent_user_id=row["credentials_consent_user_id"],
        credentials_consent_at=row["credentials_consent_at"],
        excluded_paths_json=row["excluded_paths_json"] or "[]",
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def get_site_auth_credentials(
    site_id: str,
    *,
    org_id: str | None = None,
) -> SiteAuthCredentialRecord | None:
    """Fetch site credentials, optionally scoped to an organization (IDOR-safe)."""
    init_accounts_schema()
    with _lock:
        conn = _connect()
        try:
            if org_id is not None:
                row = conn.execute(
                    """
                    SELECT * FROM site_auth_credentials
                    WHERE site_id = ? AND org_id = ?
                    """,
                    (site_id, org_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM site_auth_credentials WHERE site_id = ?",
                    (site_id,),
                ).fetchone()
            return _row_to_site_auth(row) if row else None
        finally:
            conn.close()


def probe_accounts_db() -> tuple[bool, str | None]:
    """Return (ok, error) for health checks — verifies SQLite is readable."""
    try:
        init_accounts_schema()
        with _lock:
            conn = _connect()
            try:
                conn.execute("SELECT 1").fetchone()
            finally:
                conn.close()
        return True, None
    except Exception as exc:  # noqa: BLE001 - health probe must never raise
        return False, str(exc)


def get_site_auth_credentials_by_target(
    org_id: str, target: str
) -> SiteAuthCredentialRecord | None:
    site = get_site_by_target(org_id, target)
    if site is None:
        return None
    return get_site_auth_credentials(site.id)


def upsert_site_auth_credentials(
    *,
    site_id: str,
    org_id: str,
    login_url: str,
    username_field: str,
    password_field: str,
    encrypted_data_key: bytes,
    encrypted_payload: bytes,
    username_hint: str,
    credentials_consent_user_id: str,
    credentials_consent_at: str | None = None,
    excluded_paths: list[str] | None = None,
) -> SiteAuthCredentialRecord:
    """Store or replace encrypted credentials + consent attestation for a site."""
    init_accounts_schema()
    now = _utc_now()
    consent_at = credentials_consent_at or now
    paths_json = json.dumps(excluded_paths or [])
    with _lock:
        conn = _connect()
        try:
            existing = conn.execute(
                "SELECT site_id FROM site_auth_credentials WHERE site_id = ?",
                (site_id,),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO site_auth_credentials (
                        site_id, org_id, login_url, username_field, password_field,
                        encrypted_data_key, encrypted_payload, username_hint,
                        credentials_consent_user_id, credentials_consent_at,
                        excluded_paths_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        site_id,
                        org_id,
                        login_url,
                        username_field,
                        password_field,
                        encrypted_data_key,
                        encrypted_payload,
                        username_hint,
                        credentials_consent_user_id,
                        consent_at,
                        paths_json,
                        now,
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE site_auth_credentials SET
                        login_url = ?,
                        username_field = ?,
                        password_field = ?,
                        encrypted_data_key = ?,
                        encrypted_payload = ?,
                        username_hint = ?,
                        credentials_consent_user_id = ?,
                        credentials_consent_at = ?,
                        excluded_paths_json = ?,
                        updated_at = ?
                    WHERE site_id = ?
                    """,
                    (
                        login_url,
                        username_field,
                        password_field,
                        encrypted_data_key,
                        encrypted_payload,
                        username_hint,
                        credentials_consent_user_id,
                        consent_at,
                        paths_json,
                        now,
                        site_id,
                    ),
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM site_auth_credentials WHERE site_id = ?",
                (site_id,),
            ).fetchone()
            return _row_to_site_auth(row)
        finally:
            conn.close()


def update_site_excluded_paths(
    site_id: str, excluded_paths: list[str]
) -> SiteAuthCredentialRecord | None:
    """Update destructive-path exclusions without touching ciphertext."""
    init_accounts_schema()
    now = _utc_now()
    paths_json = json.dumps(excluded_paths)
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE site_auth_credentials SET
                    excluded_paths_json = ?,
                    updated_at = ?
                WHERE site_id = ?
                """,
                (paths_json, now, site_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM site_auth_credentials WHERE site_id = ?",
                (site_id,),
            ).fetchone()
            return _row_to_site_auth(row) if row else None
        finally:
            conn.close()


def delete_site_auth_credentials(site_id: str) -> bool:
    """Fully delete the encrypted credential record. Returns True if a row was removed."""
    init_accounts_schema()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "DELETE FROM site_auth_credentials WHERE site_id = ?",
                (site_id,),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def site_auth_public_dict(record: SiteAuthCredentialRecord | None) -> dict[str, Any]:
    """Safe public view — never includes ciphertext or plaintext secrets."""
    if record is None:
        return {
            "configured": False,
            "username_hint": None,
            "login_url": None,
            "username_field": None,
            "password_field": None,
            "excluded_paths": [],
            "credentials_consent_at": None,
            "credentials_consent_user_id": None,
        }
    return {
        "configured": True,
        "username_hint": record.username_hint,
        "login_url": record.login_url,
        "username_field": record.username_field,
        "password_field": record.password_field,
        "excluded_paths": record.excluded_paths,
        "credentials_consent_at": record.credentials_consent_at,
        "credentials_consent_user_id": record.credentials_consent_user_id,
        "updated_at": record.updated_at,
    }


def site_to_dict(site: SiteRecord) -> dict[str, Any]:
    fingerprint = None
    if site.fingerprint_json:
        try:
            fingerprint = json.loads(site.fingerprint_json)
        except json.JSONDecodeError:
            fingerprint = None
    auth = site_auth_public_dict(get_site_auth_credentials(site.id))
    return {
        "id": site.id,
        "org_id": site.org_id,
        "target": site.target,
        "active": site.active,
        "last_watch_at": site.last_watch_at,
        "last_cve_check_at": site.last_cve_check_at,
        "fingerprint": fingerprint,
        "created_at": site.created_at,
        "updated_at": site.updated_at,
        "authenticated_scanning": auth,
    }


def _hash_extension_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_extension_token(
    *,
    org_id: str,
    user_id: str,
    label: str | None = "chrome-extension",
) -> tuple[ExtensionTokenRecord, str]:
    """Mint a long-lived extension API key. Returns (record, plaintext_once)."""
    token_id = str(uuid.uuid4())
    raw = f"cmext_{secrets.token_urlsafe(32)}"
    key_hash = _hash_extension_token(raw)
    key_prefix = raw[:12]
    now = _utc_now()
    record = ExtensionTokenRecord(
        id=token_id,
        org_id=org_id,
        user_id=user_id,
        key_prefix=key_prefix,
        created_at=now,
        label=label,
    )
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO extension_tokens (
                    id, org_id, user_id, key_hash, key_prefix, label, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.org_id,
                    record.user_id,
                    key_hash,
                    record.key_prefix,
                    record.label,
                    record.created_at,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return record, raw


def resolve_extension_token(raw_token: str) -> ExtensionTokenRecord | None:
    """Look up a non-revoked extension token by its plaintext value."""
    token = (raw_token or "").strip()
    if not token:
        return None
    key_hash = _hash_extension_token(token)
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT * FROM extension_tokens
                WHERE key_hash = ? AND revoked_at IS NULL
                """,
                (key_hash,),
            ).fetchone()
            if row is None:
                return None
            return ExtensionTokenRecord(
                id=row["id"],
                org_id=row["org_id"],
                user_id=row["user_id"],
                key_prefix=row["key_prefix"],
                created_at=row["created_at"],
                revoked_at=row["revoked_at"],
                label=row["label"],
            )
        finally:
            conn.close()


def revoke_extension_tokens_for_user(user_id: str) -> int:
    """Revoke all active extension tokens for a user. Returns count revoked."""
    now = _utc_now()
    with _lock:
        conn = _connect()
        try:
            cursor = conn.execute(
                """
                UPDATE extension_tokens
                SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (now, user_id),
            )
            conn.commit()
            return int(cursor.rowcount or 0)
        finally:
            conn.close()


def extension_token_to_dict(record: ExtensionTokenRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "org_id": record.org_id,
        "user_id": record.user_id,
        "key_prefix": record.key_prefix,
        "label": record.label,
        "created_at": record.created_at,
        "revoked_at": record.revoked_at,
    }
