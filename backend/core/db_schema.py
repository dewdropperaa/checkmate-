"""Canonical accounts-database schema baseline for Alembic drift checks."""

from __future__ import annotations

# Executed one statement at a time — SQLite rejects multi-statement batches.
INITIAL_SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        plan_id TEXT NOT NULL DEFAULT 'free',
        max_targets INTEGER,
        scans_per_month INTEGER,
        watch_emails_enabled INTEGER NOT NULL DEFAULT 1,
        brand_name TEXT,
        brand_logo_path TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT,
        display_name TEXT,
        auth_provider TEXT,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        email_verified INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_login_at TEXT,
        terms_accepted_at TEXT,
        terms_version TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
    "CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)",
    """
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        target TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        current_node TEXT,
        overall_risk_score REAL,
        severity TEXT,
        kind TEXT NOT NULL DEFAULT 'full',
        findings_count INTEGER,
        critical_high_count INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_scans_org_created
        ON scans(org_id, created_at DESC)
    """,
    "CREATE INDEX IF NOT EXISTS idx_scans_org_target ON scans(org_id, target)",
    """
    CREATE TABLE IF NOT EXISTS finding_fix_verifications (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        finding_id TEXT NOT NULL,
        finding_url TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        result TEXT NOT NULL,
        evidence TEXT,
        verification_status TEXT,
        checked_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_fix_verify_scan_finding
        ON finding_fix_verifications(scan_id, finding_id, checked_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS sites (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        target TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        last_watch_at TEXT,
        last_cve_check_at TEXT,
        fingerprint_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(org_id, target)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sites_org_active ON sites(org_id, active)",
    """
    CREATE TABLE IF NOT EXISTS watch_findings_snapshots (
        id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        scan_id TEXT,
        source TEXT NOT NULL,
        findings_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_watch_snapshots_site
        ON watch_findings_snapshots(site_id, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS watch_diffs (
        id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        scan_id TEXT,
        newly_appeared_json TEXT NOT NULL,
        severity_increased_json TEXT NOT NULL,
        fixed_json TEXT NOT NULL,
        should_alert INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_watch_diffs_site
        ON watch_diffs(site_id, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS site_cve_alerts (
        site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        cve_id TEXT NOT NULL,
        alerted_at TEXT NOT NULL,
        product TEXT,
        version TEXT,
        summary TEXT,
        PRIMARY KEY (site_id, cve_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS email_outbox (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        to_email TEXT NOT NULL,
        subject TEXT NOT NULL,
        html_body TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        next_attempt_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_email_outbox_pending
        ON email_outbox(status, next_attempt_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS extension_tokens (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        user_id TEXT NOT NULL REFERENCES users(id),
        key_hash TEXT NOT NULL UNIQUE,
        key_prefix TEXT NOT NULL,
        label TEXT,
        created_at TEXT NOT NULL,
        revoked_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_extension_tokens_hash ON extension_tokens(key_hash)",
    "CREATE INDEX IF NOT EXISTS idx_extension_tokens_org ON extension_tokens(org_id)",
    """
    CREATE TABLE IF NOT EXISTS site_auth_credentials (
        site_id TEXT PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
        org_id TEXT NOT NULL REFERENCES organizations(id),
        login_url TEXT NOT NULL,
        username_field TEXT NOT NULL,
        password_field TEXT NOT NULL,
        encrypted_data_key BLOB NOT NULL,
        encrypted_payload BLOB NOT NULL,
        username_hint TEXT NOT NULL,
        credentials_consent_user_id TEXT NOT NULL,
        credentials_consent_at TEXT NOT NULL,
        excluded_paths_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_site_auth_creds_org
        ON site_auth_credentials(org_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS processed_webhook_events (
        event_hash TEXT PRIMARY KEY,
        processed_at TEXT NOT NULL
    )
    """,
)

# Table -> expected column names (matches INITIAL_SCHEMA_STATEMENTS).
EXPECTED_TABLES: dict[str, set[str]] = {
    "organizations": {
        "id",
        "name",
        "plan_id",
        "max_targets",
        "scans_per_month",
        "watch_emails_enabled",
        "brand_name",
        "brand_logo_path",
        "created_at",
        "updated_at",
    },
    "users": {
        "id",
        "email",
        "display_name",
        "auth_provider",
        "org_id",
        "email_verified",
        "created_at",
        "updated_at",
        "last_login_at",
        "terms_accepted_at",
        "terms_version",
    },
    "scans": {
        "id",
        "org_id",
        "target",
        "status",
        "current_node",
        "overall_risk_score",
        "severity",
        "kind",
        "findings_count",
        "critical_high_count",
        "created_at",
        "updated_at",
    },
    "finding_fix_verifications": {
        "id",
        "scan_id",
        "org_id",
        "finding_id",
        "finding_url",
        "finding_type",
        "result",
        "evidence",
        "verification_status",
        "checked_at",
    },
    "sites": {
        "id",
        "org_id",
        "target",
        "active",
        "last_watch_at",
        "last_cve_check_at",
        "fingerprint_json",
        "created_at",
        "updated_at",
    },
    "watch_findings_snapshots": {
        "id",
        "site_id",
        "org_id",
        "scan_id",
        "source",
        "findings_json",
        "created_at",
    },
    "watch_diffs": {
        "id",
        "site_id",
        "org_id",
        "scan_id",
        "newly_appeared_json",
        "severity_increased_json",
        "fixed_json",
        "should_alert",
        "created_at",
    },
    "site_cve_alerts": {
        "site_id",
        "cve_id",
        "alerted_at",
        "product",
        "version",
        "summary",
    },
    "email_outbox": {
        "id",
        "org_id",
        "to_email",
        "subject",
        "html_body",
        "status",
        "attempts",
        "last_error",
        "next_attempt_at",
        "created_at",
        "updated_at",
    },
    "extension_tokens": {
        "id",
        "org_id",
        "user_id",
        "key_hash",
        "key_prefix",
        "label",
        "created_at",
        "revoked_at",
    },
    "site_auth_credentials": {
        "site_id",
        "org_id",
        "login_url",
        "username_field",
        "password_field",
        "encrypted_data_key",
        "encrypted_payload",
        "username_hint",
        "credentials_consent_user_id",
        "credentials_consent_at",
        "excluded_paths_json",
        "created_at",
        "updated_at",
    },
    "processed_webhook_events": {
        "event_hash",
        "processed_at",
    },
}
