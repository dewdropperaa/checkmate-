"""Add finding_fix_verifications table and scan trend metric columns.

Revision ID: 004
Revises: 003
Create Date: 2026-07-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, Sequence[str], None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
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
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_fix_verify_scan_finding
            ON finding_fix_verifications(scan_id, finding_id, checked_at DESC)
        """
    )
    # Idempotent: fresh installs from INITIAL_SCHEMA may already include these.
    conn = op.get_bind()
    existing = {
        row[1]
        for row in conn.exec_driver_sql("PRAGMA table_info(scans)").fetchall()
    }
    if "findings_count" not in existing:
        op.execute("ALTER TABLE scans ADD COLUMN findings_count INTEGER")
    if "critical_high_count" not in existing:
        op.execute("ALTER TABLE scans ADD COLUMN critical_high_count INTEGER")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_fix_verify_scan_finding")
    op.execute("DROP TABLE IF EXISTS finding_fix_verifications")
