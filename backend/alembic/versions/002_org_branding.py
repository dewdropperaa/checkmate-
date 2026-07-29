"""Add Agency white-label branding columns on organizations.

Revision ID: 002
Revises: 001
Create Date: 2026-07-22
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "002"
down_revision: Union[str, Sequence[str], None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent: revision 001's INITIAL_SCHEMA may already include these
    # columns on fresh installs; older DBs need ALTER TABLE.
    conn = op.get_bind()
    existing = {
        row[1]
        for row in conn.exec_driver_sql("PRAGMA table_info(organizations)").fetchall()
    }
    if "brand_name" not in existing:
        op.execute("ALTER TABLE organizations ADD COLUMN brand_name TEXT")
    if "brand_logo_path" not in existing:
        op.execute("ALTER TABLE organizations ADD COLUMN brand_logo_path TEXT")


def downgrade() -> None:
    # SQLite cannot DROP COLUMN on older versions; leave columns in place on
    # downgrade. Fresh installs still get the baseline from revision 001 + 002.
    pass
