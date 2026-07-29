"""Initial accounts schema baseline.

Revision ID: 001
Revises:
Create Date: 2026-07-21

Captures the full accounts.db schema as of launch readiness:
organizations, users, scans, sites, watch tables, email_outbox,
extension_tokens, and site_auth_credentials.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from core.db_schema import INITIAL_SCHEMA_STATEMENTS

revision: str = "001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite accepts only one statement per execute() call.
    for statement in INITIAL_SCHEMA_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    for statement in (
        "DROP TABLE IF EXISTS site_auth_credentials",
        "DROP TABLE IF EXISTS extension_tokens",
        "DROP TABLE IF EXISTS email_outbox",
        "DROP TABLE IF EXISTS site_cve_alerts",
        "DROP TABLE IF EXISTS watch_diffs",
        "DROP TABLE IF EXISTS watch_findings_snapshots",
        "DROP TABLE IF EXISTS sites",
        "DROP TABLE IF EXISTS scans",
        "DROP TABLE IF EXISTS users",
        "DROP TABLE IF EXISTS organizations",
    ):
        op.execute(statement)
