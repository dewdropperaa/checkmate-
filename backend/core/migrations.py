"""Alembic migration runner for the accounts SQLite database."""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from core.accounts import get_accounts_db_path

logger = logging.getLogger(__name__)

_ALEMBIC_INI = Path(__file__).resolve().parent.parent / "alembic.ini"


def _alembic_config() -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    db_path = get_accounts_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.set_main_option("script_location", str(_ALEMBIC_INI.parent / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def upgrade_database() -> None:
    """Apply all pending Alembic migrations."""
    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    logger.info("Database migrations applied (head=%s)", get_head_revision())


def get_head_revision() -> str | None:
    script = ScriptDirectory.from_config(_alembic_config())
    return script.get_current_head()


def get_current_revision() -> str | None:
    db_path = get_accounts_db_path()
    if not db_path.exists():
        return None
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.connect() as conn:
        context = MigrationContext.configure(conn)
        return context.get_current_revision()


def probe_migrations() -> tuple[bool, str | None]:
    """Return (migrations_current, error) for health checks."""
    try:
        head = get_head_revision()
        if head is None:
            return False, "No Alembic head revision configured"
        current = get_current_revision()
        if current is None:
            return False, "Database has not been migrated (alembic_version missing)"
        if current != head:
            return (
                False,
                f"Database revision {current!r} is behind head {head!r}",
            )
        return True, None
    except Exception as exc:  # noqa: BLE001 - health probe must never raise
        return False, str(exc)


def verify_schema_matches_models() -> list[str]:
    """Compare live SQLite schema to the expected baseline tables/columns."""
    from core.db_schema import EXPECTED_TABLES

    db_path = get_accounts_db_path()
    if not db_path.exists():
        return ["accounts database file does not exist"]

    engine = create_engine(f"sqlite:///{db_path}")
    drift: list[str] = []
    with engine.connect() as conn:
        for table, expected_columns in EXPECTED_TABLES.items():
            row = conn.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name=:name"
                ),
                {"name": table},
            ).fetchone()
            if row is None:
                drift.append(f"missing table: {table}")
                continue
            info = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            live_columns = {str(col[1]) for col in info}
            missing = sorted(expected_columns - live_columns)
            if missing:
                drift.append(f"{table}: missing columns {missing}")
    return drift
