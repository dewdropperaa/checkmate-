"""Ops isolation, Alembic migrations, and data persistence tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.accounts import (
    configure_accounts_db,
    get_organization,
    get_user,
    init_accounts_schema,
    upsert_user_from_firebase,
)
from core.config import Settings, validate_startup_settings
from core.migrations import (
    get_current_revision,
    get_head_revision,
    probe_migrations,
    upgrade_database,
    verify_schema_matches_models,
)


def _production_settings(**overrides) -> Settings:
    base = dict(
        app_env="production",
        debug=False,
        firecrawl_enabled=False,
        zap_api_key="zap-key",
        firebase_project_id="checkmate-prod",
        production_firebase_project_id="checkmate-prod",
        firebase_credentials_json="{}",
        require_firebase_auth=True,
        dodo_environment="live",
        dodo_api_key="dodo_live_integration_key",
        dodo_webhook_secret="whsec_prod",
        credentials_master_key="x" * 44,
    )
    base.update(overrides)
    return Settings(**base)


class TestEnvironmentIsolation:
    def test_production_rejects_debug_with_live_dodo(self) -> None:
        settings = _production_settings(debug=True)
        with pytest.raises(ValueError, match="DEBUG=true"):
            validate_startup_settings(settings)

    def test_production_rejects_test_dodo_key(self) -> None:
        settings = _production_settings(
            dodo_environment="live",
            dodo_api_key="dodo_test_only_key",
        )
        with pytest.raises(ValueError, match="dodo_live_"):
            validate_startup_settings(settings)

    def test_production_rejects_test_dodo_environment(self) -> None:
        settings = _production_settings(dodo_environment="test")
        with pytest.raises(ValueError, match="DODO_ENVIRONMENT=live"):
            validate_startup_settings(settings)

    def test_development_rejects_live_dodo_key(self) -> None:
        settings = Settings(
            app_env="development",
            dodo_environment="test",
            dodo_api_key="dodo_live_should_not_run_locally",
        )
        with pytest.raises(ValueError, match="live key"):
            validate_startup_settings(settings)

    def test_development_rejects_production_firebase_project(self) -> None:
        settings = Settings(
            app_env="development",
            firebase_project_id="checkmate-prod",
            production_firebase_project_id="checkmate-prod",
        )
        with pytest.raises(ValueError, match="PRODUCTION_FIREBASE_PROJECT_ID"):
            validate_startup_settings(settings)

    def test_dodo_environment_must_match_key_prefix(self) -> None:
        settings = Settings(
            app_env="development",
            dodo_environment="test",
            dodo_api_key="dodo_live_mismatch",
        )
        with pytest.raises(ValueError, match="does not match"):
            validate_startup_settings(settings)

    def test_production_requires_all_blocking_secrets(self) -> None:
        settings = Settings(
            app_env="production",
            firecrawl_enabled=False,
            zap_api_key="zap-key",
            firebase_project_id="checkmate-prod",
            firebase_credentials_json="{}",
            require_firebase_auth=False,
            dodo_environment="live",
            dodo_api_key=None,
            dodo_webhook_secret=None,
            credentials_master_key=None,
        )
        with pytest.raises(ValueError) as exc:
            validate_startup_settings(settings)
        message = str(exc.value)
        assert "REQUIRE_FIREBASE_AUTH" in message
        assert "DODO_WEBHOOK_SECRET" in message
        assert "CREDENTIALS_MASTER_KEY" in message
        assert "DODO_API_KEY" in message

    def test_production_passes_with_complete_isolated_config(self) -> None:
        validate_startup_settings(_production_settings())

    def test_development_skips_production_requirements(self) -> None:
        settings = Settings(app_env="development", firecrawl_enabled=True)
        validate_startup_settings(settings)

    def test_hosted_requires_firebase_and_auth_without_live_billing(self) -> None:
        settings = Settings(
            app_env="hosted",
            debug=False,
            firecrawl_enabled=False,
            cloud_scanning_enabled=False,
            firebase_project_id="checkmate-prod",
            firebase_credentials_json="{}",
            require_firebase_auth=True,
            credentials_master_key="x" * 44,
            dodo_environment="test",
        )
        validate_startup_settings(settings)

    def test_hosted_with_scans_requires_zap_key(self) -> None:
        settings = Settings(
            app_env="hosted",
            debug=False,
            firecrawl_enabled=False,
            cloud_scanning_enabled=True,
            cloud_scan_profile="full",
            zap_api_key="",
            firebase_project_id="checkmate-prod",
            firebase_credentials_json="{}",
            require_firebase_auth=True,
            credentials_master_key="x" * 44,
        )
        with pytest.raises(ValueError, match="ZAP_API_KEY"):
            validate_startup_settings(settings)

    def test_hosted_firecrawl_profile_requires_firecrawl_key(self) -> None:
        settings = Settings(
            app_env="hosted",
            debug=False,
            cloud_scanning_enabled=True,
            cloud_scan_profile="firecrawl",
            firecrawl_enabled=True,
            firecrawl_api_key="",
            firebase_project_id="checkmate-prod",
            firebase_credentials_json="{}",
            require_firebase_auth=True,
            credentials_master_key="x" * 44,
        )
        with pytest.raises(ValueError, match="FIRECRAWL_API_KEY"):
            validate_startup_settings(settings)

    def test_hosted_firecrawl_profile_passes_without_zap(self) -> None:
        settings = Settings(
            app_env="hosted",
            debug=False,
            cloud_scanning_enabled=True,
            cloud_scan_profile="firecrawl",
            firecrawl_enabled=True,
            firecrawl_api_key="fc-test",
            firebase_project_id="checkmate-prod",
            firebase_credentials_json="{}",
            require_firebase_auth=True,
            credentials_master_key="x" * 44,
        )
        validate_startup_settings(settings)

    def test_hosted_rejects_debug(self) -> None:
        settings = Settings(
            app_env="hosted",
            debug=True,
            firecrawl_enabled=False,
            cloud_scanning_enabled=False,
            firebase_project_id="checkmate-prod",
            firebase_credentials_json="{}",
            require_firebase_auth=True,
            credentials_master_key="x" * 44,
        )
        with pytest.raises(ValueError, match="APP_ENV=hosted"):
            validate_startup_settings(settings)


class TestMigrations:
    def test_initial_migration_applies_to_empty_database(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "accounts.db"
        configure_accounts_db(db_path)
        try:
            upgrade_database()
            assert get_current_revision() == get_head_revision()
            drift = verify_schema_matches_models()
            assert drift == []
        finally:
            configure_accounts_db(None)

    def test_init_accounts_schema_runs_migrations(self, tmp_path: Path) -> None:
        db_path = tmp_path / "accounts.db"
        configure_accounts_db(db_path)
        try:
            init_accounts_schema()
            ok, error = probe_migrations()
            assert ok is True, error
        finally:
            configure_accounts_db(None)

    def test_health_reports_migration_status(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert "migrations_current" in body
        assert isinstance(body["migrations_current"], bool)


class TestDataPersistence:
    def test_sqlite_data_survives_connection_restart(self, tmp_path: Path) -> None:
        """Simulates container restart: same volume path, new DB connections."""
        db_path = tmp_path / "accounts.db"
        configure_accounts_db(db_path)
        try:
            init_accounts_schema()
            user, _created = upsert_user_from_firebase(
                uid="persist-user-1",
                email="persist@example.com",
                display_name="Persist User",
                email_verified=True,
                auth_provider="password",
            )
            org_id = user.org_id

            # "Restart" — drop in-process state and reopen the file.
            configure_accounts_db(db_path)
            init_accounts_schema()
            restored_user = get_user("persist-user-1")
            assert restored_user is not None
            restored = get_organization(org_id)
            assert restored is not None
            assert "persist" in restored.name.lower()

            conn = sqlite3.connect(str(db_path))
            try:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
            finally:
                conn.close()
            assert "organizations" in tables
            assert "alembic_version" in tables
        finally:
            configure_accounts_db(None)

    def test_compose_documents_named_data_volumes(self) -> None:
        compose = (
            Path(__file__).resolve().parent.parent / "docker-compose.yml"
        ).read_text(encoding="utf-8")
        assert "app-data:/app/data" in compose
        assert "app-reports:/app/reports" in compose
        assert "app-data:" in compose
        assert "app-reports:" in compose
