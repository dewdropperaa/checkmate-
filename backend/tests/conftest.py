"""Pytest configuration and shared fixtures."""

import os

import pytest
from fastapi.testclient import TestClient

# Ensure tests run with a known allowlist before settings are cached.
os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")
os.environ.setdefault("OPENAI_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")

# Never hit the real Firecrawl API from the test suite. Env vars take
# precedence over the .env file, so this overrides any local key.
os.environ["FIRECRAWL_ENABLED"] = "false"
os.environ["FIRECRAWL_API_KEY"] = ""


@pytest.fixture(autouse=True)
def isolated_orchestrator():
    from agents.orchestrator import reset_orchestrator

    reset_orchestrator(use_sqlite=False)
    yield
    reset_orchestrator(use_sqlite=False)


@pytest.fixture
def client() -> TestClient:
    from core.config import get_settings

    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()
