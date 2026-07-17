"""Pytest configuration and shared fixtures."""

import os

import pytest
from fastapi.testclient import TestClient

# Ensure tests run with a known allowlist before settings are cached.
os.environ.setdefault("AUTHORIZED_TARGETS", "authorized.example.com")
os.environ.setdefault("OPENAI_API_KEY", "")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("GEMINI_API_KEY", "")
os.environ.setdefault("GROQ_API_KEY", "")

# Never hit the real Firecrawl API from the test suite. Env vars take
# precedence over the .env file, so this overrides any local key.
os.environ["FIRECRAWL_ENABLED"] = "false"
os.environ["FIRECRAWL_API_KEY"] = ""
os.environ.setdefault("REQUIRE_TOOLCHAIN_AT_STARTUP", "false")


@pytest.fixture(autouse=True)
def mock_toolchain_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests run without real security binaries installed locally."""
    from core.toolchain import BinaryStatus, ToolchainReport, REQUIRED_BINARIES

    report = ToolchainReport(ready=True, zap_ready=True, nuclei_templates_ok=True)
    for name in REQUIRED_BINARIES:
        report.binaries[name] = BinaryStatus(
            name=name,
            path=f"/opt/tools/{name}",
            ok=True,
        )

    monkeypatch.setattr("core.toolchain.get_toolchain_report", lambda: report)
    monkeypatch.setattr("core.toolchain.inspect_toolchain", lambda *a, **k: report)
    monkeypatch.setattr("core.toolchain.ensure_toolchain_ready", lambda: None)
    monkeypatch.setattr("core.toolchain.validate_toolchain_at_startup", lambda *a, **k: report)


@pytest.fixture(autouse=True)
def mock_test_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve test hostnames to a public IP so tool scope checks succeed offline."""
    import socket

    _TEST_HOSTS = frozenset({
        "authorized.example.com",
        "test.example.com",
        "sub.authorized.example.com",
        "sub1.authorized.example.com",
        "sub2.authorized.example.com",
        "api.authorized.example.com",
        "cdn.authorized.example.com",
    })
    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]

    real_getaddrinfo = socket.getaddrinfo

    def _patched_getaddrinfo(host, *args, **kwargs):
        normalized = str(host).lower().rstrip(".")
        if normalized in _TEST_HOSTS or normalized.endswith(".authorized.example.com"):
            return fake_results
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr("socket.getaddrinfo", _patched_getaddrinfo)


@pytest.fixture
def fast_scan_nodes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep graph integration tests fast and offline-friendly."""
    from agents.state import ScanState

    async def _instant_recon(state: ScanState) -> dict:
        target = state["target"]
        if not str(target).startswith("http"):
            target = f"https://{target}"
        return {
            "recon_results": {
                "target": target,
                "subdomains": [],
                "hosts": [target],
                "technologies": [],
                "endpoints": [],
                "urls": [target],
                "js_files": [],
                "pages": [],
                "tool_results": {},
                "errors": {},
                "partial_failure": False,
            }
        }

    async def _instant_passive(state: ScanState) -> dict:
        existing = list(state.get("findings", []))
        return {
            "findings": existing,
            "status": "detecting",
            "detection_metadata": {
                "passive_count": 0,
                "passive_deduplicated_count": 0,
                "passive_new_findings_count": 0,
                "errors": None,
                "passive_tools_run": True,
            },
        }

    async def _instant_active(state: ScanState) -> dict:
        prior_meta = dict(state.get("detection_metadata") or {})
        planned = list(state.get("planned_active_tests") or [])
        approved_tools = state.get("approved_tools")
        if approved_tools is None:
            approved_tools = planned if state.get("human_approved", False) else []
        rejected_tools = [t for t in planned if t not in set(approved_tools)]
        if not approved_tools:
            return {
                "status": "detecting",
                "detection_metadata": {
                    **prior_meta,
                    "active_count": 0,
                    "active_tools_run": False,
                    "approved_tools": [],
                    "rejected_tools": rejected_tools,
                },
            }
        return {
            "findings": list(state.get("findings", [])),
            "status": "detecting",
            "detection_metadata": {
                **prior_meta,
                "active_count": 0,
                "active_tools_run": True,
                "approved_tools": approved_tools,
                "rejected_tools": rejected_tools,
            },
        }

    monkeypatch.setattr("agents.orchestrator.run_recon_async", _instant_recon)
    monkeypatch.setattr("agents.orchestrator.run_passive_detection_async", _instant_passive)
    monkeypatch.setattr("agents.orchestrator.run_active_detection_async", _instant_active)


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    fake_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: fake_results)


@pytest.fixture
def fast_scan(public_dns: None, fast_scan_nodes: None) -> None:
    """Fast offline scan pipeline for API/orchestrator integration tests."""
    return None


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
