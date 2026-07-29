"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Secrets are read from the environment only."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "checkmate"
    app_env: str = Field(
        default="development",
        description=(
            "Runtime environment: development, staging, hosted, or production. "
            "'hosted' = cloud launch (Vercel + PaaS API) without live billing."
        ),
    )
    debug: bool = False
    log_level: str = "INFO"

    # Comma-separated list of authorized scan targets (domains or URLs).
    authorized_targets: str = Field(
        default="",
        description="Comma-separated allowlist of authorized scan targets",
    )

    openai_api_key: str | None = Field(default=None, repr=False)
    anthropic_api_key: str | None = Field(default=None, repr=False)

    # AI Security Copilot (ai_synthesis stage). Keys are optional — when none of
    # the configured providers have a key, the stage is skipped gracefully.
    gemini_api_key: str | None = Field(default=None, repr=False)
    groq_api_key: str | None = Field(default=None, repr=False)
    ai_llm_providers: str = Field(
        default="gemini,groq",
        description=(
            "Comma-separated ordered LLM provider list for ai_synthesis. "
            "Known providers: gemini, groq, openai, anthropic."
        ),
    )
    ai_synthesis_timeout_seconds: float = Field(
        default=15.0,
        description="Per-provider timeout in seconds for ai_synthesis LLM calls",
    )
    ai_synthesis_max_llm_calls: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Hard cap on LLM calls per scan (summary+roadmap + grader)",
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        description="Gemini model id used by the primary ai_synthesis provider",
    )
    groq_model: str = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model id used by the fallback ai_synthesis provider",
    )
    openai_model: str = Field(
        default="gpt-4o-mini",
        description="OpenAI model id when openai is listed in ai_llm_providers",
    )
    anthropic_model: str = Field(
        default="claude-3-5-haiku-latest",
        description="Anthropic model id when anthropic is listed in ai_llm_providers",
    )

    # Tool execution settings
    tools_binary_dir: str = Field(
        default="/opt/tools",
        description="Directory where security tool binaries are installed",
    )
    tool_timeout: float = Field(
        default=120.0,
        description="Default timeout in seconds for tool execution",
    )

    # Katana crawler limits
    katana_max_depth: int = Field(
        default=3,
        description="Maximum crawl depth for Katana",
    )
    katana_max_pages: int = Field(
        default=100,
        description="Maximum number of pages to crawl with Katana",
    )
    katana_rate_limit: int = Field(
        default=50,
        description="Rate limit for Katana requests per second",
    )

    # Firecrawl recon settings (managed web crawling / URL discovery API).
    # Complements Katana: map pulls sitemap + SERP + previously-crawled URLs
    # so recon does not miss endpoints; scrape yields verified live content
    # that downstream detection uses to reduce false positives.
    firecrawl_api_key: str | None = Field(default=None, repr=False)
    firecrawl_enabled: bool = Field(
        default=True,
        description="Enable Firecrawl-powered URL discovery in recon",
    )
    firecrawl_api_url: str | None = Field(
        default=None,
        description="Override Firecrawl API base URL (self-hosted or proxy)",
    )
    firecrawl_map_limit: int = Field(
        default=500,
        description="Maximum URLs to request from Firecrawl map",
    )
    firecrawl_include_subdomains: bool = Field(
        default=True,
        description="Include subdomains when mapping a site with Firecrawl",
    )
    firecrawl_sitemap: str = Field(
        default="include",
        description="Firecrawl sitemap handling: 'include', 'skip', or 'only'",
    )
    firecrawl_scrape_root: bool = Field(
        default=True,
        description="Scrape the root URL to extract extra links/JS and content",
    )
    firecrawl_timeout: float = Field(
        default=120.0,
        description="Timeout in seconds for Firecrawl recon operations",
    )
    # Finding verification: corroborate content-based findings against scraped
    # page content to reduce false positives.
    firecrawl_verify_findings: bool = Field(
        default=True,
        description="Corroborate content-based findings against scraped content",
    )
    firecrawl_verify_max_urls: int = Field(
        default=15,
        description="Max distinct finding URLs to scrape on-demand for verification",
    )
    firecrawl_verify_timeout: float = Field(
        default=60.0,
        description="Timeout in seconds for a single verification scrape",
    )

    # Subfinder settings
    subfinder_timeout: float = Field(
        default=120.0,
        description="Timeout for subfinder execution",
    )

    # HTTPx settings
    httpx_timeout: float = Field(
        default=120.0,
        description="Timeout for httpx execution",
    )
    httpx_rate_limit: int = Field(
        default=50,
        description="Rate limit for httpx requests per second",
    )

    # Nuclei settings
    nuclei_rate_limit: int = Field(
        default=50,
        description="Rate limit for nuclei requests per second",
    )
    nuclei_concurrency: int = Field(
        default=10,
        description="Maximum concurrent nuclei template executions",
    )
    nuclei_timeout: float = Field(
        default=300.0,
        description="Timeout for nuclei execution",
    )

    # testssl.sh settings
    testssl_timeout: float = Field(
        default=300.0,
        description="Timeout for testssl.sh execution",
    )

    # retire.js settings
    retirejs_timeout: float = Field(
        default=180.0,
        description="Timeout for retire.js execution",
    )

    # Header checks settings
    header_check_timeout: float = Field(
        default=30.0,
        description="Timeout for HTTP header check requests",
    )
    header_check_rate_limit_delay: float = Field(
        default=0.5,
        description="Delay between header check requests (seconds)",
    )

    # Active finding verification: re-fetch each finding's URL and corroborate
    # it against the live HTTP response (headers + body) so every finding gets a
    # deterministic confirmed/refuted verdict instead of a Firecrawl-dependent
    # "unverified"/"unconfirmed" guess.
    verification_enabled: bool = Field(
        default=True,
        description="Actively re-check each finding against the live response",
    )
    verification_timeout: float = Field(
        default=15.0,
        description="Timeout in seconds for a single verification HTTP request",
    )
    verification_max_concurrency: int = Field(
        default=8,
        description="Maximum concurrent verification HTTP requests",
    )
    verification_max_urls: int = Field(
        default=200,
        description="Maximum distinct finding URLs to re-fetch during verification",
    )
    verification_max_body_bytes: int = Field(
        default=2_000_000,
        description="Maximum response body bytes to inspect during verification",
    )
    verify_fix_cooldown_seconds: int = Field(
        default=180,
        ge=30,
        le=3600,
        description=(
            "Minimum seconds between Verify Fix re-checks for the same finding "
            "(prevents using Verify Fix as an unthrottled scanning primitive)"
        ),
    )

    # OWASP ZAP settings
    zap_api_url: str = Field(
        default="http://zap:8080",
        description=(
            "ZAP REST API URL. Prefer the Compose service name "
            "(http://zap:8080) on the private Docker network. ZAP has no "
            "built-in TLS — do not point this at a public hostname over plain HTTP."
        ),
    )
    zap_api_key: str = Field(
        default="",
        description="ZAP API key for authentication (required in production)",
    )
    zap_timeout: float = Field(
        default=600.0,
        description="Timeout for ZAP scan completion",
    )
    zap_poll_interval: float = Field(
        default=5.0,
        description="Interval for polling ZAP scan status",
    )
    zap_max_concurrent: int = Field(
        default=1,
        ge=1,
        le=4,
        description=(
            "Maximum concurrent ZAP active scans against the shared daemon. "
            "Keep at 1 unless the host has substantial RAM headroom — ZAP is "
            "stateful and memory-heavy; parallel scans risk OOM and session races."
        ),
    )

    # Envelope encryption master key for site auth credentials (Fernet).
    # Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    credentials_master_key: str | None = Field(
        default=None,
        repr=False,
        description="Fernet master key for envelope-encrypting site credentials",
    )

    # Destructive-action form keyword blocklist (comma-separated override).
    destructive_form_keywords: str = Field(
        default="",
        description=(
            "Optional comma-separated override for destructive form keywords. "
            "Empty = use built-in defaults from core.destructive_actions."
        ),
    )

    # SQLMap settings
    sqlmap_timeout: float = Field(
        default=300.0,
        description="Timeout for SQLMap execution",
    )
    sqlmap_max_level: int = Field(
        default=2,
        description="Maximum SQLMap testing level (1-5, capped for safety)",
    )
    sqlmap_max_risk: int = Field(
        default=2,
        description="Maximum SQLMap risk level (1-3, capped for safety)",
    )

    # Scan API rate limiting / concurrency controls
    scan_rate_limit_window_seconds: int = Field(
        default=60,
        description="Sliding window in seconds for /scan rate limiting",
    )
    scan_rate_limit_max_requests: int = Field(
        default=10,
        description="Maximum /scan requests per client in each window",
    )
    scan_rate_limit_max_concurrent_per_client: int = Field(
        default=1,
        description=(
            "Maximum concurrently running scans per client identity. "
            "Keep low while active scans share a single ZAP daemon."
        ),
    )
    scan_rate_limit_max_concurrent_global: int = Field(
        default=3,
        description=(
            "Maximum concurrently running scans across all clients. "
            "Conservative default — ZAP memory scales poorly with parallel active scans."
        ),
    )
    auth_rate_limit_window_seconds: int = Field(
        default=60,
        description="Sliding window in seconds for auth/session endpoints",
    )
    auth_rate_limit_max_requests_per_ip: int = Field(
        default=20,
        description="Maximum auth/session requests per client IP in each window",
    )
    auth_rate_limit_max_requests_per_account: int = Field(
        default=10,
        description="Maximum auth/session requests per Firebase account in each window",
    )
    scan_timeout_seconds: float = Field(
        default=1800.0,
        description="Maximum wall-clock seconds for a scan before it is marked failed",
    )
    report_max_findings: int = Field(
        default=500,
        description="Maximum findings rendered in report artifacts (truncation cap)",
    )

    # Firebase Admin (server-side only — never NEXT_PUBLIC_ / never commit JSON keys)
    firebase_project_id: str | None = Field(
        default=None,
        description="Firebase project ID used to verify ID tokens",
    )
    firebase_credentials_path: str | None = Field(
        default=None,
        repr=False,
        description="Path to Firebase service-account JSON (server secret)",
    )
    firebase_credentials_json: str | None = Field(
        default=None,
        repr=False,
        description="Inline Firebase service-account JSON string (server secret)",
    )
    # When true, /scan and scan sub-routes require a verified Firebase ID token.
    # Leave false so the Chrome extension can keep using X-API-Key during migration.
    require_firebase_auth: bool = Field(
        default=False,
        description="Require Firebase ID tokens on protected scan routes",
    )

    # Watch Agent — Resend email (free tier) + optional NVD API key for higher rate limits.
    resend_api_key: str | None = Field(default=None, repr=False)
    resend_from_email: str = Field(
        default="Checkmate <onboarding@resend.dev>",
        description="Verified Resend from address (use onboarding@resend.dev for sandbox)",
    )
    nvd_api_key: str | None = Field(
        default=None,
        repr=False,
        description=(
            "Optional NVD API key. Without a key: 5 req/30s; with a key: 50 req/30s."
        ),
    )
    public_app_url: str = Field(
        default="http://localhost:3000",
        description="Public web app base URL used in Watch Agent email links",
    )
    dodo_webhook_secret: str | None = Field(
        default=None,
        repr=False,
        description="Shared secret for Dodo Payments plan-change webhooks",
    )
    dodo_environment: str = Field(
        default="test",
        description=(
            "Dodo Payments mode: test (sandbox) or live (production billing). "
            "Must match the DODO_API_KEY prefix (dodo_test_ / dodo_live_)."
        ),
    )
    dodo_api_key: str | None = Field(
        default=None,
        repr=False,
        description="Dodo Payments API key (dodo_test_* or dodo_live_*)",
    )
    dodo_api_url: str = Field(
        default="https://api.dodopayments.com",
        description="Dodo Payments API base URL used by health probes",
    )
    upstream_health_timeout_seconds: float = Field(
        default=3.0,
        description="Timeout for lightweight upstream dependency health checks",
    )
    production_firebase_project_id: str | None = Field(
        default=None,
        description=(
            "Production Firebase project ID. Dev/staging must not point at this "
            "project — set in deploy configs to enforce isolation."
        ),
    )
    watch_scheduler_enabled: bool = Field(
        default=True,
        description="Start the APScheduler Watch Agent on API startup",
    )
    cloud_scanning_enabled: bool = Field(
        default=False,
        description=(
            "When false, POST /scan returns 503 on cloud hosts without ZAP/toolchain. "
            "Use true on paid Docker stacks (render.starter.yaml)."
        ),
    )

    # Comma-separated founder/creator emails — always receive agency-tier access.
    creator_emails: str = Field(
        default="",
        description=(
            "Comma-separated emails that receive agency plan limits and features "
            "(unlimited targets/scans, authenticated scanning, white-label reports)"
        ),
    )

    # Tool reliability
    require_toolchain_at_startup: bool = Field(
        default=True,
        description=(
            "When true, the API refuses to start (and rejects scans) unless every "
            "required security tool binary and ZAP are available."
        ),
    )
    tool_retry_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Number of attempts for each tool run before marking it failed",
    )
    tool_retry_backoff_seconds: float = Field(
        default=2.0,
        ge=0.5,
        le=30.0,
        description="Initial backoff between tool retries (doubles each attempt)",
    )

    @field_validator("app_env")
    @classmethod
    def _normalize_app_env(cls, value: str) -> str:
        normalized = (value or "development").strip().lower()
        allowed = {"development", "staging", "hosted", "production", "test"}
        if normalized not in allowed:
            raise ValueError(
                f"app_env must be one of {sorted(allowed)}, got '{value}'"
            )
        return normalized

    @field_validator("dodo_environment")
    @classmethod
    def _normalize_dodo_environment(cls, value: str) -> str:
        normalized = (value or "test").strip().lower().replace("-", "_")
        aliases = {
            "test": "test",
            "test_mode": "test",
            "sandbox": "test",
            "live": "live",
            "live_mode": "live",
            "production": "live",
        }
        if normalized not in aliases:
            raise ValueError(
                "dodo_environment must be 'test' or 'live' "
                f"(aliases: test_mode, live_mode), got '{value}'"
            )
        return aliases[normalized]

    @property
    def authorized_target_list(self) -> list[str]:
        if not self.authorized_targets.strip():
            return []
        return [t.strip() for t in self.authorized_targets.split(",") if t.strip()]

    @property
    def creator_email_list(self) -> list[str]:
        if not self.creator_emails.strip():
            return []
        return [
            e.strip().lower()
            for e in self.creator_emails.split(",")
            if e.strip()
        ]

    @property
    def ai_llm_provider_list(self) -> list[str]:
        """Ordered provider ids for ai_synthesis (empty entries stripped)."""
        if not self.ai_llm_providers.strip():
            return []
        return [
            p.strip().lower()
            for p in self.ai_llm_providers.split(",")
            if p.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()


def _dodo_key_mode(api_key: str | None) -> str | None:
    if not api_key:
        return None
    if api_key.startswith("dodo_live_"):
        return "live"
    if api_key.startswith("dodo_test_"):
        return "test"
    return None


def validate_startup_settings(settings: Settings | None = None) -> None:
    """Fail fast when runtime settings are missing or environment-inconsistent.

    Raises ValueError with a clear message so the process exits at startup
    rather than failing confusingly on the first paid API call.
    """
    settings = settings or get_settings()
    errors: list[str] = []

    if settings.app_env == "production":
        if settings.debug:
            errors.append(
                "DEBUG=true is not allowed when APP_ENV=production "
                "(refusing to run production with dev diagnostics enabled)"
            )
        if settings.dodo_environment != "live":
            errors.append(
                "DODO_ENVIRONMENT=live is required when APP_ENV=production "
                f"(got {settings.dodo_environment!r})"
            )
        if not settings.dodo_api_key:
            errors.append(
                "DODO_API_KEY (live Dodo Payments key — dodo_live_*)"
            )
        elif _dodo_key_mode(settings.dodo_api_key) != "live":
            errors.append(
                "DODO_API_KEY must be a live key (dodo_live_*) when "
                "APP_ENV=production"
            )
        if settings.firecrawl_enabled and not settings.firecrawl_api_key:
            errors.append(
                "FIRECRAWL_API_KEY (required when FIRECRAWL_ENABLED=true)"
            )
        if not settings.zap_api_key:
            errors.append("ZAP_API_KEY")
        if not settings.firebase_project_id:
            errors.append("FIREBASE_PROJECT_ID")
        if not (
            settings.firebase_credentials_json
            or settings.firebase_credentials_path
        ):
            errors.append(
                "FIREBASE_CREDENTIALS_JSON or FIREBASE_CREDENTIALS_PATH "
                "(Firebase Admin service account — never a client web API key)"
            )
        if not settings.require_firebase_auth:
            errors.append(
                "REQUIRE_FIREBASE_AUTH=true "
                "(scan routes must not accept anonymous/legacy-only traffic in production)"
            )
        if not settings.dodo_webhook_secret:
            errors.append(
                "DODO_WEBHOOK_SECRET "
                "(unsigned billing webhooks must not be accepted in production)"
            )
        if not settings.credentials_master_key:
            errors.append(
                "CREDENTIALS_MASTER_KEY "
                "(required to encrypt authenticated-scan credentials at rest)"
            )
        if (
            settings.production_firebase_project_id
            and settings.firebase_project_id
            and settings.firebase_project_id
            != settings.production_firebase_project_id
        ):
            errors.append(
                "FIREBASE_PROJECT_ID must match PRODUCTION_FIREBASE_PROJECT_ID "
                "when APP_ENV=production"
            )

    elif settings.app_env == "staging":
        if settings.debug:
            errors.append(
                "DEBUG=true is not allowed when APP_ENV=staging"
            )
        if settings.dodo_environment != "test":
            errors.append(
                "DODO_ENVIRONMENT=test is required when APP_ENV=staging "
                f"(got {settings.dodo_environment!r})"
            )
        if settings.dodo_api_key and _dodo_key_mode(settings.dodo_api_key) != "test":
            errors.append(
                "DODO_API_KEY must be a test key (dodo_test_*) when APP_ENV=staging"
            )
        if not settings.dodo_webhook_secret:
            errors.append("DODO_WEBHOOK_SECRET")
        if not settings.credentials_master_key:
            errors.append("CREDENTIALS_MASTER_KEY")

    elif settings.app_env == "hosted":
        # Cloud API behind HTTPS (Render/Fly) with Vercel web — no local Docker.
        if settings.debug:
            errors.append(
                "DEBUG=true is not allowed when APP_ENV=hosted "
                "(refusing to run public API with dev diagnostics enabled)"
            )
        if not settings.firebase_project_id:
            errors.append("FIREBASE_PROJECT_ID")
        if not (
            settings.firebase_credentials_json
            or settings.firebase_credentials_path
        ):
            errors.append(
                "FIREBASE_CREDENTIALS_JSON or FIREBASE_CREDENTIALS_PATH "
                "(Firebase Admin service account — never a client web API key)"
            )
        if not settings.require_firebase_auth:
            errors.append(
                "REQUIRE_FIREBASE_AUTH=true "
                "(public /scan routes must require verified Firebase tokens)"
            )
        if not settings.credentials_master_key:
            errors.append(
                "CREDENTIALS_MASTER_KEY "
                "(required to encrypt authenticated-scan credentials at rest)"
            )
        if settings.firecrawl_enabled and not settings.firecrawl_api_key:
            errors.append(
                "FIRECRAWL_API_KEY (required when FIRECRAWL_ENABLED=true) "
                "or set FIRECRAWL_ENABLED=false"
            )
        if settings.cloud_scanning_enabled and not settings.zap_api_key:
            errors.append(
                "ZAP_API_KEY (required when CLOUD_SCANNING_ENABLED=true — "
                "see render.starter.yaml)"
            )
        if settings.dodo_api_key and _dodo_key_mode(settings.dodo_api_key) == "live":
            errors.append(
                "DODO_API_KEY must not be a live key when APP_ENV=hosted "
                "(use APP_ENV=production after billing go-live)"
            )

    # Non-production environments must never reach live billing.
    if settings.app_env in {"development", "test", "staging", "hosted"}:
        if settings.dodo_environment == "live":
            errors.append(
                f"DODO_ENVIRONMENT=live is not allowed when APP_ENV={settings.app_env}"
            )
        key_mode = _dodo_key_mode(settings.dodo_api_key)
        if key_mode == "live":
            errors.append(
                "DODO_API_KEY is a live key (dodo_live_*) — use a test key "
                f"when APP_ENV={settings.app_env}"
            )

    # Dev/staging must not share the production Firebase project.
    if settings.app_env in {"development", "test", "staging"}:
        if (
            settings.production_firebase_project_id
            and settings.firebase_project_id
            and settings.firebase_project_id
            == settings.production_firebase_project_id
        ):
            errors.append(
                "FIREBASE_PROJECT_ID matches PRODUCTION_FIREBASE_PROJECT_ID — "
                f"dev/staging must use a separate Firebase project (APP_ENV={settings.app_env})"
            )

    # DODO_ENVIRONMENT must agree with the API key prefix when a key is set.
    if settings.dodo_api_key:
        key_mode = _dodo_key_mode(settings.dodo_api_key)
        if key_mode is None:
            errors.append(
                "DODO_API_KEY must start with dodo_test_ or dodo_live_"
            )
        elif key_mode != settings.dodo_environment:
            errors.append(
                f"DODO_ENVIRONMENT={settings.dodo_environment!r} does not match "
                f"DODO_API_KEY mode ({key_mode!r})"
            )

    if errors:
        label = (
            "Production startup validation failed"
            if settings.app_env == "production"
            else f"Startup validation failed for APP_ENV={settings.app_env}"
        )
        raise ValueError(f"{label}. Issues: " + "; ".join(errors))
