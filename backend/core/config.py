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
        description="Runtime environment: development, staging, or production",
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

    # OWASP ZAP settings
    zap_api_url: str = Field(
        default="http://zap:8080",
        description="ZAP REST API URL",
    )
    zap_api_key: str = Field(
        default="",
        description="ZAP API key for authentication",
    )
    zap_timeout: float = Field(
        default=600.0,
        description="Timeout for ZAP scan completion",
    )
    zap_poll_interval: float = Field(
        default=5.0,
        description="Interval for polling ZAP scan status",
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
        default=2,
        description="Maximum concurrently running scans per client identity",
    )
    scan_rate_limit_max_concurrent_global: int = Field(
        default=20,
        description="Maximum concurrently running scans across all clients",
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
    watch_scheduler_enabled: bool = Field(
        default=True,
        description="Start the APScheduler Watch Agent on API startup",
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
        allowed = {"development", "staging", "production", "test"}
        if normalized not in allowed:
            raise ValueError(
                f"app_env must be one of {sorted(allowed)}, got '{value}'"
            )
        return normalized

    @property
    def authorized_target_list(self) -> list[str]:
        if not self.authorized_targets.strip():
            return []
        return [t.strip() for t in self.authorized_targets.split(",") if t.strip()]

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


def validate_startup_settings(settings: Settings | None = None) -> None:
    """Fail fast when production is misconfigured.

    Raises ValueError with a clear message so the process exits at startup
    rather than failing confusingly on the first paid API call.
    """
    settings = settings or get_settings()
    if settings.app_env != "production":
        return

    missing: list[str] = []
    if settings.firecrawl_enabled and not settings.firecrawl_api_key:
        missing.append("FIRECRAWL_API_KEY (required when FIRECRAWL_ENABLED=true)")
    if not settings.zap_api_key:
        missing.append("ZAP_API_KEY")

    if not settings.firebase_project_id:
        missing.append("FIREBASE_PROJECT_ID")
    if not (
        settings.firebase_credentials_json
        or settings.firebase_credentials_path
    ):
        missing.append(
            "FIREBASE_CREDENTIALS_JSON or FIREBASE_CREDENTIALS_PATH "
            "(Firebase Admin service account — never a client web API key)"
        )

    if missing:
        raise ValueError(
            "Production startup validation failed. Missing required settings: "
            + "; ".join(missing)
        )
