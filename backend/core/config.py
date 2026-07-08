"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Secrets are read from the environment only."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "sentinel-scan"
    debug: bool = False
    log_level: str = "INFO"

    # Comma-separated list of authorized scan targets (domains or URLs).
    authorized_targets: str = Field(
        default="",
        description="Comma-separated allowlist of authorized scan targets",
    )

    openai_api_key: str | None = Field(default=None, repr=False)
    anthropic_api_key: str | None = Field(default=None, repr=False)

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

    @property
    def authorized_target_list(self) -> list[str]:
        if not self.authorized_targets.strip():
            return []
        return [t.strip() for t in self.authorized_targets.split(",") if t.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
