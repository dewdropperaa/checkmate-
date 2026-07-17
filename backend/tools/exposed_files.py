"""Lightweight exposed-file checks for Watch Agent (passive, no quota).

Probes a small set of well-known sensitive paths. Pure httpx — no Nuclei
binary required so scheduled jobs stay reliable on free-tier hosts.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from core.config import get_settings
from core.retries import run_with_retries
from core.ssrf import SSRFError, create_safe_async_client, validate_url
from tools.base import ToolResult
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

# Paths that should never be publicly reachable. Status 200 with non-empty
# body is treated as a finding; redirects/404/403 are ignored.
EXPOSED_PATHS: list[tuple[str, str, Severity]] = [
    ("/.env", "exposed-env-file", Severity.HIGH),
    ("/.git/config", "exposed-git-config", Severity.HIGH),
    ("/.git/HEAD", "exposed-git-head", Severity.HIGH),
    ("/wp-config.php.bak", "exposed-wp-config-backup", Severity.CRITICAL),
    ("/wp-config.php~", "exposed-wp-config-backup", Severity.CRITICAL),
    ("/config.php.bak", "exposed-config-backup", Severity.HIGH),
    ("/backup.zip", "exposed-backup-archive", Severity.HIGH),
    ("/backup.sql", "exposed-backup-sql", Severity.CRITICAL),
    ("/dump.sql", "exposed-backup-sql", Severity.CRITICAL),
    ("/phpinfo.php", "exposed-phpinfo", Severity.MEDIUM),
    ("/server-status", "exposed-server-status", Severity.MEDIUM),
    ("/.DS_Store", "exposed-ds-store", Severity.LOW),
    ("/web.config", "exposed-web-config", Severity.MEDIUM),
    ("/composer.json", "exposed-composer-json", Severity.LOW),
    ("/package.json", "exposed-package-json", Severity.LOW),
]


def _normalize_base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


class ExposedFilesChecker:
    """Probe common sensitive paths on a single origin."""

    name = "exposed-files"

    async def run(self, target: str, scope: dict[str, Any] | None = None) -> ToolResult:
        del scope  # Watch Agent jobs already enforce org ownership / allowlist.
        settings = get_settings()
        try:
            base = _normalize_base(target)
            validate_url(base)
        except SSRFError as exc:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=str(exc),
            )

        findings: list[Finding] = []
        errors: list[str] = []

        async with create_safe_async_client(
            timeout=settings.header_check_timeout,
        ) as client:
            for path, finding_type, severity in EXPOSED_PATHS:
                url = urljoin(base + "/", path.lstrip("/"))
                try:
                    response = await run_with_retries(
                        self.name,
                        lambda u=url: client.get(u),
                        max_attempts=2,
                        backoff_seconds=0.5,
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{path}: {exc}")
                    continue

                if response.status_code != 200:
                    continue
                body = response.text or ""
                if len(body.strip()) < 8:
                    continue
                # Soft filter: HTML soft-404 pages often return 200.
                lower = body[:2000].lower()
                if "not found" in lower and len(body) < 800:
                    continue

                findings.append(
                    Finding(
                        tool=self.name,
                        type=finding_type,
                        url=url,
                        severity=severity,
                        description=(
                            f"Potentially sensitive file is publicly reachable at {path}."
                        ),
                        evidence=f"HTTP {response.status_code}; body_bytes={len(body)}",
                        cwe_id=538,
                        raw_data={"path": path, "status_code": response.status_code},
                    )
                )
                await asyncio.sleep(settings.header_check_rate_limit_delay)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            data={
                "findings": [f.model_dump_for_state() for f in findings],
                "errors": errors,
            },
        )
