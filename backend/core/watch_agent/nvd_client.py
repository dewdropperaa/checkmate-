"""NVD CVE API client + CPE version-range matching for Watch Agent."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from core.config import get_settings

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_VERSION_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+)")


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    summary: str
    product: str
    version: str
    severity: str | None = None
    published: str | None = None


class NvdRateLimiter:
    """Pace NVD requests: 5/30s without key, 50/30s with key."""

    def __init__(self, *, has_api_key: bool) -> None:
        self._max = 50 if has_api_key else 5
        self._window = 30.0
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self._window]
                if len(self._timestamps) < self._max:
                    self._timestamps.append(now)
                    return
                sleep_for = self._window - (now - self._timestamps[0]) + 0.05
                await asyncio.sleep(max(sleep_for, 0.05))


def parse_version_tuple(version: str) -> tuple[Any, ...]:
    """Parse a version string into comparable tokens (ints preferred)."""
    if not version or version in {"*", "-", "unknown"}:
        return ()
    tokens: list[Any] = []
    for part in _VERSION_TOKEN_RE.findall(version.strip()):
        if part.isdigit():
            tokens.append(int(part))
        else:
            tokens.append(part.lower())
    return tuple(tokens)


def _cmp_versions(a: str, b: str) -> int:
    ta, tb = parse_version_tuple(a), parse_version_tuple(b)
    if not ta or not tb:
        return 0
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def version_in_range(
    version: str,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    exact: str | None = None,
) -> bool:
    """Return True when ``version`` falls inside an NVD CPE match range."""
    if not version or version in {"*", "-", "unknown"}:
        return False
    if exact and exact not in {"*", "-"}:
        return _cmp_versions(version, exact) == 0

    if start_including and _cmp_versions(version, start_including) < 0:
        return False
    if start_excluding and _cmp_versions(version, start_excluding) <= 0:
        return False
    if end_including and _cmp_versions(version, end_including) > 0:
        return False
    if end_excluding and _cmp_versions(version, end_excluding) >= 0:
        return False

    # If no bounds at all, do not claim a match (avoids keyword false positives).
    if not any([start_including, start_excluding, end_including, end_excluding, exact]):
        return False
    return True


def _cpe_product_token(criteria: str) -> str | None:
    # cpe:2.3:part:vendor:product:version:...
    parts = criteria.split(":")
    if len(parts) < 5:
        return None
    return parts[4].replace("_", " ").lower()


def cve_affects_version(
    cve: dict[str, Any],
    *,
    product_name: str,
    version: str,
) -> bool:
    """Inspect NVD configurations.cpeMatch ranges for the fingerprinted version."""
    product_l = product_name.lower().replace(" ", "_")
    product_space = product_name.lower()
    configurations = cve.get("configurations") or []
    for config in configurations:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                criteria = str(match.get("criteria") or "")
                token = _cpe_product_token(criteria)
                if token and token not in {product_l, product_space} and product_space not in token:
                    # Still allow if product name appears in criteria.
                    if product_l not in criteria.lower() and product_space not in criteria.lower():
                        continue
                exact = None
                cpe_parts = criteria.split(":")
                if len(cpe_parts) > 5 and cpe_parts[5] not in {"*", "-"}:
                    exact = cpe_parts[5]
                if version_in_range(
                    version,
                    start_including=match.get("versionStartIncluding"),
                    start_excluding=match.get("versionStartExcluding"),
                    end_including=match.get("versionEndIncluding"),
                    end_excluding=match.get("versionEndExcluding"),
                    exact=exact if not any(
                        [
                            match.get("versionStartIncluding"),
                            match.get("versionStartExcluding"),
                            match.get("versionEndIncluding"),
                            match.get("versionEndExcluding"),
                        ]
                    )
                    else None,
                ):
                    return True
    return False


def _english_summary(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            return str(desc.get("value") or "")[:500]
    descs = cve.get("descriptions") or []
    if descs:
        return str(descs[0].get("value") or "")[:500]
    return ""


def _cvss_severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        sev = data.get("baseSeverity") or entries[0].get("baseSeverity")
        if sev:
            return str(sev).lower()
    return None


class NvdClient:
    """Thin async client for NVD CVE API 2.0 with rate limiting."""

    def __init__(self, *, api_key: str | None = None) -> None:
        settings = get_settings()
        self.api_key = (api_key if api_key is not None else settings.nvd_api_key) or None
        self._limiter = NvdRateLimiter(has_api_key=bool(self.api_key))

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": "checkmate-watch-agent/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def search_cves_for_product(
        self,
        product_name: str,
        *,
        since: datetime | None = None,
        results_per_page: int = 50,
    ) -> list[dict[str, Any]]:
        """Keyword-search CVEs, optionally filtered by lastMod date window.

        NVD docs: keywordSearch matches description text; we then apply CPE
        version-range filtering client-side so we do not alert on every mention.
        """
        params: dict[str, Any] = {
            "keywordSearch": product_name,
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": 0,
        }
        if since is not None:
            end = datetime.now(timezone.utc)
            # NVD max date range is 120 days.
            start = max(since, end - timedelta(days=119))
            params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        await self._limiter.acquire()
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(
                NVD_CVE_URL,
                params=params,
                headers=self._headers(),
            )
            if response.status_code == 403:
                # Rate limited — back off hard then retry once.
                await asyncio.sleep(30.0)
                await self._limiter.acquire()
                response = await client.get(
                    NVD_CVE_URL,
                    params=params,
                    headers=self._headers(),
                )
            response.raise_for_status()
            payload = response.json()

        vulns = payload.get("vulnerabilities") or []
        return [item.get("cve") or {} for item in vulns if item.get("cve")]

    async def find_matching_cves(
        self,
        *,
        product_name: str,
        version: str,
        since: datetime | None = None,
    ) -> list[CveMatch]:
        records = await self.search_cves_for_product(product_name, since=since)
        matches: list[CveMatch] = []
        for cve in records:
            if not cve_affects_version(cve, product_name=product_name, version=version):
                continue
            matches.append(
                CveMatch(
                    cve_id=str(cve.get("id") or ""),
                    summary=_english_summary(cve),
                    product=product_name,
                    version=version,
                    severity=_cvss_severity(cve),
                    published=cve.get("published"),
                )
            )
        return [m for m in matches if m.cve_id]
