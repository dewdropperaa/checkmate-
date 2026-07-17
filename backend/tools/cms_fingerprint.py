"""Lightweight CMS / plugin fingerprinting for Watch Agent.

Detects common CMS products and versions from HTML meta tags, response
headers, and well-known paths. Output feeds the CVE-watch job.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from core.config import get_settings
from core.ssrf import SSRFError, create_safe_async_client, validate_url
from tools.base import ToolResult
from tools.schemas import Finding, Severity

logger = logging.getLogger(__name__)

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_GENERATOR_REV_RE = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+){0,3})")

# (product_key, display_name, detection helpers)
_PRODUCT_HINTS: list[tuple[str, str, list[str]]] = [
    ("wordpress", "WordPress", ["wp-content", "wp-includes", "wordpress"]),
    ("drupal", "Drupal", ["drupal", "sites/default"]),
    ("joomla", "Joomla", ["joomla", "/components/com_"]),
    ("magento", "Magento", ["magento", "mage/cookies"]),
    ("shopify", "Shopify", ["cdn.shopify.com", "shopify"]),
]


def _normalize_base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


def _parse_generator(content: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for match in list(_GENERATOR_RE.finditer(content)) + list(
        _GENERATOR_REV_RE.finditer(content)
    ):
        raw = match.group(1).strip()
        lower = raw.lower()
        version_match = _VERSION_RE.search(raw)
        version = version_match.group(1) if version_match else ""
        product = raw
        for key, display, _ in _PRODUCT_HINTS:
            if key in lower:
                product = display
                break
        hits.append({"name": product, "version": version, "source": "generator"})
    return hits


def _detect_from_body(body: str, headers: httpx.Headers) -> list[dict[str, str]]:
    products: dict[str, dict[str, str]] = {}
    for item in _parse_generator(body):
        products[item["name"].lower()] = item

    x_gen = headers.get("x-generator") or headers.get("x-powered-by") or ""
    if x_gen:
        version_match = _VERSION_RE.search(x_gen)
        version = version_match.group(1) if version_match else ""
        name = x_gen.split("/")[0].strip() or x_gen
        products.setdefault(
            name.lower(),
            {"name": name, "version": version, "source": "header"},
        )

    lower_body = body.lower()
    for key, display, needles in _PRODUCT_HINTS:
        if key in products or display.lower() in products:
            continue
        if any(n in lower_body for n in needles):
            products[key] = {
                "name": display,
                "version": "",
                "source": "body-hint",
            }

    return list(products.values())


class CmsFingerprint:
    """Fingerprint CMS / plugin name+version for CVE monitoring."""

    name = "cms-fingerprint"

    async def run(self, target: str, scope: dict[str, Any] | None = None) -> ToolResult:
        del scope
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
        products: list[dict[str, str]] = []

        try:
            async with create_safe_async_client(
                timeout=settings.header_check_timeout,
            ) as client:
                response = await client.get(base)
                products = _detect_from_body(response.text or "", response.headers)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=str(exc),
            )

        for product in products:
            label = product["name"]
            version = product.get("version") or "unknown"
            findings.append(
                Finding(
                    tool=self.name,
                    type="cms-detected",
                    url=base,
                    severity=Severity.INFO,
                    description=f"Detected {label} (version {version}).",
                    evidence=f"source={product.get('source')}",
                    raw_data=product,
                )
            )

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            data={
                "findings": [f.model_dump_for_state() for f in findings],
                "products": products,
            },
        )
