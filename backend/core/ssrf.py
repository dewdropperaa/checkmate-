"""SSRF protections for outbound HTTP requests and scan targets.

Blocks private, loopback, link-local, and cloud-metadata destinations before
any server-side fetch. Re-validates on every redirect hop to mitigate DNS
rebinding and redirect-based SSRF bypasses.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

# RFC 1123-ish hostname: labels 1-63 chars, total <= 253, no leading/trailing dots.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$"
)

# Known cloud metadata endpoints (literal IPs and common hostnames).
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
})

# Well-known metadata IP — also caught by link-local range check.
_METADATA_IP = ipaddress.ip_address("169.254.169.254")

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_REQUEST_TIMEOUT = 30.0
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB


class SSRFError(ValueError):
    """Raised when a URL or resolved address is not safe to fetch."""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP must not be reached by outbound scan traffic."""
    if ip == _METADATA_IP:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_hostname(hostname: str) -> str:
    """Validate and normalize a scan target hostname.

    Raises SSRFError for malformed hostnames.
    """
    host = hostname.strip().lower().rstrip(".")
    if not host:
        raise SSRFError("Hostname is required")

    if host in _BLOCKED_HOSTNAMES:
        raise SSRFError(f"Hostname '{host}' is not allowed")

    # Strip bracket notation for IPv6 literals before IP parsing.
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host

    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_blocked_ip(ip):
            raise SSRFError(f"IP address '{bare}' resolves to a blocked range")
        return bare

    if len(host) > 253 or not _HOSTNAME_RE.match(host):
        raise SSRFError(f"Malformed hostname: '{hostname}'")

    return host


def resolve_and_validate_host(hostname: str) -> None:
    """Resolve hostname via DNS and reject if any A/AAAA record is blocked."""
    host = validate_hostname(hostname)

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_blocked_ip(ip):
            raise SSRFError(f"IP address '{host}' is in a blocked range")
        return

    try:
        addr_infos = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve hostname '{host}': {exc}") from exc

    if not addr_infos:
        raise SSRFError(f"Could not resolve hostname '{host}'")

    seen: set[str] = set()
    for family, _type, _proto, _canonname, sockaddr in addr_infos:
        if family == socket.AF_INET:
            ip_str = sockaddr[0]
        elif family == socket.AF_INET6:
            ip_str = sockaddr[0]
        else:
            continue
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            resolved = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(resolved):
            raise SSRFError(
                f"Hostname '{host}' resolves to blocked address '{ip_str}'"
            )


def validate_url(url: str, *, resolve_dns: bool = True) -> str:
    """Validate a URL before any outbound fetch or scan.

    Returns the normalized URL string. Raises SSRFError on unsafe input.
    """
    raw = url.strip()
    if not raw:
        raise SSRFError("URL is required")

    if "://" not in raw:
        raw = f"https://{raw}"

    parsed = urlparse(raw)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"URL scheme '{scheme or '(none)'}' is not allowed; "
            "only http and https are permitted"
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError(f"Could not parse hostname from URL: {url}")

    validate_hostname(hostname)
    if resolve_dns:
        resolve_and_validate_host(hostname)

    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise SSRFError(f"Invalid port: {port}")

    # Reconstruct a canonical form without credentials.
    netloc = hostname
    if port is not None and port not in (80, 443):
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]:{port}"
        else:
            netloc = f"{hostname}:{port}"

    return f"{scheme}://{netloc}{parsed.path or ''}{parsed.query and '?' + parsed.query or ''}"


class SSRFValidationTransport(httpx.AsyncBaseTransport):
    """httpx transport that re-validates every redirect destination."""

    def __init__(
        self,
        *,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        verify: bool = True,
    ) -> None:
        self._max_redirects = max_redirects
        self._max_response_bytes = max_response_bytes
        self._inner = httpx.AsyncHTTPTransport(verify=verify)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        validate_url(url, resolve_dns=True)

        response = await self._inner.handle_async_request(request)

        redirect_count = 0
        while response.is_redirect:
            redirect_count += 1
            if redirect_count > self._max_redirects:
                await response.aclose()
                raise SSRFError(
                    f"Redirect limit exceeded ({self._max_redirects} hops)"
                )

            location = response.headers.get("location")
            if not location:
                break

            next_url = httpx.URL(str(request.url)).join(location)
            validate_url(str(next_url), resolve_dns=True)

            await response.aclose()
            request = httpx.Request(
                method=request.method,
                url=next_url,
                headers=request.headers,
            )
            response = await self._inner.handle_async_request(request)

        # Read the raw wire bytes (not auto-decompressed) so we never fail on
        # mismatched Content-Encoding headers when reconstructing the response.
        body = b""
        async for chunk in response.aiter_raw():
            body += chunk
            if len(body) > self._max_response_bytes:
                await response.aclose()
                raise SSRFError(
                    f"Response exceeds maximum size ({self._max_response_bytes} bytes)"
                )

        headers = httpx.Headers(response.headers)
        headers.pop("content-encoding", None)
        headers.pop("transfer-encoding", None)
        headers["content-length"] = str(len(body))

        return httpx.Response(
            status_code=response.status_code,
            headers=headers,
            content=body,
            request=request,
        )


def create_safe_async_client(
    *,
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    verify: bool = True,
) -> httpx.AsyncClient:
    """Build an httpx AsyncClient with SSRF-safe redirect handling."""
    transport = SSRFValidationTransport(
        max_redirects=max_redirects,
        max_response_bytes=max_response_bytes,
        verify=verify,
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
    )


def normalize_scan_target(target: str, *, resolve_dns: bool = True) -> str:
    """Validate and normalize user input to a canonical https://hostname/ URL.

    Strips paths, query strings, and fragments so downstream modules receive
    one consistent origin regardless of how the user pasted the target.
    """
    validated = validate_url(target, resolve_dns=resolve_dns)
    parsed = urlparse(validated)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError(f"Could not parse hostname from URL: {target}")

    port = parsed.port
    if port is not None and port not in (80, 443):
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]:{port}"
        else:
            netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    return f"https://{netloc}/"


def validate_scan_target(target: str) -> str:
    """Validate a user-supplied scan target at API ingress."""
    return normalize_scan_target(target, resolve_dns=True)
