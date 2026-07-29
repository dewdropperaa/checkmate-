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


def _parse_alternate_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Detect decimal, hex, octal, and shorthand IPv4 literals that bypass ip_address()."""
    bare = host.strip().lower()
    if bare.startswith("[") and bare.endswith("]"):
        bare = bare[1:-1]

    try:
        return ipaddress.ip_address(bare)
    except ValueError:
        pass

    if bare.isdigit():
        value = int(bare)
        if 0 <= value <= 0xFFFFFFFF:
            try:
                return ipaddress.IPv4Address(value)
            except ValueError:
                return None

    if bare.startswith("0x"):
        try:
            value = int(bare, 16)
            if 0 <= value <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(value)
        except ValueError:
            return None

    if "." not in bare:
        return None

    # Dotted forms: octal segments (0177.0.0.1), hex segments, or shorthand (127.1).
    if not re.fullmatch(r"[0-9a-fx.]+", bare):
        return None

    parts = bare.split(".")
    if not (1 <= len(parts) <= 4):
        return None

    octets: list[int] = []
    for part in parts:
        if not part:
            return None
        if part.startswith("0x"):
            octets.append(int(part, 16))
        elif (
            len(part) > 1
            and part.startswith("0")
            and all(ch in "01234567" for ch in part[1:])
        ):
            octets.append(int(part, 8))
        else:
            octets.append(int(part))

    if len(octets) == 1:
        octets = [0, 0, 0, octets[0]]
    elif len(octets) == 2:
        octets = [octets[0], 0, 0, octets[1]]
    elif len(octets) == 3:
        octets = [octets[0], octets[1], 0, octets[2]]
    elif len(octets) != 4:
        return None

    if not all(0 <= octet <= 255 for octet in octets):
        return None
    try:
        return ipaddress.IPv4Address(".".join(str(octet) for octet in octets))
    except ValueError:
        return None


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

    ip = _parse_alternate_ip_literal(bare)
    if ip is not None:
        if _is_blocked_ip(ip):
            raise SSRFError(f"IP address '{bare}' resolves to a blocked range")
        return str(ip)

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


def resolve_and_validate_host(hostname: str) -> str:
    """Resolve hostname via DNS, reject blocked records, and return a safe IP."""
    host = validate_hostname(hostname)

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_blocked_ip(ip):
            raise SSRFError(f"IP address '{host}' is in a blocked range")
        return host

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
    first_safe: str | None = None
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
        if first_safe is None:
            first_safe = ip_str
    if first_safe is None:
        raise SSRFError(f"Could not resolve hostname '{host}' to an IP address")
    return first_safe


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


def validate_login_url_for_site(
    login_url: str,
    site_target: str,
    *,
    resolve_dns: bool = True,
) -> str:
    """Validate an authenticated-scan login URL against SSRF rules and site origin.

    The login page must share the same registrable hostname as the authorized
    site target (or be an exact host match). Cross-origin / private / metadata
    destinations are rejected so credentials cannot be posted off-site.
    """
    normalized_login = validate_url(login_url, resolve_dns=resolve_dns)
    login_host = (urlparse(normalized_login).hostname or "").lower().rstrip(".")
    if not login_host:
        raise SSRFError("Login URL hostname is required")

    site_normalized = site_target.strip()
    if "://" not in site_normalized:
        site_normalized = f"https://{site_normalized}"
    site_host = (urlparse(site_normalized).hostname or "").lower().rstrip(".")
    if not site_host:
        site_host = validate_hostname(site_target)

    def _host_matches(candidate: str, allowed: str) -> bool:
        if candidate == allowed:
            return True
        return candidate.endswith("." + allowed)

    if not (
        _host_matches(login_host, site_host) or _host_matches(site_host, login_host)
    ):
        raise SSRFError(
            f"Login URL host '{login_host}' is not same-site with "
            f"authorized target '{site_host}'"
        )
    return normalized_login


class SSRFValidationTransport(httpx.AsyncBaseTransport):
    """httpx transport that validates and pins each request to a safe IP."""

    def __init__(
        self,
        *,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        verify: bool = True,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._max_redirects = max_redirects
        self._max_response_bytes = max_response_bytes
        self._inner = inner or httpx.AsyncHTTPTransport(verify=verify)

    def _pin_request_to_validated_ip(self, request: httpx.Request) -> httpx.Request:
        """Connect to the already-validated IP while preserving the Host header.

        httpx/httpcore do not expose a stable public API to connect to one IP
        while sending TLS SNI for another hostname. For scan modules that call
        this transport with certificate verification disabled, rewriting the
        URL host to the validated IP and preserving Host closes the DNS
        rebinding window for the socket connection. Callers that need strict
        certificate validation should use a custom httpcore network backend
        that can set SNI independently.
        """
        url = request.url
        host = url.host
        if not host:
            raise SSRFError(f"Could not parse hostname from URL: {url}")
        pinned_ip = resolve_and_validate_host(host)
        pinned_url = url.copy_with(host=pinned_ip)
        headers = httpx.Headers(request.headers)
        original_authority = host
        if url.port is not None:
            original_authority = f"{host}:{url.port}"
        headers["host"] = original_authority
        return httpx.Request(
            method=request.method,
            url=pinned_url,
            headers=headers,
            content=request.stream,
            extensions=request.extensions,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        logical_request = request
        url = str(logical_request.url)
        validate_url(url, resolve_dns=True)
        pinned_request = self._pin_request_to_validated_ip(logical_request)

        response = await self._inner.handle_async_request(pinned_request)

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

            next_url = httpx.URL(str(logical_request.url)).join(location)
            validate_url(str(next_url), resolve_dns=True)

            await response.aclose()
            logical_request = httpx.Request(
                method=logical_request.method,
                url=next_url,
                headers=logical_request.headers,
            )
            pinned_request = self._pin_request_to_validated_ip(logical_request)
            response = await self._inner.handle_async_request(pinned_request)

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
            request=logical_request,
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
