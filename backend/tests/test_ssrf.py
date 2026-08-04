"""Tests for SSRF protections."""

from __future__ import annotations

import socket
from unittest.mock import patch

import httpx
import pytest

from core.ssrf import (
    SSRFError,
    SSRFValidationTransport,
    validate_scan_target,
    validate_url,
)


class TestValidateUrl:
    def test_rejects_localhost(self) -> None:
        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://127.0.0.1/", resolve_dns=False)

    def test_rejects_localhost_hostname(self) -> None:
        with pytest.raises(SSRFError, match="not allowed"):
            validate_url("http://localhost/", resolve_dns=False)

    def test_rejects_private_ip_literal(self) -> None:
        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://192.168.1.1/", resolve_dns=False)

    def test_rejects_link_local_metadata_ip(self) -> None:
        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://169.254.169.254/", resolve_dns=False)

    def test_rejects_ipv6_link_local_literal(self) -> None:
        with pytest.raises(SSRFError, match="blocked"):
            validate_url("http://[fe80::1]/", resolve_dns=False)

    def test_rejects_cloud_metadata_hostname(self) -> None:
        with pytest.raises(SSRFError, match="not allowed"):
            validate_url("http://metadata.google.internal/", resolve_dns=False)

    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(SSRFError, match="not allowed"):
            validate_url("file:///etc/passwd", resolve_dns=False)

    def test_rejects_gopher_scheme(self) -> None:
        with pytest.raises(SSRFError, match="not allowed"):
            validate_url("gopher://evil.com/", resolve_dns=False)

    def test_rejects_malformed_hostname(self) -> None:
        with pytest.raises(SSRFError, match="Malformed"):
            validate_url("http://not_a_valid_host!!!/", resolve_dns=False)

    @pytest.mark.parametrize(
        "url",
        [
            "http://2852039166/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.1/",
        ],
    )
    def test_rejects_non_canonical_ip_literals(self, url: str) -> None:
        with pytest.raises(SSRFError, match="blocked"):
            validate_url(url, resolve_dns=False)

    def test_rejects_domain_resolving_to_private_ip(self) -> None:
        fake_results = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.50.1", 0)),
        ]
        with patch("core.ssrf.socket.getaddrinfo", return_value=fake_results):
            with pytest.raises(SSRFError, match="resolves to blocked"):
                validate_url("http://internal.corp.example/", resolve_dns=True)

    def test_accepts_public_domain_without_blocked_resolution(self) -> None:
        fake_results = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]
        with patch("core.ssrf.socket.getaddrinfo", return_value=fake_results):
            result = validate_url("http://example.com/", resolve_dns=True)
            assert result.startswith("http://example.com")


class TestRedirectSSRF:
    @pytest.mark.asyncio
    async def test_rejects_redirect_to_private_ip(self) -> None:
        public_ip = "93.184.216.34"
        fake_public = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (public_ip, 0)),
        ]

        request = httpx.Request("GET", "http://example.com/")
        redirect_response = httpx.Response(
            302,
            headers={"location": "http://127.0.0.1/"},
            request=request,
        )
        ok_response = httpx.Response(200, request=request)

        class FakeInner(httpx.AsyncBaseTransport):
            call_count = 0

            async def handle_async_request(self, req: httpx.Request) -> httpx.Response:
                FakeInner.call_count += 1
                if FakeInner.call_count == 1:
                    return redirect_response
                return ok_response

        transport = SSRFValidationTransport(max_redirects=5)
        transport._inner = FakeInner()

        with patch("core.ssrf.socket.getaddrinfo", return_value=fake_public):
            with pytest.raises(SSRFError, match="blocked"):
                await transport.handle_async_request(request)

    def test_dns_rebinding_like_resolution_change_is_rechecked_per_request(self) -> None:
        first_public = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]
        second_private = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
        ]
        with patch(
            "core.ssrf.socket.getaddrinfo",
            side_effect=[first_public, second_private],
        ):
            assert validate_url("https://rebinding.example", resolve_dns=True).startswith("https://")
            with pytest.raises(SSRFError, match="blocked"):
                validate_url("https://rebinding.example", resolve_dns=True)


class TestScanTargetIngress:
    def test_validate_scan_target_rejects_loopback(self) -> None:
        with pytest.raises(SSRFError):
            validate_scan_target("http://127.0.0.1:8080/admin")

    def test_api_rejects_ssrf_target(self, client) -> None:
        from fastapi.testclient import TestClient

        assert isinstance(client, TestClient)
        response = client.post(
            "/scan",
            json={"target": "http://127.0.0.1", "confirmed_authorized": True},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_scan_target"

    def test_api_rejects_private_ip(self, client) -> None:
        response = client.post(
            "/scan",
            json={"target": "http://10.0.0.1", "confirmed_authorized": True},
        )
        assert response.status_code == 400

    def test_api_rejects_metadata_ip(self, client) -> None:
        response = client.post(
            "/scan",
            json={"target": "http://169.254.169.254", "confirmed_authorized": True},
        )
        assert response.status_code == 400

    def test_api_accepts_public_target_with_mocked_dns(self, client, monkeypatch) -> None:
        fake_results = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]
        monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: fake_results)
        response = client.post(
            "/scan",
            json={"target": "https://example.com", "confirmed_authorized": True},
        )
        assert response.status_code == 202


class TestSSRFTransportStreamPinning:
    """Regression: IP-pinning must preserve request.stream type for AsyncHTTPTransport.

    Using content=request.stream wrapped the body in IteratorByteStream, which
    AsyncHTTPTransport rejects with AssertionError — blank header-checks failures.
    """

    @pytest.mark.asyncio
    async def test_pin_preserves_stream_type_for_head(self, monkeypatch: pytest.MonkeyPatch) -> None:
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: public)

        seen_streams: list[type] = []

        class _Inner(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                seen_streams.append(type(request.stream))
                # AsyncHTTPTransport asserts AsyncByteStream; IteratorByteStream
                # (from the content= wrapping bug) fails that check.
                assert "IteratorByteStream" not in type(request.stream).__name__
                # Provide an unconsumed stream so SSRFValidationTransport can
                # aiter_raw() without StreamConsumed.
                return httpx.Response(
                    200,
                    request=request,
                    stream=httpx.ByteStream(b""),
                )

        transport = SSRFValidationTransport(inner=_Inner(), verify=False)
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            response = await client.head("https://example.com/")
        assert response.status_code == 200
        assert seen_streams, "inner transport was not invoked"
        # Must not be IteratorByteStream (the content= wrapping bug).
        for stream_type in seen_streams:
            assert "IteratorByteStream" not in stream_type.__name__

    @pytest.mark.asyncio
    async def test_pin_connects_to_validated_ip_not_hostname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        public_ip = "93.184.216.34"
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (public_ip, 0))]
        monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: public)
        connected: list[str] = []

        class _Inner(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                connected.append(str(request.url))
                assert request.headers.get("host") == "example.com"
                return httpx.Response(
                    200,
                    request=request,
                    stream=httpx.ByteStream(b"ok"),
                )

        transport = SSRFValidationTransport(inner=_Inner(), verify=False)
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            await client.get("https://example.com/path")
        assert connected == [f"https://{public_ip}/path"]

    @pytest.mark.asyncio
    async def test_pin_sets_sni_hostname_to_original_host(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """IP-pinned HTTPS must keep hostname SNI or TLS handshakes fail."""
        public_ip = "93.184.216.34"
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (public_ip, 0))]
        monkeypatch.setattr("core.ssrf.socket.getaddrinfo", lambda *a, **k: public)
        seen_sni: list[str | None] = []

        class _Inner(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                seen_sni.append(request.extensions.get("sni_hostname"))
                return httpx.Response(
                    200,
                    request=request,
                    stream=httpx.ByteStream(b"ok"),
                )

        transport = SSRFValidationTransport(inner=_Inner(), verify=False)
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            await client.get("https://example.com/")
        assert seen_sni == ["example.com"]
