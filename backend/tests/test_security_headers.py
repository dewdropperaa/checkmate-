"""Security headers middleware tests."""

from fastapi.testclient import TestClient


def test_api_security_headers(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert "content-security-policy" in response.headers
    assert "strict-transport-security" in response.headers
    assert "includeSubDomains" in response.headers["strict-transport-security"]
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    # No wildcard CORS on API responses (credentials disabled in CORS middleware).
    assert response.headers.get("access-control-allow-origin") != "*"
