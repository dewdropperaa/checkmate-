# -----------------------------------------------------------------------------
# Origin CA + Authenticated Origin Pulls
#
# Full (strict) needs a cert Cloudflare trusts on the API origin. Cloudflare
# Origin CA is free and intended for this (browsers do NOT trust it — only CF).
#
# Install the issued cert+key on nginx/Caddy in front of uvicorn:8000.
# Examples: origin-lock/
#
# Authenticated Origin Pulls (optional): Cloudflare presents a client cert so
# the origin can reject non-Cloudflare TLS clients even if they know the IP.
# Enable only after the origin trusts Cloudflare's AOP CA.
# -----------------------------------------------------------------------------

resource "tls_private_key" "origin_ca" {
  count = var.enable_origin_ca ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "origin_ca" {
  count = var.enable_origin_ca ? 1 : 0

  private_key_pem = tls_private_key.origin_ca[0].private_key_pem

  subject {
    common_name = local.origin_ca_hostnames[0]
  }

  dns_names = local.origin_ca_hostnames
}

resource "cloudflare_origin_ca_certificate" "api" {
  count = var.enable_origin_ca ? 1 : 0

  csr                = tls_cert_request.origin_ca[0].cert_request_pem
  hostnames          = local.origin_ca_hostnames
  request_type       = "origin-rsa"
  requested_validity = 5475 # ~15 years (Cloudflare allowed value)
}

# Zone-level AOP: Cloudflare presents its client cert on origin pulls.
# Origin must require/verify that client cert (see origin-lock/) BEFORE enabling
# or TLS handshakes from Cloudflare will fail.
resource "cloudflare_zone_setting" "tls_client_auth" {
  count = var.enable_authenticated_origin_pulls ? 1 : 0

  zone_id    = local.zone_id
  setting_id = "tls_client_auth"
  value      = "on"
}
