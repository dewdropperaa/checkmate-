# -----------------------------------------------------------------------------
# SSL / TLS + zone security settings
#
# Full (strict) requires the ORIGIN to present a valid certificate that
# Cloudflare trusts (public CA or Cloudflare Origin CA). Encrypting only the
# browser↔Cloudflare leg ("flexible") is NOT used here.
# -----------------------------------------------------------------------------

resource "cloudflare_zone_setting" "ssl" {
  zone_id    = local.zone_id
  setting_id = "ssl"
  value      = var.ssl_mode
}

resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = local.zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "tls_1_3" {
  zone_id    = local.zone_id
  setting_id = "tls_1_3"
  value      = "on"
}

resource "cloudflare_zone_setting" "automatic_https_rewrites" {
  zone_id    = local.zone_id
  setting_id = "automatic_https_rewrites"
  value      = "on"
}

resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = local.zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "security_level" {
  zone_id    = local.zone_id
  setting_id = "security_level"
  value      = var.security_level
}

# -----------------------------------------------------------------------------
# DDoS (L3/L4 + HTTP L7 managed) — always-on for proxied hostnames on every
# plan including Free. There is no Terraform switch to "turn on" unmetered
# network-layer DDoS mitigation; it activates because proxied=true on DNS.
#
# Verify in Dashboard → Security → Analytics / DDoS (or Overview security
# summary) after traffic flows. Do not assume grey-cloud (DNS-only) names are
# protected — they are not.
# -----------------------------------------------------------------------------
