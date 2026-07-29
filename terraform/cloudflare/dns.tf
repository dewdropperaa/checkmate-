# -----------------------------------------------------------------------------
# DNS — proxied (orange-cloud) so traffic hits Cloudflare's edge
#
# Orange-cloud ≠ DNS-only. Without proxied=true you get Cloudflare DNS but no
# WAF/DDoS/Bot Fight Mode on that hostname.
# -----------------------------------------------------------------------------

# Apex → web origin (Vercel). Cloudflare CNAME-flattens the root.
resource "cloudflare_dns_record" "apex" {
  zone_id = local.zone_id
  name    = var.domain
  type    = "CNAME"
  content = var.web_origin_cname
  proxied = true
  ttl     = 1 # auto when proxied
  comment = "checkmate web (Vercel) — proxied through Cloudflare edge"
}

resource "cloudflare_dns_record" "www" {
  count = var.enable_www ? 1 : 0

  zone_id = local.zone_id
  name    = "www"
  type    = "CNAME"
  content = var.web_origin_cname
  proxied = true
  ttl     = 1
  comment = "www → web origin — proxied"
}

# API origin — A record to the Compose host. Proxied hides the IP from casual
# DNS lookups; historical A records / old resolvers may still know the IP.
resource "cloudflare_dns_record" "api" {
  zone_id = local.zone_id
  name    = var.api_subdomain
  type    = "A"
  content = var.api_origin_ipv4
  proxied = true
  ttl     = 1
  comment = "checkmate API origin — proxied; lock down real IP (see origin-lock/)"
}

resource "cloudflare_dns_record" "api_aaaa" {
  count = var.api_origin_ipv6 != "" ? 1 : 0

  zone_id = local.zone_id
  name    = var.api_subdomain
  type    = "AAAA"
  content = var.api_origin_ipv6
  proxied = true
  ttl     = 1
  comment = "checkmate API IPv6 — proxied"
}
