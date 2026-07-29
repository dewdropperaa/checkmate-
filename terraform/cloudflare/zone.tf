# -----------------------------------------------------------------------------
# Zone
#
# MANUAL (outside Terraform) — after create_zone=true apply succeeds:
#   1. Copy output cloudflare_nameservers
#   2. At your domain registrar, replace NS records with those Cloudflare NS
#   3. Wait for propagation (hours → 48h). Until then, proxied DNS/WAF will
#      not protect public traffic even if Terraform resources look "created".
# -----------------------------------------------------------------------------

locals {
  zone_id = var.create_zone ? cloudflare_zone.this[0].id : var.zone_id_override

  api_hostname = "${var.api_subdomain}.${var.domain}"

  origin_ca_hostnames = length(var.origin_ca_hostnames) > 0 ? var.origin_ca_hostnames : [
    local.api_hostname,
  ]

  is_free = var.cloudflare_plan == "free"
  is_pro  = var.cloudflare_plan == "pro"

  # Actual FastAPI paths in backend/app/main.py (no /api prefix; no /billing/checkout).
  # Web signup/signin/reset live on Next.js (Vercel), not on the API host.
  path_scan            = "/scan"
  path_auth_prefix     = "/auth/"
  path_webhook_dodo    = "/webhooks/dodo"
  # Future-proof: if a checkout proxy is ever added under the API host.
  path_billing_prefix  = "/billing/"
  path_checkout_prefix = "/checkout"
}

resource "cloudflare_zone" "this" {
  count = var.create_zone ? 1 : 0

  account = {
    id = var.cloudflare_account_id
  }
  name = var.domain
  type = "full"
}

check "zone_id_when_not_creating" {
  assert {
    condition     = var.create_zone || length(var.zone_id_override) > 0
    error_message = "Set zone_id_override when create_zone=false."
  }
}
