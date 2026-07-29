# -----------------------------------------------------------------------------
# Rate limiting (Ruleset Engine — http_ratelimit)
#
# Free plan quota: **1** rate limiting rule, period=10s, mitigation_timeout=10s,
# characteristics = IP only.
#
# Therefore Free uses ONE combined rule covering the highest-value abuse paths.
# Set cloudflare_plan = "pro" for separate scan / auth / billing thresholds
# (Pro allows 2 rules — we prioritize scan+auth; billing shares auth window or
# upgrade further for a third rule on Business).
#
# These sit in FRONT of application limiters:
#   POST /scan          → ScanRateLimiter (backend/app/main.py)
#   POST /auth/sync     → auth SlidingWindowRateLimiter
#   POST /webhooks/dodo → shared-secret header (not a substitute for RL)
# -----------------------------------------------------------------------------

# Free (default): single combined sensitive-path rule
resource "cloudflare_ruleset" "rate_limiting_free" {
  count = local.is_free ? 1 : 0

  zone_id     = local.zone_id
  name        = "checkmate rate limiting (free)"
  description = "Single Free-tier rate limit covering /scan, /auth/*, /webhooks/dodo"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "rl_sensitive_combined"
      description = "Per-IP rate limit for scan + auth API + Dodo webhook (Free: 1 rule budget)"
      # Free RL expressions: Path (+ Verified Bot) only — no method field.
      expression = <<-EOT
        (http.request.uri.path eq "${local.path_scan}") or
        (http.request.uri.path contains "${local.path_auth_prefix}") or
        (http.request.uri.path eq "${local.path_webhook_dodo}") or
        (http.request.uri.path contains "${local.path_billing_prefix}") or
        (http.request.uri.path contains "${local.path_checkout_prefix}")
      EOT
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["ip.src"]
        period              = var.rate_limit_sensitive_period
        requests_per_period = var.rate_limit_sensitive_requests
        mitigation_timeout  = var.rate_limit_sensitive_mitigation_timeout
      }
    }
  ]
}

# Pro: separate rules with different aggressiveness (uses 2-rule Pro quota:
# scan alone + auth/billing combined). Business (5 rules) can split further.
resource "cloudflare_ruleset" "rate_limiting_pro" {
  count = local.is_pro ? 1 : 0

  zone_id     = local.zone_id
  name        = "checkmate rate limiting (pro)"
  description = "Separate edge rate limits for scan vs auth/billing (Pro)"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      ref         = "rl_scan"
      description = "Aggressive per-IP rate limit for POST /scan"
      expression  = "(http.request.uri.path eq \"${local.path_scan}\" and http.request.method eq \"POST\")"
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 60
        requests_per_period = var.rate_limit_scan_requests
        mitigation_timeout  = 60
      }
    },
    {
      ref         = "rl_auth_and_billing"
      description = "Per-IP rate limit for /auth/*, webhook, billing/checkout paths"
      expression  = <<-EOT
        (starts_with(http.request.uri.path, "${local.path_auth_prefix}")) or
        (http.request.uri.path eq "${local.path_webhook_dodo}") or
        (starts_with(http.request.uri.path, "${local.path_billing_prefix}")) or
        (starts_with(http.request.uri.path, "${local.path_checkout_prefix}"))
      EOT
      action      = "block"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 60
        requests_per_period = min(var.rate_limit_auth_requests, var.rate_limit_billing_requests)
        mitigation_timeout  = 60
      }
    }
  ]
}
