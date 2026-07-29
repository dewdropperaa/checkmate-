# -----------------------------------------------------------------------------
# WAF — managed rulesets + custom rules
#
# Free plan: Cloudflare Free Managed Ruleset only
#   ID: 77454fe2d30c4220b5701f6fdfb893ba
#   Covers high-impact / widely exploited patterns (e.g. Log4Shell, Shellshock
#   class rules, some CMS exploits). NOT the full OWASP Core Ruleset.
#
# Pro+: Cloudflare Managed Ruleset + OWASP Core Ruleset (true OWASP CRS
#   equivalent). Set cloudflare_plan = "pro" after upgrading.
#
# Custom rules (Free quota: 5). No regex on Free — use eq / contains /
# starts_with only. These complement app-level protections; they do not replace
# Firebase auth, webhook secrets, or ScanRateLimiter in backend/app/main.py.
#
# NOTE on "IP reputation" / cf.threat_score:
#   Cloudflare permanently sets cf.threat_score to 0. Classic "challenge if
#   threat_score > N" rules no longer work. On Free we rely on Bot Fight Mode,
#   Free Managed Ruleset, Security Level, and path-focused custom challenges.
# -----------------------------------------------------------------------------

locals {
  # Managed ruleset IDs (Cloudflare-published, stable)
  free_managed_ruleset_id       = "77454fe2d30c4220b5701f6fdfb893ba"
  cloudflare_managed_ruleset_id = "efb7b8c949ac4650a09736fc376e9aee"
  owasp_core_ruleset_id         = "4814384a9e5d4991b9815dcfc25d2f1f"
}

resource "cloudflare_ruleset" "managed_waf" {
  zone_id     = local.zone_id
  name        = "checkmate managed WAF"
  description = "Zone entry-point for WAF Managed Rules"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules = concat(
    [
      {
        ref         = "execute_free_managed_ruleset"
        description = "Execute Cloudflare Free Managed Ruleset (baseline edge SQLi/XSS/exploit patterns available on Free)"
        expression  = "true"
        action      = "execute"
        action_parameters = {
          id = local.free_managed_ruleset_id
        }
        enabled = true
      }
    ],
    local.is_pro ? [
      {
        ref         = "execute_cloudflare_managed_ruleset"
        description = "Execute Cloudflare Managed Ruleset (Pro+)"
        expression  = "true"
        action      = "execute"
        action_parameters = {
          id = local.cloudflare_managed_ruleset_id
        }
        enabled = true
      },
      {
        ref         = "execute_owasp_core_ruleset"
        description = "Execute Cloudflare OWASP Core Ruleset (Pro+)"
        expression  = "true"
        action      = "execute"
        action_parameters = {
          id = local.owasp_core_ruleset_id
        }
        enabled = true
      }
    ] : []
  )
}

resource "cloudflare_ruleset" "custom_waf" {
  zone_id     = local.zone_id
  name        = "checkmate custom WAF"
  description = "Browser challenges + probe friction (Free: max 5 rules, no regex). JSON APIs are rate-limited, not challenged."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    # Browser auth surfaces (Next.js / Firebase) — Managed Challenge is safe here.
    # Do NOT managed_challenge JSON API routes: SPA, extension, and Dodo webhooks
    # cannot solve interactive challenges; those paths use rate limiting + Bot Fight Mode.
    {
      ref         = "challenge_web_auth_pages"
      description = "Managed Challenge signup/signin/reset-password pages (fake-signup abuse)"
      expression  = "(http.request.uri.path contains \"/signup\" or http.request.uri.path contains \"/signin\" or http.request.uri.path contains \"/reset-password\")"
      action      = "managed_challenge"
      enabled     = true
    },
    # Browser-facing billing/checkout paths if ever hosted on this zone.
    # /webhooks/dodo is intentionally excluded — providers cannot pass CAPTCHA.
    {
      ref         = "challenge_billing_browser_paths"
      description = "Managed Challenge /billing/* and /checkout* browser paths (not webhooks)"
      expression  = "(starts_with(http.request.uri.path, \"${local.path_billing_prefix}\") or starts_with(http.request.uri.path, \"${local.path_checkout_prefix}\"))"
      action      = "managed_challenge"
      enabled     = true
    },
    # Empty User-Agent scanners / script-kiddie probes.
    {
      ref         = "challenge_empty_ua"
      description = "Managed Challenge requests with empty User-Agent"
      expression  = "(http.user_agent eq \"\")"
      action      = "managed_challenge"
      enabled     = true
    },
    # Common exploit probes that never apply to this stack.
    {
      ref         = "block_wp_probes"
      description = "Block WordPress admin/login probes"
      expression  = "(http.request.uri.path contains \"/wp-admin\" or http.request.uri.path contains \"/wp-login.php\" or http.request.uri.path contains \"/xmlrpc.php\")"
      action      = "block"
      enabled     = true
    },
    # Obvious missing Host / junk — low false-positive catch-all within Free quota.
    {
      ref         = "block_missing_user_agent_post_scan"
      description = "Block POST /scan with empty User-Agent (scan-quota abuse scripts)"
      expression  = "(http.request.uri.path eq \"${local.path_scan}\" and http.request.method eq \"POST\" and http.user_agent eq \"\")"
      action      = "block"
      enabled     = true
    },
  ]
}
