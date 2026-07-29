# -----------------------------------------------------------------------------
# Variables — checkmate Cloudflare edge (WAF / DNS / origin lock)
# -----------------------------------------------------------------------------

variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare account ID (Dashboard → right sidebar, or Overview → Account ID)."
}

variable "domain" {
  type        = string
  description = "Apex production domain (e.g. checkmate.ma). Must already be addable under this account."
  default     = "checkmate.ma"
}

variable "create_zone" {
  type        = bool
  description = <<-EOT
    If true, Terraform creates the Cloudflare zone. After apply, you MUST update
    nameservers at your registrar to the values in output `cloudflare_nameservers`
    (manual step — cannot be automated). If the zone already exists in Cloudflare,
    set this false and import / use zone_id_override instead.
  EOT
  default     = true
}

variable "zone_id_override" {
  type        = string
  description = "Existing Cloudflare zone ID when create_zone=false (Dashboard → Overview)."
  default     = ""
}

# --- DNS origins ----------------------------------------------------------------

variable "web_origin_cname" {
  type        = string
  description = <<-EOT
    CNAME target for apex + www (proxied through Cloudflare). For Vercel use
    cname.vercel-dns.com (or your project-specific Vercel CNAME). Cloudflare
    flattens apex CNAMEs automatically.
  EOT
  default     = "cname.vercel-dns.com"
}

variable "api_subdomain" {
  type        = string
  description = "API hostname label under the zone (api → api.example.com)."
  default     = "api"
}

variable "api_origin_ipv4" {
  type        = string
  description = <<-EOT
    Public IPv4 of the API origin (Docker/Compose host). Proxied (orange-cloud)
    so clients never see this IP in DNS — but historical exposure still matters;
    see README § Origin IP exposure.
  EOT
}

variable "api_origin_ipv6" {
  type        = string
  description = "Optional public IPv6 of the API origin. Leave empty to skip AAAA."
  default     = ""
}

variable "enable_www" {
  type        = bool
  description = "Create www CNAME → web_origin_cname (proxied)."
  default     = true
}

# --- Security posture -----------------------------------------------------------

variable "ssl_mode" {
  type        = string
  description = <<-EOT
    Cloudflare SSL/TLS encryption mode. Use "strict" (Full strict): Cloudflare
    validates the origin certificate. Requires a valid cert on the origin
    (Let's Encrypt, Cloudflare Origin CA, or public CA). Our API Compose stack
    speaks HTTP on :8000 today — you MUST terminate TLS on a reverse proxy
    (nginx/Caddy) with Origin CA or a public cert before enabling strict, or
    edge→origin will fail with 525/526.
  EOT
  default     = "strict"

  validation {
    condition     = contains(["flexible", "full", "strict"], var.ssl_mode)
    error_message = "ssl_mode must be flexible, full, or strict."
  }
}

variable "security_level" {
  type        = string
  description = <<-EOT
    Zone security level. "medium" balances false positives vs protection for a
    SaaS API + marketing site. Use "high" only if you accept more challenges.
    In Cloudflare's newer security UI this mainly maps to Under Attack mode
    (essentially_off vs under_attack); we still set medium for API/Terraform
    compatibility. Prefer Bot Fight Mode + custom rules for day-to-day.
  EOT
  default     = "medium"

  validation {
    condition     = contains(["off", "essentially_off", "low", "medium", "high", "under_attack"], var.security_level)
    error_message = "Invalid security_level."
  }
}

variable "enable_bot_fight_mode" {
  type        = bool
  description = <<-EOT
    Enable free Bot Fight Mode (zone-wide — cannot be scoped to paths on Free).
    Challenges/blocks obvious bots hitting the whole zone, including signup,
    checkout UIs, and API. Outbound scanner traffic FROM our backend TO customer
    targets does NOT transit this Cloudflare zone inbound, so it is unaffected.
  EOT
  default     = true
}

variable "cloudflare_plan" {
  type        = string
  description = <<-EOT
    "free" (default) or "pro". Controls which managed rulesets and how many
    rate-limit rules Terraform deploys. Free: 1 rate-limit rule, Free Managed
    Ruleset only. Pro: up to 2 rate-limit rules + Cloudflare Managed + OWASP.
  EOT
  default     = "free"

  validation {
    condition     = contains(["free", "pro"], var.cloudflare_plan)
    error_message = "cloudflare_plan must be free or pro."
  }
}

# --- Rate limits (edge). Complement app-level limiters in backend/app/main.py. ---

variable "rate_limit_sensitive_period" {
  type        = number
  description = "Counting window seconds. Free plan only supports 10."
  default     = 10
}

variable "rate_limit_sensitive_requests" {
  type        = number
  description = <<-EOT
    Max requests per IP per period for the combined sensitive-path Free rule
    (/scan, /auth/*, /webhooks/dodo). App still enforces its own windows.
  EOT
  default     = 20
}

variable "rate_limit_sensitive_mitigation_timeout" {
  type        = number
  description = "Seconds to block after threshold. Free plan only supports 10."
  default     = 10
}

variable "rate_limit_scan_requests" {
  type        = number
  description = "Pro-only: POST /scan requests per IP per period."
  default     = 10
}

variable "rate_limit_auth_requests" {
  type        = number
  description = "Pro-only: /auth/* requests per IP per period (more aggressive)."
  default     = 15
}

variable "rate_limit_billing_requests" {
  type        = number
  description = "Pro-only: webhook/billing paths per IP per period."
  default     = 30
}

variable "enable_origin_ca" {
  type        = bool
  description = "Issue a Cloudflare Origin CA cert for api (+ optional apex/www) via Terraform."
  default     = true
}

variable "origin_ca_hostnames" {
  type        = list(string)
  description = <<-EOT
    Hostnames on the Origin CA cert. Default: api.<domain> only (self-hosted).
    Web on Vercel already has its own certs — do not put Vercel hostnames here
    unless you terminate TLS yourself for those names.
  EOT
  default     = [] # resolved in locals when empty
}

variable "enable_authenticated_origin_pulls" {
  type        = bool
  description = <<-EOT
    Enable zone-level Authenticated Origin Pulls (Cloudflare presents a client
    cert to the origin). Requires origin reverse-proxy trust of Cloudflare's
    AOP CA — see origin-lock/. Keep false until nginx/Caddy is ready or you
    will break origin connectivity.
  EOT
  default     = false
}
