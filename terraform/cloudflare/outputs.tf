output "zone_id" {
  description = "Cloudflare zone ID for this domain."
  value       = local.zone_id
}

output "cloudflare_nameservers" {
  description = <<-EOT
    MANUAL STEP: set these NS records at your domain registrar (replace existing
    nameservers). Terraform cannot do this. Wait until Dashboard shows the zone
    as Active before expecting WAF/proxy protection on public traffic.
  EOT
  value       = var.create_zone ? cloudflare_zone.this[0].name_servers : []
}

output "api_hostname" {
  description = "Proxied API hostname."
  value       = local.api_hostname
}

output "ssl_mode" {
  description = "Configured SSL/TLS mode (strict = Full strict)."
  value       = var.ssl_mode
}

output "origin_ca_certificate_pem" {
  description = "Cloudflare Origin CA certificate PEM — install on API reverse proxy."
  value       = var.enable_origin_ca ? cloudflare_origin_ca_certificate.api[0].certificate : null
  sensitive   = true
}

output "origin_ca_private_key_pem" {
  description = "Origin CA private key PEM — store in a secret manager; never commit."
  value       = var.enable_origin_ca ? tls_private_key.origin_ca[0].private_key_pem : null
  sensitive   = true
}

output "origin_ca_expires_on" {
  description = "Origin CA certificate expiry."
  value       = var.enable_origin_ca ? cloudflare_origin_ca_certificate.api[0].expires_on : null
}

output "cloudflare_ip_ranges_url" {
  description = "Published Cloudflare IP ranges for origin firewall allowlisting."
  value       = "https://www.cloudflare.com/ips/"
}

output "observability_notes" {
  description = "Where to look during an attack (Free vs paid logging limits)."
  value       = <<-EOT
    Dashboard (all plans):
      - Security → Analytics / Events — firewall, WAF, rate-limit, bot events
      - Security → Analytics — traffic & threat overview
      - Speed / Caching analytics — separate from security events

    Free-tier limits (honest):
      - Firewall event detail retention is short (often ~24h of Security Events
        visibility; exact UI retention can change — do not treat Free as a SIEM).
      - No Logpush (HTTP request logs to S3/R2/SIEM) on Free — Logpush is a
        paid/Enterprise capability.
      - Pair Cloudflare edge signals with our app structured logs
        (backend/core/logging.py) for lasting incident evidence.

    API (token-scoped):
      - GET /zones/:id/security/events (and related Analytics APIs) for recent
        events when automating triage.
  EOT
}
