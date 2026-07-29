# Origin IP exposure & lock-down checklist
#
# Cloudflare orange-cloud hides the origin IP from *new* DNS lookups. It does
# not erase history. If api.checkmate.ma (or the apex) ever resolved directly
# to your VPS before proxying, that IP may still be:
#   - in DNS history databases (SecurityTrails, ViewDNS, etc.)
#   - in old certificate transparency / scanner datasets
#   - cached by attackers who probed the domain earlier
#
# How to check exposure risk
#   1. Query historical DNS for your hostnames (SecurityTrails, ViewDNS,
#      Whoxy, etc.) and note any pre-Cloudflare A/AAAA values.
#   2. From a network that is NOT your office VPN, `dig +short api.<domain>`
#      should return Cloudflare anycast IPs (not your VPS) once proxied + NS live.
#   3. From the same external network, attempt `curl -vk https://<origin-ip>`
#      with Host: api.<domain>. If TLS/HTTP answers, the origin is reachable
#      without Cloudflare — lock it down.
#
# Mitigations (do these on the host / cloud firewall — not only in nginx)
#   1. Security group / ufw / iptables: allow 443 (and 80 only if needed for
#      redirects) solely from Cloudflare IP ranges; deny the rest.
#      Ranges: https://www.cloudflare.com/ips/
#      API:    https://api.cloudflare.com/client/v4/ips
#   2. Do not publish Docker `8000:8000` to 0.0.0.0 in production; bind the
#      reverse proxy only, or publish API port on a private interface.
#   3. Install Cloudflare Origin CA (Terraform outputs) and set SSL mode
#      Full (strict) so flexible/plaintext origin mode is never used.
#   4. Enable Authenticated Origin Pulls (Terraform
#      enable_authenticated_origin_pulls) and require the client cert in
#      nginx/Caddy once ready.
#   5. If the origin IP was previously public DNS: rotate to a new IP/VPS
#      after Cloudflare is active, update Terraform api_origin_ipv4, and
#      never publish the new IP in clear DNS (keep proxied=true).
#
# See also: nginx-cloudflare-only.conf.example, caddy-cloudflare-only.Caddyfile.example
