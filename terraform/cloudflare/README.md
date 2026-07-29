# Cloudflare edge protection (Terraform)

Version-controlled WAF / DNS / SSL / bot / rate-limit / origin-CA config for **checkmate** using the official [`cloudflare/cloudflare`](https://registry.terraform.io/providers/cloudflare/cloudflare/latest) provider (~> 5).

Traffic shape this repo assumes:

| Hostname | Origin | Notes |
|----------|--------|--------|
| `checkmate.ma` + `www` | Vercel (`cname.vercel-dns.com`) | Proxied (orange-cloud) |
| `api.checkmate.ma` | Self-hosted Docker/Compose host IP | Proxied; needs TLS terminator + Origin CA for Full strict |

API routes protected at the edge match `backend/app/main.py` (no `/api` prefix):

- `POST /scan`
- `/auth/*` (`/auth/sync`, `/auth/extension/token`, …)
- `POST /webhooks/dodo` (billing sync — there is **no** `/api/billing/checkout` on this API; Dodo checkout is off-origin)
- Web Firebase pages: `/*/signup`, `/*/signin`, `/*/reset-password` on the Vercel host

---

## Free-tier honesty (read before applying)

| Feature | Free reality |
|---------|----------------|
| Managed WAF | **Free Managed Ruleset** only (`77454fe2d30c4220b5701f6fdfb893ba`). Full Cloudflare Managed + **OWASP Core** need **Pro+**. Set `cloudflare_plan = "pro"` after upgrade. |
| Rate limiting | **1 rule**, period **10s**, mitigation **10s**. This config uses one combined rule for sensitive paths. Separate scan/auth/billing thresholds require Pro (2 rules here) or Business. |
| Custom WAF rules | **5** max; **no regex**. |
| Bot Fight Mode | Zone-wide on/off; **cannot** scope to `/scan` only; **cannot** Skip with custom rules. |
| `cf.threat_score` | Permanently **0** — classic “bad IP reputation score” rules no longer work. Use Bot Fight Mode + managed rules + path challenges. |
| L3/L4 DDoS | **Always on** for **proxied** hostnames — no extra Terraform flag. Grey-cloud (DNS-only) is **not** protected. |
| Firewall event logs | Dashboard Security Events with **short retention** on Free. **Logpush** (durable export) is paid/Enterprise. Keep relying on app structured logs. |

---

## Manual steps (outside Terraform)

Do these in order. Steps marked **MANUAL** cannot be automated from this repo.

### 1. Cloudflare account — MANUAL

1. Create or sign in to a Cloudflare account.
2. Note **Account ID** (Overview sidebar).

### 2. API token — MANUAL

Create an API token (My Profile → API Tokens → Create Token) with **least privilege**:

| Permission | Access |
|------------|--------|
| Zone — Zone | Edit |
| Zone — DNS | Edit |
| Zone — Firewall Services | Edit |
| Zone — Zone WAF | Edit |
| Zone — Zone Settings | Edit |
| Zone — Bot Management | Edit (or Account equivalent if prompted) |
| Account — Origin CA Certificate | Edit |
| Account — Account Settings | Read (if required to list/create zones) |

Set in your shell (never commit):

```bash
# Windows PowerShell
$env:CLOUDFLARE_API_TOKEN = "your-token"

# macOS / Linux
export CLOUDFLARE_API_TOKEN="your-token"
```

Do **not** use the Global API Key.

### 3. Domain on Cloudflare + nameservers — MANUAL (critical)

**This is the step Terraform cannot do for you.**

1. Either:
   - Let Terraform create the zone (`create_zone = true`), **or**
   - Add the domain in the Cloudflare dashboard first, then set `create_zone = false` and `zone_id_override = "<zone id>"`.
2. After the zone exists, copy Cloudflare **nameservers** (Terraform output `cloudflare_nameservers`, or Dashboard → Overview).
3. At your **domain registrar**, replace the domain’s NS records with those Cloudflare nameservers.
4. Wait until Cloudflare shows the zone as **Active** (minutes to 48h). Until then, public traffic may still hit the old DNS path and **bypass** this edge config.

### 4. Fill Terraform variables — local files

```bash
cd terraform/cloudflare
cp terraform.tfvars.example terraform.tfvars
# Edit: account id, domain, api_origin_ipv4, web_origin_cname, etc.
```

### 5. Origin TLS before Full (strict) — MANUAL on the server

The API container still speaks **HTTP on :8000**. Full (strict) requires HTTPS on the origin with a cert Cloudflare trusts.

1. `terraform apply` with `enable_origin_ca = true` (or apply SSL last).
2. Install `origin_ca_certificate_pem` + `origin_ca_private_key_pem` on nginx/Caddy — see [`origin-lock/`](./origin-lock/).
3. Firewall the host so **only Cloudflare IPs** reach :443; do not leave :8000 public.
4. Only then keep `ssl_mode = "strict"`. If you enable strict before origin TLS is ready, expect **525/526** errors.

### 6. Apply

```bash
cd terraform/cloudflare
terraform init
terraform plan
terraform apply
```

### 7. Optional: Authenticated Origin Pulls — MANUAL readiness

Set `enable_authenticated_origin_pulls = true` only after the origin trusts Cloudflare’s AOP CA and `ssl_verify_client` (or Caddy equivalent) is configured. Enabling AOP without origin trust **breaks** edge→origin TLS.

### 8. Rotate origin IP if previously exposed — MANUAL (recommended)

See [`origin-lock/README.md`](./origin-lock/README.md). If the API IP was ever in public DNS before Cloudflare, treat it as known to attackers and rotate after orange-cloud is live.

---

## What Terraform manages

| File | Purpose |
|------|---------|
| `versions.tf` | Provider `cloudflare/cloudflare` ~> 5, `hashicorp/tls` |
| `zone.tf` | Zone create / ID local |
| `dns.tf` | Proxied apex, www, api A/AAAA |
| `ssl.tf` | Full strict, HTTPS redirects, TLS 1.3, security level; DDoS notes |
| `waf.tf` | Free Managed Ruleset (+ Pro Managed/OWASP); custom path challenges |
| `rate_limiting.tf` | Free combined RL or Pro split RL |
| `bot.tf` | Bot Fight Mode + inbound vs outbound comments |
| `origin.tf` | Origin CA CSR/cert; optional AOP zone setting |
| `outputs.tf` | NS, certs, observability notes |

---

## Post-setup verification checklist

- [ ] **Nameservers**: registrar NS match `terraform output cloudflare_nameservers`; zone status **Active**.
- [ ] **Proxied DNS**: `dig +short checkmate.ma` and `dig +short api.checkmate.ma` return **Cloudflare** anycast IPs (not your VPS IP).
- [ ] **Orange-cloud**: Dashboard → DNS shows proxied (orange) for apex, www, api.
- [ ] **SSL Full strict**: Dashboard → SSL/TLS → Overview = **Full (strict)**; browse `https://api.<domain>/health` succeeds (no 525/526).
- [ ] **Origin cert**: `openssl s_client -connect <origin-ip>:443 -servername api.<domain>` shows Origin CA / your installed cert; non-CF IPs should be firewalled.
- [ ] **Managed rules**: Security → WAF → Managed rules shows Free Managed Ruleset deployed (Pro: also Cloudflare Managed + OWASP).
- [ ] **Bot Fight Mode**: Security → Bots → Bot Fight Mode **On**.
- [ ] **DDoS**: Security analytics available; confirm hostnames are proxied (always-on L3/L4 only applies when proxied).
- [ ] **Rate limit test** (use a throwaway IP / controlled loop — do not DoS yourself from prod NAT you need):
  ```bash
  # Free rule: > rate_limit_sensitive_requests within 10s to /scan or /auth/sync
  for i in $(seq 1 40); do curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://api.<domain>/scan"; done
  ```
  Expect **429** or Cloudflare block/challenge pages after the threshold (exact status depends on action). Confirm an event under **Security → Events**.
- [ ] **Custom challenge**: browser hit on `/fr/signup` may show Managed Challenge. JSON `POST /scan` / `/auth/*` / `/webhooks/dodo` are **rate-limited / Bot Fight Mode**, not Managed Challenge (interactive challenges break API clients and payment webhooks).
- [ ] **Outbound scanners unaffected**: run a normal authorized scan from the backend; confirm it still reaches the **customer target** (outbound path, not inbound through this zone).
- [ ] **Webhook**: send a test Dodo webhook (or staging event) and confirm it still passes app secret validation; if Bot Fight Mode interferes, see comments in `bot.tf`.
- [ ] **Logging**: open Security → Events during the RL test; note Free retention is short — rely on app logs for longer history.

---

## Observability (where to look during an attack)

1. **Cloudflare Dashboard** → **Security** → **Analytics** / **Events** (WAF, rate limit, bot, challenge).
2. **API** (scoped token): zone security/analytics endpoints for recent events.
3. **Logpush** — not on Free; upgrade if you need durable edge logs in your SIEM.
4. **Application**: `backend` structured logs (auth failures, scan rate limits, webhook rejects) remain the durable source of truth on Free.

---

## Related app notes

- App rate limits still use `request.client.host`. Behind Cloudflare every client may look like a proxy IP unless you later trust `CF-Connecting-IP` only after verifying the peer is a Cloudflare IP. Edge RL is therefore an important complement today.
- Outbound vulnerability scans to customer sites never enter this zone inbound; Bot Fight Mode on checkmate does not block our tools.
