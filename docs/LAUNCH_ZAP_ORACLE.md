# Full ZAP scans in production — $0/month (Oracle Cloud)

**Your product needs OWASP ZAP active scanning.** Render’s free Python tier cannot run ZAP. Render Starter (~$14/mo) can, but requires a card.

**Oracle Cloud “Always Free”** gives you an ARM VM (2 vCPU, 12 GB RAM) forever — enough to run the full Docker stack (API + ZAP + nuclei + sqlmap) in the cloud, **not on your laptop**.

> Oracle asks for a **credit/debit card for identity verification** (like Render). You are not charged if you stay within Always Free limits. Prepaid/virtual cards are often rejected.

---

## What you get

| Component | Where it runs |
|-----------|----------------|
| Vercel web app | Unchanged |
| FastAPI + ZAP + tools | Oracle VM (Docker Compose) |
| Active ZAP scan | Yes (`CLOUD_SCAN_PROFILE=full`) |
| Your laptop | Off — not required |

---

## 1. Create Oracle VM (one time)

1. Sign up: [cloud.oracle.com](https://www.oracle.com/cloud/free/)
2. **Compute → Instances → Create instance**
3. **Image:** Ubuntu 22.04 or 24.04 (aarch64)
4. **Shape:** `VM.Standard.A1.Flex` (Ampere) — **2 OCPUs, 12 GB RAM** (Always Free limit)
5. **Boot volume:** 50–100 GB
6. **Networking:** assign a **public IPv4**
7. **SSH key:** add your public key
8. Create

Open **ingress rules** on the VCN security list:

| Port | Source | Purpose |
|------|--------|---------|
| 22 | Your IP | SSH |
| 80 | 0.0.0.0/0 | HTTP (Let’s Encrypt) |
| 443 | 0.0.0.0/0 | HTTPS API |

> Do **not** expose ZAP (8080) publicly — Docker keeps it internal.

If you get **“Out of host capacity”**, try another availability domain or region, or retry later.

---

## 2. Bootstrap the scanner on the VM

SSH in:

```bash
ssh ubuntu@YOUR_VM_PUBLIC_IP
```

Run the bootstrap script from your repo (after pushing to GitHub):

```bash
curl -fsSL https://raw.githubusercontent.com/dewdropperaa/checkmate-/main/scripts/vps-bootstrap.sh | bash
```

Or clone and run locally on the VM:

```bash
git clone https://github.com/dewdropperaa/checkmate-.git
cd checkmate-
chmod +x scripts/vps-bootstrap.sh
./scripts/vps-bootstrap.sh
```

The script installs Docker, builds `backend/docker-compose.yml`, and prompts you to paste production `.env` values (Firebase JSON, `ZAP_API_KEY`, `CREDENTIALS_MASTER_KEY`, etc.).

---

## 3. HTTPS (required for Vercel)

Browsers on `https://checkmateapp-nine.vercel.app` **cannot** call a plain `http://IP:8000` API.

**Option A — Custom domain (recommended)**  
Point `api.yourdomain.com` A-record → VM IP. Caddy in the bootstrap script obtains Let’s Encrypt automatically.

**Option B — Cloudflare Tunnel (free, no open ports)**  
[Cloudflare Zero Trust](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) → create a tunnel to `http://localhost:8000` → get a stable `https://….trycloudflare.com` or your domain.

---

## 4. Wire Vercel

```powershell
.\scripts\deploy-production-api.ps1 -RenderApiUrl "https://api.yourdomain.com"
```

Verify:

```bash
curl https://api.yourdomain.com/health
# expect: "zap_ready": true, "toolchain": { "ready": true }
```

Sign in on the live app → **Lancer le scan** → ZAP active scan runs in the cloud.

---

## 5. Costs

| Path | ZAP active | Monthly $ | Card |
|------|------------|-----------|------|
| Oracle Always Free | Yes | **$0** | Verification only |
| Render Starter | Yes | ~$14+ | Required |
| Render free Python | **No** | $0 | No |

---

## Troubleshooting

- **`zap_ready: false`** — `docker compose logs zap` on the VM; ZAP needs ~2 min on first boot.
- **Scan 503 toolchain** — ensure `CLOUD_SCAN_PROFILE=full` and `CLOUD_SCANNING_ENABLED=true` in VM `.env`.
- **VM RAM** — ZAP + backend need ~4 GB; 12 GB Always Free is sufficient for one concurrent scan.
