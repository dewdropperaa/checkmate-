# Launch checklist — checkmate

> **No Docker on your laptop?** Use **[LAUNCH_NO_DOCKER.md](./LAUNCH_NO_DOCKER.md)** (Render + Vercel).  
> This document is the **VPS + `api.checkmate.ma` + Cloudflare** path.

Concrete go-live path for:

| Layer | Target |
|-------|--------|
| **Web (Vercel)** | Project **`checkmate.app`** → [https://checkmateapp-nine.vercel.app](https://checkmateapp-nine.vercel.app) (add custom domain e.g. `checkmate.ma` when ready) |
| **API** | `https://api.checkmate.ma` (self-hosted Docker Compose behind Cloudflare — see `terraform/cloudflare/`) |

Do **not** launch on a laptop + localtunnel. That setup is for short-lived debugging only.

---

## Phase 0 — Retire the dev bridge

- [ ] Stop localtunnel and host `uvicorn` used for temporary Vercel testing.
- [ ] In **Vercel → checkmate.app → Settings → Environment Variables (Production)**:
  - [ ] Remove or replace any value containing `127.0.0.1`, `localhost`, or `loca.lt`.
  - [ ] Set **`NEXT_PUBLIC_API_BASE_URL`** to `https://api.checkmate.ma` (recommended), **or** leave loopback unset and set server-only **`API_BASE_URL`** to `https://api.checkmate.ma` (browser uses same-origin `/api/backend/*` — see `web/next.config.ts`).
  - [ ] If you use **`API_BASE_URL`**, mark it available at **build time** (Vercel: do not rely on “sensitive-only” for values Next.js reads in `next.config.ts` rewrites; prefer `NEXT_PUBLIC_API_BASE_URL` for the public HTTPS API or verify rewrites after deploy).
- [ ] **Redeploy** production after any `NEXT_PUBLIC_*` change (values are baked in at build time).

---

## Phase 1 — API host (VPS)

**Sizing:** ≥ 4 GiB RAM free on the host (ZAP limit 2 GiB + backend). See `backend/docker-compose.yml`.

- [ ] Provision a Linux VPS with a **static IPv4** (and optional IPv6) for `api.checkmate.ma`.
- [ ] Install Docker Engine + Compose v2.
- [ ] Clone this repo on the server (or deploy via CI artifacts).
- [ ] Copy env template and fill secrets on the server only:

  ```bash
  cd backend
  cp .env.production.example .env
  # edit .env — never commit .env
  ```

- [ ] Place Firebase Admin JSON on the server (e.g. `/etc/checkmate/firebase-sa.json`) and set `FIREBASE_CREDENTIALS_PATH` **or** inject `FIREBASE_CREDENTIALS_JSON` via your secret manager.
- [ ] Generate and set strong values (examples in `backend/.env.production.example`):
  - `ZAP_API_KEY`
  - `CREDENTIALS_MASTER_KEY`
  - `DODO_WEBHOOK_SECRET` (if billing is live)
- [ ] Start the stack:

  ```bash
  cd backend
  docker compose -f docker-compose.yml -f docker-compose.launch.yml up -d --build
  ```

- [ ] From the server: `curl -sf http://127.0.0.1:8000/health` → JSON with `"status":"ok"`, `"migrations_current":true`, `"database_ready":true`.
- [ ] Configure **host firewall**: deny public `:8000`; only **127.0.0.1** (or your TLS proxy) may reach the API container (see `docker-compose.launch.yml`).
- [ ] Put **Caddy or nginx** on the host with Cloudflare Origin CA (or Full Strict) terminating TLS on `api.checkmate.ma` → `http://127.0.0.1:8000`. Examples: `terraform/cloudflare/origin-lock/`.
- [ ] Restrict origin to **Cloudflare IPs only** on the VPS (origin-lock README).

---

## Phase 2 — Cloudflare DNS & edge

Follow `terraform/cloudflare/README.md` (or equivalent manual steps).

- [ ] Zone active on Cloudflare for **`checkmate.ma`** (nameservers at registrar).
- [ ] **Apex / www** → Vercel (`cname.vercel-dns.com`), proxied.
- [ ] **`api`** → VPS IPv4, **proxied** (orange cloud).
- [ ] WAF / rate limits applied to sensitive paths (`POST /scan`, `/auth/*`, webhooks).
- [ ] Public check: `dig +short api.checkmate.ma` returns Cloudflare anycast, not your raw VPS IP in casual lookups.
- [ ] HTTPS: `curl -sf https://api.checkmate.ma/health` succeeds from your laptop.

---

## Phase 3 — Backend production env

`APP_ENV=production` triggers strict startup validation in `backend/core/config.py`. The API **must not start** until required keys are set.

Use `backend/.env.production.example` as the checklist. Minimum expectations:

- [ ] `APP_ENV=production`, `DEBUG=false`, `LOG_LEVEL=INFO`
- [ ] `REQUIRE_FIREBASE_AUTH=true`
- [ ] `REQUIRE_TOOLCHAIN_AT_STARTUP=true` (Compose default)
- [ ] `FIREBASE_PROJECT_ID` + Admin credentials
- [ ] `PRODUCTION_FIREBASE_PROJECT_ID` matches `FIREBASE_PROJECT_ID` when set
- [ ] `CREDENTIALS_MASTER_KEY` set
- [ ] `ZAP_API_KEY` set (Compose injects `ZAP_API_URL=http://zap:8080`)
- [ ] `PUBLIC_APP_URL` = your real web origin (e.g. `https://checkmateapp-nine.vercel.app` or `https://checkmate.ma`)
- [ ] **Billing (production):** `DODO_ENVIRONMENT=live`, `DODO_API_KEY` (`dodo_live_*`), `DODO_WEBHOOK_SECRET`
- [ ] **Firecrawl:** either `FIRECRAWL_API_KEY` or `FIRECRAWL_ENABLED=false`
- [ ] `AUTHORIZED_TARGETS` — only domains you are legally allowed to scan (see `SECURITY.md`)
- [ ] Persist volumes `app-data` / `app-reports`; document backup/restore (`README.md` runbook)

**Staging soft launch:** use `APP_ENV=staging` with test Dodo keys and a separate Firebase project — see `backend/.env.production.example` notes. Do not point staging at production Firebase.

---

## Phase 4 — Vercel (`checkmate.app`)

**Project settings**

- [ ] **Root Directory:** repository root **or** `web` — must match how you deploy (root `vercel.json` runs `npm run build --prefix web`).
- [ ] Framework: **Next.js**.

**Production environment variables** (copy from `web/.env.production.example`):

| Variable | Example / notes |
|----------|-----------------|
| `NEXT_PUBLIC_FIREBASE_API_KEY` | Firebase console → Project settings → Web app |
| `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN` | `your-project.firebaseapp.com` |
| `NEXT_PUBLIC_FIREBASE_PROJECT_ID` | Same project as backend Admin SDK |
| `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET` | |
| `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID` | |
| `NEXT_PUBLIC_FIREBASE_APP_ID` | |
| `NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID` | Optional |
| `NEXT_PUBLIC_API_BASE_URL` | **`https://api.checkmate.ma`** |
| `API_BASE_URL` | Optional: same as above if using `/api/backend` proxy instead of direct browser calls |

- [ ] Production **redeploy** after env changes.
- [ ] Add custom domain in Vercel and assign to **Production** when `checkmate.ma` is ready.

---

## Phase 5 — Firebase & Google Cloud (auth)

- [ ] **Authentication → Sign-in method:** Email/Password (+ Google if used) enabled.
- [ ] **Authentication → Settings → Authorized domains:** add every web origin:
  - `checkmateapp-nine.vercel.app`
  - `checkmate.ma`, `www.checkmate.ma` (when live)
  - Any Vercel preview pattern you actually use (Firebase does not support `*.vercel.app` wildcards — add specific preview hostnames or use a stable staging URL)

  Helper (run locally with service account on disk):

  ```bash
  backend/.venv/bin/python scripts/firebase_add_authorized_domain.py checkmate.ma www.checkmate.ma checkmateapp-nine.vercel.app
  ```

- [ ] **Google Cloud → APIs & Services → Credentials → Browser API key:** HTTP referrer restrictions include:
  - `https://checkmateapp-nine.vercel.app/*`
  - `https://checkmate.ma/*`
  - `https://www.checkmate.ma/*`
- [ ] Never put Firebase **Admin** JSON or `AIza` server keys in `NEXT_PUBLIC_*`.

---

## Phase 6 — Smoke tests (go / no-go)

Run in order after Phase 1–5.

- [ ] `GET https://api.checkmate.ma/health` — OK, migrations current.
- [ ] Open `https://checkmateapp-nine.vercel.app/fr/signin` — no CSP console errors for Firebase.
- [ ] Sign up / sign in with **verified email** — no `127.0.0.1` or `loca.lt` in Network tab.
- [ ] `POST /auth/sync` succeeds (dashboard loads without “Failed to fetch”).
- [ ] Queue a scan against an **allowlisted** target — completes or fails gracefully with auth enforced.
- [ ] Confirm **no** `DEBUG=true`, **no** tunnel URLs, **no** open `:8000` on the public internet (only via Cloudflare → TLS proxy).

---

## Phase 7 — Operations before marketing

- [ ] Log shipping / alerting (Compose restart loops, ZAP OOM, 5xx rate).
- [ ] Backup schedule for `app-data` and `app-reports` volumes.
- [ ] Incident contact and secret rotation plan (ZAP, Dodo webhook, Firebase SA).
- [ ] Legal: terms/privacy pages live; scan scope documented (`SECURITY.md`).

---

## Quick reference

| File | Purpose |
|------|---------|
| `backend/.env.production.example` | API secrets template (copy to `.env` on server) |
| `backend/docker-compose.yml` | Production stack (backend + ZAP) |
| `backend/docker-compose.launch.yml` | Bind API to loopback only (use with host TLS proxy) |
| `web/.env.production.example` | Vercel production variable list |
| `terraform/cloudflare/` | DNS, WAF, origin lock |
| `scripts/firebase_add_authorized_domain.py` | Add Firebase authorized domains |
