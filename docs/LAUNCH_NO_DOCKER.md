# Launch without Docker on your laptop

> **Want $0 hosting?** Use **[LAUNCH_FREE.md](./LAUNCH_FREE.md)** (`render.yaml` free tier).  
> **Paid cloud scans (ZAP + disk):** **[LAUNCH_NO_DOCKER.md](./LAUNCH_NO_DOCKER.md)** (`render.starter.yaml`).

**Web:** Vercel project [`checkmate.app`](https://checkmateapp-nine.vercel.app)  
**API:** [Render](https://render.com) builds in the cloud — you never install Docker locally.

Security properties of the **paid** path (`render.starter.yaml`):

- HTTPS end-to-end (Render + Vercel), no localtunnel, no `127.0.0.1` in production env.
- `APP_ENV=hosted`: Firebase auth required on scans, no live billing keys, no `DEBUG`.
- ZAP runs as a **private** Render service (not on the public internet).
- Firebase Admin JSON stays in Render secrets only.

When you are ready for live billing and full production gates, switch the API to `APP_ENV=production` (see `docs/LAUNCH.md`).

---

## 1. One-time: Render blueprint

1. Push this repo to GitHub (if not already).
2. Open [Render Dashboard](https://dashboard.render.com/) → **New** → **Blueprint**.
3. Connect the `checkmate` GitHub repo.
4. Render reads root **`render.starter.yaml`** and creates:
   - **`checkmate-zap`** (private ZAP)
   - **`checkmate-api`** (public HTTPS API + 1 GiB persistent disk for SQLite)
5. When prompted, set **manual** secrets on **`checkmate-api`**:
   - **`FIREBASE_PROJECT_ID`** — e.g. `checkmate-68921`
   - **`FIREBASE_CREDENTIALS_JSON`** — entire service-account JSON **on one line**  
     (PowerShell: `(Get-Content path\to\sa.json -Raw)` → paste into Render)
   - Optional: **`GEMINI_API_KEY`**, **`GROQ_API_KEY`** for AI synthesis
6. Wait until **`checkmate-api`** is **Live** and open  
   `https://<your-service-name>.onrender.com/health` → `"status":"ok"`.

**Cost note:** Blueprint uses **Starter** plans (persistent disk + enough RAM). Render’s free web tier sleeps and has no disk — not suitable for this app.

Copy the public API URL, e.g. `https://checkmate-api.onrender.com`.

---

## 2. Wire Vercel to the cloud API

In [Vercel → checkmate.app → Environment Variables → Production](https://vercel.com/dewdropperaas-projects/checkmate.app/settings/environment-variables):

| Variable | Value |
|----------|--------|
| `NEXT_PUBLIC_API_BASE_URL` | `https://<checkmate-api>.onrender.com` |

Remove any `127.0.0.1`, `localhost`, or `loca.lt` values.

**Redeploy** production (Deployments → … → Redeploy).

Or from your laptop (no Docker):

```powershell
cd web
echo "https://YOUR-API.onrender.com" | npx vercel env add NEXT_PUBLIC_API_BASE_URL production --force
npx vercel deploy --prod
```

(Run from repo root if your Vercel root is the monorepo — see `vercel.json`.)

---

## 3. Firebase (auth)

1. **Authorized domains:** `checkmateapp-nine.vercel.app` (+ custom domain when added).

   ```powershell
   backend\.venv\Scripts\python.exe scripts\firebase_add_authorized_domain.py checkmateapp-nine.vercel.app
   ```

2. **Google Cloud → Credentials → Browser API key:** HTTP referrers  
   `https://checkmateapp-nine.vercel.app/*`

---

## 4. Smoke test

1. `GET https://<checkmate-api>.onrender.com/health` — OK.
2. Sign in at `https://checkmateapp-nine.vercel.app/fr/signin`.
3. Network tab: `/auth/sync` goes to **onrender.com** (or `/api/backend` if you use proxy), never loopback.
4. Run a scan on an allowlisted target (set `AUTHORIZED_TARGETS` on Render if you re-enable scope).

---

## 5. Turn on full scanner toolchain (optional)

After the API is stable, on **`checkmate-api`** in Render:

1. Set `REQUIRE_TOOLCHAIN_AT_STARTUP=true`.
2. Redeploy (image already contains nuclei/subfinder/etc.).
3. Confirm `/health` shows `toolchain.ready` and `zap_ready: true`.

---

## 6. Stop using the dev bridge

- Kill local **uvicorn** and **localtunnel** if still running.
- Delete tunnel URLs from Vercel env.

---

## Files

| File | Role |
|------|------|
| `render.yaml` | Render Blueprint (API + private ZAP) |
| `backend/.env.hosted.example` | Env reference for `APP_ENV=hosted` |
| `web/.env.production.example` | Vercel variable names |
| `scripts/firebase_add_authorized_domain.py` | Firebase authorized domains |

## Upgrade path

| Stage | `APP_ENV` | Billing |
|-------|-----------|---------|
| Launch (this doc) | `hosted` | Test / none |
| Full production | `production` | Live Dodo + `docs/LAUNCH.md` |
