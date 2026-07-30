# $0 launch — Vercel (free) + optional Render API (auth only)

> **You need ZAP active scans?** Read **[LAUNCH_ZAP_ORACLE.md](./LAUNCH_ZAP_ORACLE.md)** — full stack on Oracle Cloud Always Free ($0/mo, card for verification only).  
> **Paid on Render:** **[LAUNCH_NO_DOCKER.md](./LAUNCH_NO_DOCKER.md)** (`render.starter.yaml`, ~$14/mo).

## What you get for free

| Works | Limitation |
|--------|------------|
| Sign-in / sign-up (Firebase) | API **sleeps** after ~15 min idle |
| Dashboard shell | **No ZAP scans** on this tier |
| Secure auth | SQLite ephemeral |

**This path does not run ZAP.** For active scanning see **[LAUNCH_ZAP_ORACLE.md](./LAUNCH_ZAP_ORACLE.md)** (Oracle $0) or **render.starter.yaml** (~$14/mo).

---

## 1. Deploy API on Render (free, no card)

> **Blueprint asks for a card?** Render often requires a payment method for Blueprint even when the service is free. Skip Blueprint — create a **Web Service** manually.

1. Push this repo to GitHub.
2. [Render Dashboard](https://dashboard.render.com/) → **New** → **Web Service** (not Blueprint).
3. Connect **dewdropperaa/checkmate-** and use these settings:

| Setting | Value |
|---------|--------|
| Name | `checkmate-api` |
| Region | Frankfurt (EU) |
| Branch | `main` (or your default) |
| Root directory | `backend` |
| Runtime | **Python 3** |
| Build command | `pip install -r requirements.txt` |
| Start command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Instance type | **Free** |
| Health check path | `/health` |

4. **Environment variables** (Environment → Add):

| Key | Value |
|-----|--------|
| `APP_ENV` | `hosted` |
| `CLOUD_SCANNING_ENABLED` | `true` |
| `CLOUD_SCAN_PROFILE` | `firecrawl` |
| `DEBUG` | `false` |
| `LOG_LEVEL` | `INFO` |
| `REQUIRE_FIREBASE_AUTH` | `true` |
| `REQUIRE_TOOLCHAIN_AT_STARTUP` | `false` |
| `FIRECRAWL_ENABLED` | `true` |
| `FIRECRAWL_API_KEY` | your Firecrawl key |
| `WATCH_SCHEDULER_ENABLED` | `false` |
| `DODO_ENVIRONMENT` | `test` |
| `PUBLIC_APP_URL` | `https://checkmateapp-nine.vercel.app` |
| `FIREBASE_PROJECT_ID` | e.g. `checkmate-68921` |
| `FIREBASE_CREDENTIALS_JSON` | service account JSON, **one line** |
| `CREDENTIALS_MASTER_KEY` | Fernet key (see `backend/.env` or generate) |
| `CREATOR_EMAILS` | your founder email (optional, agency tier) |

   PowerShell for Firebase JSON:
   ```powershell
   (Get-Content C:\path\to\firebase-adminsdk.json -Raw)
   ```

5. Click **Create Web Service**. Wait until **Live**, then open `https://<name>.onrender.com/health`.

Copy the URL: `https://<name>.onrender.com`.

---

## 2. Point Vercel at Render (free)

```powershell
.\scripts\deploy-production-api.ps1 -RenderApiUrl "https://YOUR-SERVICE.onrender.com"
```

Or manually:

```powershell
.\scripts\sync-vercel-api-url.ps1 -ApiUrl "https://YOUR-SERVICE.onrender.com"
npx vercel deploy --prod
```

Remove any `127.0.0.1` or `loca.lt` env vars in Vercel.

---

## 3. Firebase

```powershell
backend\.venv\Scripts\python.exe scripts\firebase_add_authorized_domain.py checkmateapp-nine.vercel.app
```

Google Cloud → browser API key → HTTP referrers: `https://checkmateapp-nine.vercel.app/*`

---

## 4. Local scans without Docker

```powershell
cd backend
.venv\Scripts\activate
# .env: REQUIRE_TOOLCHAIN_AT_STARTUP=false if tools not installed
uvicorn app.main:app --reload
```

Point `NEXT_PUBLIC_API_BASE_URL` in **local** `web/.env.local` at `http://127.0.0.1:8000` for development only.

---

## 5. When you outgrow free

| Need | Use |
|------|-----|
| Always-on API + disk + ZAP | **`render.starter.yaml`** Blueprint (paid, card required) |
| Custom domain API | `api.checkmate.ma` + **`docs/LAUNCH.md`** |

---

## Files

- **`render.yaml`** — free tier reference (Blueprint may still ask for a card)
- **`render.starter.yaml`** — paid scanner stack
- **`backend/.env.hosted.example`** — env reference
