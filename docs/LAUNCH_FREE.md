# $0 launch — Vercel (free) + Render (free)

No Docker on your laptop. No credit card required on Render’s free web tier (as of 2026 — confirm on [render.com/pricing](https://render.com/pricing)).

## What you get for free

| Works | Limitation |
|--------|------------|
| Sign-in / sign-up (Firebase) | API **sleeps** after ~15 min idle → first request ~30–60s cold start |
| `/auth/sync`, dashboard shell | SQLite **not persisted** — scan history may reset when Render redeploys or spins down |
| Secure auth (`REQUIRE_FIREBASE_AUTH=true`, `APP_ENV=hosted`) | **No cloud scans** (`CLOUD_SCANNING_ENABLED=false`) — use local backend for scanning |

**Scans:** run `uvicorn` on your PC (no Docker) for the full scanner, or upgrade later to `render.starter.yaml` (paid).

---

## 1. Deploy API on Render (free)

1. Push this repo to GitHub.
2. [Render Dashboard](https://dashboard.render.com/) → **New** → **Blueprint**.
3. Connect the repo — Render uses root **`render.yaml`** (free Python service).
4. On **`checkmate-api`**, set:
   - **`FIREBASE_PROJECT_ID`** — e.g. `checkmate-68921`
   - **`FIREBASE_CREDENTIALS_JSON`** — service account JSON as **one line**  
     PowerShell: `(Get-Content C:\path\to\sa.json -Raw)`
5. Wait until **Live**, then open `https://<name>.onrender.com/health`.

Copy the URL: `https://<name>.onrender.com`.

---

## 2. Point Vercel at Render (free)

```powershell
.\scripts\sync-vercel-api-url.ps1 -ApiUrl "https://YOUR-SERVICE.onrender.com"
cd c:\Users\pc\Desktop\scan
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

Point the extension / `NEXT_PUBLIC_API_BASE_URL` in **local** `web/.env.local` at `http://127.0.0.1:8000` for development only.

---

## 5. When you outgrow free

| Need | Use |
|------|-----|
| Always-on API + disk + ZAP | Import **`render.starter.yaml`** as a new blueprint (paid) |
| Custom domain API | `api.checkmate.ma` + **`docs/LAUNCH.md`** |

---

## Files

- **`render.yaml`** — free tier (default)
- **`render.starter.yaml`** — paid scanner stack
- **`backend/.env.hosted.example`** — env reference
