# checkmate

Multi-agent web vulnerability scanner with a **Chrome Manifest V3 extension** frontend and a **Python FastAPI** backend. This repository is the production scaffold — scanning agents and external tool integrations are added in later phases.

## Architecture

```
checkmate/
├── backend/          # FastAPI API, agents, tool wrappers, scope enforcement
├── extension/        # Chrome MV3 extension (Vite + TypeScript)
├── web/              # Marketing site (Next.js) — FR/EN landing + auth stubs
└── terraform/        # Cloudflare edge (WAF/DNS/SSL) — see terraform/cloudflare/README.md
```

## Prerequisites

- Python 3.12+
- Node.js 20+ (for the extension build)
- Docker & Docker Compose (optional)

## Backend setup

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `AUTHORIZED_TARGETS` to a comma-separated list of domains or URLs you are **explicitly authorized** to scan, for example:

```env
AUTHORIZED_TARGETS=authorized.example.com,https://staging.example.com
```

For **local development** without installing every security CLI on your machine, keep the defaults in `.env.example`:

```env
REQUIRE_TOOLCHAIN_AT_STARTUP=false
ZAP_API_URL=http://localhost:8080
```

The API will start, but real scans need the full tool chain (use Docker Compose below). With `REQUIRE_TOOLCHAIN_AT_STARTUP=true`, startup fails until subfinder, nuclei, ZAP, and the other tools are available.

Start the API:

```bash
uvicorn app.main:app --reload
```

The server listens on `http://127.0.0.1:8000`. Interactive docs: `http://127.0.0.1:8000/docs`.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Queue a scan for an authorized target |
| `GET` | `/scan/{id}/status?target=...` | Poll scan status |
| `GET` | `/scan/{id}/report?target=...` | Retrieve scan report |
| `GET` | `/scan/{id}/report/{format}?target=...` | Download report artifact in `json`, `md`, `html`, or `pdf` |

Every endpoint validates the target against the allowlist **before** any other logic. Out-of-scope targets receive **403 Forbidden**.
The `/scan` endpoint is also rate-limited and concurrency-limited per client identity (IP or API key) to prevent unbounded scan launches.

### Run tests

```bash
cd backend
pytest
```

### Docker

Production-oriented Compose (ZAP is **not** published on a host port — only
reachable as `http://zap:8080` on the private Compose network):

```bash
cd backend
cp .env.example .env
# Set AUTHORIZED_TARGETS and a strong ZAP_API_KEY (required).
docker compose up --build
```

Local development with ZAP reachable from the host on loopback only:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Post-deploy ZAP smoke test (healthy container + `/health` zap_ready + minimal scan):

```bash
bash scripts/smoke_zap_deploy.sh
# Windows:
powershell -File scripts/smoke_zap_deploy.ps1
```

ZAP image is pinned to `ghcr.io/zaproxy/zaproxy:2.17.0@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2` — upgrade deliberately
after testing; do not switch back to `:latest` / `:stable` (digest is authoritative).

External tool binaries can be placed in `backend/tools-bin/` and are mounted at `/opt/tools` inside the container.

**Sizing:** give the host ≥4 GiB free RAM when running ZAP (2 GiB container
limit) alongside the backend. Concurrent active scans are capped via
`ZAP_MAX_CONCURRENT` (default 1) and conservative `/scan` concurrency limits.

**Persistent data:** production Compose mounts named volumes for `/app/data`
(accounts SQLite DB, LangGraph checkpoints, scan registry/audit) and
`/app/reports` (generated scan artifacts). Container recreate/redeploy must not
wipe customer history.

#### Backup and restore (runbook)

Back up before major upgrades or host migrations:

```bash
# From the backend directory on the Docker host
docker compose exec backend sh -c 'tar czf - -C / app/data app/reports' > checkmate-data-backup.tgz
```

Restore into a fresh stack (stop backend first to avoid SQLite write races):

```bash
docker compose stop backend
docker run --rm -v backend_app-data:/data -v backend_app-reports:/reports \
  -v "$PWD":/backup alpine sh -c 'cd / && tar xzf /backup/checkmate-data-backup.tgz'
docker compose start backend
```

Volume names are prefixed with the Compose project name (often `backend_`).
Adjust `backend_app-data` / `backend_app-reports` to match `docker volume ls`.

> **HIGH PRIORITY follow-up:** automate scheduled off-host backups (e.g. cron +
> object storage) — manual tar backups are a launch baseline, not a DR strategy.

#### Database migrations

Schema changes are managed with Alembic. Migrations run automatically on
container start (`scripts/docker-entrypoint.sh`) and during API lifespan before
serving traffic. To apply manually:

```bash
cd backend
python -c "from core.migrations import upgrade_database; upgrade_database()"
```

Generate a new revision after editing the baseline in `core/db_schema.py`:

```bash
cd backend
alembic revision -m "describe_change"
```

`GET /health` reports `migrations_current` — a deploy is not ready until this
is `true`.

## Extension setup

```bash
cd extension
npm install
npm run build
```

Load the unpacked extension in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `extension/dist`

Ensure the backend is running at `http://localhost:8000` and that the active tab target appears in `AUTHORIZED_TARGETS`.

## Web (Vercel)

The Next.js app lives in `web/`. On Vercel:

1. **Root Directory** must be `web` (Project Settings → General → Root Directory).
2. Framework Preset: **Next.js**.
3. Set these Environment Variables (from `web/.env.example`):
   - `NEXT_PUBLIC_FIREBASE_*` (all required Firebase web keys)
   - `NEXT_PUBLIC_API_BASE_URL` (public HTTPS URL of the FastAPI backend)

A root `vercel.json` also targets `web/package.json` via `@vercel/next` if the Root Directory is left at the repository root.

```bash
cd web
npm install
npm run build
```

## Project layout

```
backend/
  app/main.py           # FastAPI application
  agents/               # Multi-agent pipeline (stubs)
  tools/                # External CLI wrappers (stubs)
  core/
    config.py           # Pydantic settings (reads .env)
    scope.py            # Allowlist enforcement
    logging.py          # Structured JSON logging
  tests/                # Pytest suite
extension/
  manifest.json         # Manifest V3
  popup.html / popup.ts
  background.ts
  content-script.ts
  dist/                 # Build output (after npm run build)
```

## Security

Read [SECURITY.md](SECURITY.md) before using this tool. **Only scan targets you own or have written authorization to test.**

## Legal & Scope

This tool must only be used against systems you are explicitly authorized to test (for example, your own assets or targets with written permission).

**Allowlist enforcement is currently disabled** so the extension can auto-target the open tab. The `AUTHORIZED_TARGETS` setting remains in config for later re-enable; `core/scope.py` and tool `validate_scope` calls are no-ops until then. You are responsible for ensuring legal authorization before scanning.

## License

Use responsibly and in compliance with applicable laws and engagement scope.
